# server.py
#ASSIGNMNET 2 Q2 SERVER
# IMPORTING ALL LIBRARIES
import socket
import os
import json
import hashlib
import binascii
import threading
import struct
import logging
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s] %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')

# Constants
CREDENTIALS_FILE = 'creds.txt'
BLOCK_SIZE = 16  # AES block size in bytes
HEADER_SIZE = 4   # 4 bytes for message length

def generate_dh_parameters():
    """
    Generate Diffie-Hellman parameters.
    These parameters can be generated once and reused.
    """
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    logging.debug("Diffie-Hellman parameters generated.")
    return parameters

def perform_dh_key_exchange(conn, parameters):
    """
    Perform Diffie-Hellman key exchange with the connected client.
    Returns the derived symmetric key.
    """
    # Generate server's private and public keys
    server_private_key = parameters.generate_private_key()
    server_public_key = server_private_key.public_key()

    # Serialize and send server's public key to client
    server_public_bytes = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_message(conn, server_public_bytes)
   

    # Receive client's public key
    client_public_bytes = receive_message(conn)
    if not client_public_bytes:
        raise ValueError("Failed to receive client's public key.")

    client_public_key = serialization.load_pem_public_key(client_public_bytes, backend=default_backend())
   

    # Generate shared secret
    shared_key = server_private_key.exchange(client_public_key)
   
    # Derive symmetric key using HKDF
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=16,  # 128 bits for AES-128
        salt=None,
        info=b'handshake data',
        backend=default_backend()
    ).derive(shared_key)

    logging.info("Shared symmetric key established.")
    return derived_key
#meesage encryption funvtion
def encrypt_message(message, key):
   
    iv = os.urandom(16)  # 128-bit IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # PKCS7 Padding
    padding_length = BLOCK_SIZE - (len(message) % BLOCK_SIZE)
    padded_message = message + bytes([padding_length] * padding_length)
    
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()
    #logging.debug(f"Message encrypted. IV: {binascii.hexlify(iv).decode()} | Ciphertext Length: {len(ciphertext)}")
    return iv + ciphertext
#MESSAGE DECRYPTION
def decrypt_message(ciphertext, key):
   
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short to contain IV.")
    
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_message = decryptor.update(actual_ciphertext) + decryptor.finalize()
    
    # Remove PKCS7 Padding
    padding_length = padded_message[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise ValueError("Invalid padding.")
    message = padded_message[:-padding_length]
    #logging.debug(f"Message decrypted. IV: {binascii.hexlify(iv).decode()} | Plaintext Length: {len(message)}")
    return message
#PASSWORD TO HASH 
def hash_password(password, salt):
   
    pwd_salt = password.encode() + salt
    hashed_pwd = hashlib.sha256(pwd_salt).hexdigest()
    #logging.debug(f"Password hashed. Salt: {binascii.hexlify(salt).decode()} | Hash: {hashed_pwd}")
    return hashed_pwd
#CHECKING IF USERNAME IS UNIQUE
def is_username_unique(username, email):
    
    if not os.path.exists(CREDENTIALS_FILE):
        logging.debug(" NO Credentials file . Username is unique.")
        return True
    with open(CREDENTIALS_FILE, 'r') as f:
        for line in f:
            if line.strip() == '':
                continue
            try:
                user_record = json.loads(line)
                if user_record['username'].lower() == username.lower() or user_record['email'].lower() == email.lower():
                    logging.warning(f"Duplicate found: Username='{user_record['username']}', Email='{user_record['email']}'")
                    return False
            except json.JSONDecodeError:
                continue
    logging.debug("Username and email are unique.")
    return True
#STORING CREDENTIALS
def store_credentials(email, username, hashed_password, salt):
    
    user_record = {
        'email': email,
        'username': username,
        'hashed_password': hashed_password,
        'salt': binascii.hexlify(salt).decode()
    }
    with open(CREDENTIALS_FILE, 'a') as f:
        f.write(json.dumps(user_record) + '\n')
    logging.info(f" The login Credentials re  stored for user '{username}'.")
#SENDING ENCRYPTED MESSAGE
def send_encrypted_message(conn, message, key):
   
    encrypted = encrypt_message(message, key)
    message_length = struct.pack('>I', len(encrypted))
    try:
        conn.sendall(message_length + encrypted)
       
    except Exception as e:
        logging.error(f"Failed to send encrypted message: {e}")
#RECEIVING ENCRYPTED MESSAGE
def receive_encrypted_message(conn, key):
    
    raw_length = recvall(conn, HEADER_SIZE)
    if not raw_length:
        logging.warning("No message length received.")
        return None
    message_length = struct.unpack('>I', raw_length)[0]
    #logging.debug(f"Expected message length: {message_length} bytes.")
    encrypted_message = recvall(conn, message_length)
    if not encrypted_message:
        logging.warning("No encrypted message received.")
        return None
    try:
        decrypted = decrypt_message(encrypted_message, key)
        #logging.debug(f"Encrypted message received and decrypted. Length: {len(decrypted)} bytes.")
        return decrypted
    except Exception as e:
        logging.error(f"Failed to decrypt message: {e}")
        return None
#SENDING MESSAGE
def send_message(conn, message_bytes):
    
    message_length = struct.pack('>I', len(message_bytes))
    try:
        conn.sendall(message_length + message_bytes)
        #logging.debug(f"Raw message sent. Length: {len(message_bytes)} bytes.")
    except Exception as e:
        logging.error(f"Failed to send raw message: {e}")
#RECEIVING MESSAGE
def receive_message(conn):
   
    raw_length = recvall(conn, HEADER_SIZE)
    if not raw_length:
        logging.warning("No raw message length received.")
        return None
    message_length = struct.unpack('>I', raw_length)[0]
   # logging.debug(f"Raw message expected length: {message_length} bytes.")
    message = recvall(conn, message_length)
    if not message:
        logging.warning("No raw message received.")
        return None
    #logging.debug(f"Raw message received. Length: {len(message)} bytes.")
    return message
#RECEIVING ALL
def recvall(conn, n):

    data = bytearray()
    while len(data) < n:
        try:
            packet = conn.recv(n - len(data))
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            return None
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)
#HANDLING REGISTRATION
def handle_registration(decrypted_data, key, conn):
    
    try:
        credentials = json.loads(decrypted_data.decode())
        email = credentials.get('email')
        username = credentials.get('username')
        password = credentials.get('password')

        if not email or not username or not password:
            raise ValueError("Missing registration fields.")

        #logging.info(f"Registration attempt: Username='{username}', Email='{email}'")

        if not is_username_unique(username, email):
            response = {'status': 'error', 'message': 'Username or email already exists.'}
            logging.info(f"Registration failed: Username or email '{username}' already exists.")
        else:
            # Generate a random 16-byte salt for better security
            salt = os.urandom(16)
            hashed_password = hash_password(password, salt)
            store_credentials(email, username, hashed_password, salt)
            response = {'status': 'success', 'message': 'Registration successful.'}
            logging.info(f"User '{username}' registered successfully.")

        # Encrypt and send response
        response_bytes = json.dumps(response).encode()
        send_encrypted_message(conn, response_bytes, key)

    except Exception as e:
        logging.error(f"Error during registration: {e}")
        response = {'status': 'error', 'message': 'Registration failed due to server error.'}
        response_bytes = json.dumps(response).encode()
        send_encrypted_message(conn, response_bytes, key)
#HANDLING LOGIN
def handle_login(decrypted_data, key, conn):
    
    try:
        credentials = json.loads(decrypted_data.decode())
        username = credentials.get('username')
        password = credentials.get('password')

        if not username or not password:
            raise ValueError("Missing login fields.")

        #logging.info(f"Login attempt: Username='{username}'")

        # Retrieve user record
        user_record = None
        if os.path.exists(CREDENTIALS_FILE):
            with open(CREDENTIALS_FILE, 'r') as f:
                for line in f:
                    if line.strip() == '':
                        continue
                    try:
                        record = json.loads(line)
                        if record['username'].lower() == username.lower():
                            user_record = record
                            break
                    except json.JSONDecodeError:
                        continue

        if not user_record:
            response = {'status': 'error', 'message': 'Username not found.'}
            logging.info(f"Login failed: Username '{username}' not found.")
        else:
            # Retrieve salt and hashed password
            salt = binascii.unhexlify(user_record['salt'])
            hashed_password = user_record['hashed_password']
            # Hash the entered password with the retrieved salt
            entered_hashed = hash_password(password, salt)
            if entered_hashed == hashed_password:
                response = {'status': 'success', 'message': 'Login successful.'}
                logging.info(f"User '{username}' logged in successfully.")
            else:
                response = {'status': 'error', 'message': 'Incorrect password.'}
                logging.info(f"Login failed: Incorrect password for user '{username}'.")

        # Encrypt and send response
        response_bytes = json.dumps(response).encode()
        send_encrypted_message(conn, response_bytes, key)

    except Exception as e:
        logging.error(f"Error during login: {e}")
        response = {'status': 'error', 'message': 'Login failed due to server error.'}
        response_bytes = json.dumps(response).encode()
        send_encrypted_message(conn, response_bytes, key)
#HANDLING CHAT
def handle_chat(request, key, conn):
    
    try:
        message = request.get('message')
        if not message:
            raise ValueError("Empty chat message.")

        logging.info(f"Received from client: {message}")

        if message.lower() == 'bye':
            logging.info("Client initiated termination.")
            response = {'status': 'success', 'message': 'Goodbye!'}
            send_encrypted_message(conn, json.dumps(response).encode(), key)
            return 'terminate'

        # Echo the message back
        response = {'status': 'success', 'message': f"Server received: {message}"}
        send_encrypted_message(conn, json.dumps(response).encode(), key)

    except Exception as e:
        logging.error(f"Error during chat handling: {e}")
        response = {'status': 'error', 'message': 'Failed to process chat message.'}
        send_encrypted_message(conn, json.dumps(response).encode(), key)
#SENDING SERVER MESSAGES
def send_server_messages(conn, key, terminate_event):
   
    try:
        while not terminate_event.is_set():
            message = input("Server: ").strip()
            if not message:
                continue
            # Create chat data with command
            chat_data = {
                'command': 'chat',
                'message': message
            }
            chat_json = json.dumps(chat_data).encode()
            send_encrypted_message(conn, chat_json, key)
            if message.lower() == 'bye':
                logging.info("Server initiated termination.")
                terminate_event.set()
                break
    except Exception as e:
        logging.error(f"Error in sending server messages: {e}")
        terminate_event.set()
#RECEIVING CLIENT MESSAGES
def receive_client_messages(conn, key, terminate_event):
   
    try:
        while not terminate_event.is_set():
            decrypted_data = receive_encrypted_message(conn, key)
            if decrypted_data is None:
                logging.info("Client closed the connection.")
                print("\nClient disconnected.")
                terminate_event.set()
                break

            request = json.loads(decrypted_data.decode())
            command = request.get('command')

            if command == 'register':
                handle_registration(decrypted_data, key, conn)
            elif command == 'login':
                handle_login(decrypted_data, key, conn)
            elif command == 'chat':
                termination = handle_chat(request, key, conn)
                if termination == 'terminate':
                    terminate_event.set()
                    break
            else:
                response = {'status': 'error', 'message': 'Unknown command.'}
                send_encrypted_message(conn, json.dumps(response).encode(), key)
                logging.warning(f"Unknown command received from client: {command}")
    except Exception as e:
        logging.error(f"Error decrypting or processing message from client: {e}")
        terminate_event.set()
#CLIENT HANDLER
def client_handler(conn, addr, parameters):
   
    logging.info(f"Connected by {addr}")

    try:
        # Perform Diffie-Hellman key exchange
        shared_key = perform_dh_key_exchange(conn, parameters)
    except Exception as e:
        logging.error(f"Key exchange failed with {addr}: {e}")
        conn.close()
        return

    terminate_event = threading.Event()

    # Start a thread to allow the server to send messages to the client
    sender_thread = threading.Thread(target=send_server_messages, args=(conn, shared_key, terminate_event))
    sender_thread.daemon = True
    sender_thread.start()

    # Start a thread to listen for client-initiated messages
    receiver_thread = threading.Thread(target=receive_client_messages, args=(conn, shared_key, terminate_event))
    receiver_thread.daemon = True
    receiver_thread.start()

    # Wait for termination event
    while not terminate_event.is_set():
        try:
            # Main thread can perform other tasks or simply wait
            terminate_event.wait(1)
        except KeyboardInterrupt:
            logging.info("Server shutting down due to keyboard interrupt.")
            terminate_event.set()
            break

    # Close the connection
    try:
        conn.shutdown(socket.SHUT_RDWR)
        conn.close()
        logging.info(f"Connection with {addr} closed.")
    except Exception as e:
        logging.error(f"Error closing connection with {addr}: {e}")
#STARTING SERVER
def start_server():
    
    host = '127.0.0.1'
    port = 65432

    # Generate Diffie-Hellman parameters
    parameters = generate_dh_parameters()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        logging.info(f" The Server is  listening on {host}:{port}")

        while True:
            try:
                conn, addr = s.accept()
                client_thread = threading.Thread(target=client_handler, args=(conn, addr, parameters))
                client_thread.daemon = True
                client_thread.start()
                #logging.debug(f"Started thread for {addr}")
            except KeyboardInterrupt:
                logging.info("Server shutting down due to keyboard interrupt.")
                break
            except Exception as e:
                logging.error(f"Error accepting connections: {e}")

    logging.info("Server  has shutdown.")

if __name__ == "__main__":
    start_server()