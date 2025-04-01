# client.py
#ASSIGNMNET 2 - QUESTION 2-CLIENT
#IMPORTING LIBARRAIES
import socket
import os
import json
import struct
import logging
import binascii
import hashlib
import threading
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Configure logging
"""
logging.basicConfig(level=logging.DEBUG,
                    format='[%(asctime)s] %(levelname)s - %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
"""
BLOCK_SIZE = 16  # AES block size in bytes
HEADER_SIZE = 4  # 4 bytes for message length
#FUNCTION TO PERFORM DH KEY EXCHANGE (DEFII HELLMAN)
def perform_dh_key_exchange(s):
   
    # Receive server's public key
    server_public_bytes = receive_message(s)
    if not server_public_bytes:
        raise ValueError("Failed to receive server's public key.")

    server_public_key = serialization.load_pem_public_key(server_public_bytes, backend=default_backend())
    #logging.debug("Server's public key received and loaded.")

    # Generate client's private and public keys
    parameters = server_public_key.parameters()
    client_private_key = parameters.generate_private_key()
    client_public_key = client_private_key.public_key()

    # Serialize and send client's public key to server
    client_public_bytes = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    send_message(s, client_public_bytes)
    

    # Generate shared secret
    shared_key = client_private_key.exchange(server_public_key)
    
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
#FUNCTION TO ENCRYPT MESSAGE
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
#FUNCTION TO DECRYPT MESSAGE
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
   
    return message
#FUNCTION TO HASH PASSWORD
def hash_password(password, salt):
   
    pwd_salt = password.encode() + salt
    hashed_pwd = hashlib.sha256(pwd_salt).hexdigest()
    logging.debug(f"Password hashed. Salt: {binascii.hexlify(salt).decode()} | Hash: {hashed_pwd}")
    return hashed_pwd
#FUNCTION TO SEND ENCRYPTED MESSAGE
def send_encrypted_message(s, message, key):
   
    encrypted = encrypt_message(message, key)
    message_length = struct.pack('>I', len(encrypted))
    try:
        s.sendall(message_length + encrypted)
        #logging.debug(f"Encrypted message sent. Length: {len(encrypted)} bytes.")
    except Exception as e:
        logging.error(f"Failed to send encrypted message: {e}")
#FUNCTION TO RECEIVE ENCRYPTED MESSAGE
def receive_encrypted_message(s, key):
    
    raw_length = recvall(s, HEADER_SIZE)
    if not raw_length:
        logging.warning("No message length received.")
        return None
    message_length = struct.unpack('>I', raw_length)[0]
    #logging.debug(f"Expected message length: {message_length} bytes.")
    encrypted_message = recvall(s, message_length)
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
#FUNCTION TO SEND MESSAGE
def send_message(s, message_bytes):
    
    message_length = struct.pack('>I', len(message_bytes))
    try:
        s.sendall(message_length + message_bytes)
        logging.debug(f"Raw message sent. Length: {len(message_bytes)} bytes.")
    except Exception as e:
        logging.error(f"Failed to send raw message: {e}")
#FUNCTION TO RECEIVE MESSAGE
def receive_message(s):
  
    raw_length = recvall(s, HEADER_SIZE)
    if not raw_length:
        logging.warning("No raw message length received.")
        return None
    message_length = struct.unpack('>I', raw_length)[0]
    logging.debug(f"Raw message expected length: {message_length} bytes.")
    message = recvall(s, message_length)
    if not message:
        logging.warning("No raw message received.")
        return None
    logging.debug(f"Raw message received. Length: {len(message)} bytes.")
    return message
#FUNCTION TO RECEIVE ALL
#HELPER FUNCTION TO RECEIVE ALL
def recvall(s, n):
   
    data = bytearray()
    while len(data) < n:
        try:
            packet = s.recv(n - len(data))
        except Exception as e:
            logging.error(f"Error receiving data: {e}")
            return None
        if not packet:
            return None
        data.extend(packet)
    return bytes(data)
#FUNCTION TO HANDLE REGISTRATION
def handle_registration(decrypted_data, key, s):
    
    try:
        credentials = json.loads(decrypted_data.decode())
        email = credentials.get('email')
        username = credentials.get('username')
        password = credentials.get('password')

        if not email or not username or not password:
            raise ValueError("Missing registration fields.")

        logging.info(f"Registration attempt: Username='{username}', Email='{email}'")

        # Send registration data to the server
        # (Assuming the server handles registration)
        # The client only initiates registration

    except Exception as e:
        logging.error(f"Error during registration: {e}")
#FUNCTION TO HANDLE LOGIN
def handle_login(decrypted_data, key, s):
   
    try:
        credentials = json.loads(decrypted_data.decode())
        username = credentials.get('username')
        password = credentials.get('password')

        if not username or not password:
            raise ValueError("Missing login fields.")

        logging.info(f"Login attempt: Username='{username}'")

        # Send login data to the server
        # (Assuming the server handles login)
        # The client only initiates login

    except Exception as e:
        logging.error(f"Error during login: {e}")
#FUNCTION TO HANDLE CHAT
def receive_server_messages(s, key, terminate_event):
   
    try:
        while not terminate_event.is_set():
            decrypted_data = receive_encrypted_message(s, key)
            if decrypted_data is None:
                logging.info("Server closed the connection.")
                print("\nServer disconnected.")
                terminate_event.set()
                break

            response = json.loads(decrypted_data.decode())

            # Check if it's a response or a server-initiated message
            if 'status' in response:
                # It's a response to a client-initiated command
                status = response.get('status')
                message = response.get('message')

                if status == 'success':
                    print(f"\n{message}")
                    if message.lower() == 'goodbye!':
                        print("Connection closed by server.")
                        terminate_event.set()
                        break
                else:
                    print(f"\nError from server: {message}")
            elif 'command' in response:
                # It's a server-initiated message
                command = response.get('command')
                message = response.get('message')
                if command == 'chat':
                    if message.lower() == 'bye':
                        print("\nServer has ended the chat session.")
                        logging.info("Server initiated termination.")
                        terminate_event.set()
                        break
                    else:
                        print(f"\nServer: {message}")
            else:
                print("\nReceived an unknown message format from the server.")
    except Exception as e:
        logging.error(f"Error receiving messages from server: {e}")
        terminate_event.set()
#FUNCTION TO REGISTER
def register(s, key):
   
    print("\n--- User Registration ---")
    email = input("Enter your Email Address: ").strip()
    username = input("Enter a Unique Username: ").strip()
    password = input("Enter a Password: ").strip()

    # Create registration data with command
    registration_data = {
        'command': 'register',
        'email': email,
        'username': username,
        'password': password
    }

    registration_json = json.dumps(registration_data).encode()
    send_encrypted_message(s, registration_json, key)

    # Receive and decrypt server response
    try:
        decrypted_response = receive_encrypted_message(s, key)
        if not decrypted_response:
            print("No response from server.")
            return
        response = json.loads(decrypted_response.decode())

        if response.get('status') == 'success':
            print(" Congratulation Registration successful!!\n")
        else:
            print(f"Registration failed: {response.get('message')}\n")
    except Exception as e:
        logging.error(f"Error during registration: {e}\n")
        print(f"Error during registration: {e}\n")
#FUNCTION TO LOGIN
def login(s, key):
   
    print("\n--- User Login ---")
    username = input("Enter your Username: ").strip()
    password = input("Enter your Password: ").strip()

    # Create login data with command
    login_data = {
        'command': 'login',
        'username': username,
        'password': password
    }

    login_json = json.dumps(login_data).encode()
    send_encrypted_message(s, login_json, key)

    # Receive and decrypt server response
    try:
        decrypted_response = receive_encrypted_message(s, key)
        if not decrypted_response:
            print("No response from server.")
            return False
        response = json.loads(decrypted_response.decode())

        if response.get('status') == 'success':
            print("You have sucesfully logged In!\n")
            return True
        else:
            print(f"Login failed: {response.get('message')}\n")
            return False
    except Exception as e:
        logging.error(f"Error during login: {e}\n")
        print(f"Error during login: {e}\n")
        return False

def chat(s, key):
   
    print("\n--- 💬 A secure Appliaction 💬 ---")
    print("Type your messages below or to exit Type 'bye'.\n")

    terminate_event = threading.Event()

    # Start a thread to listen for server-initiated messages
    listener_thread = threading.Thread(target=receive_server_messages, args=(s, key, terminate_event))
    listener_thread.daemon = True
    listener_thread.start()

    try:
        while not terminate_event.is_set():
            message = input("You: ").strip()
            if not message:
                continue  # Skip empty messages

            # Create chat data with command
            chat_data = {
                'command': 'chat',
                'message': message
            }

            chat_json = json.dumps(chat_data).encode()
            send_encrypted_message(s, chat_json, key)

            if message.lower() == 'bye':
                print("Chat session ended.\n")
                terminate_event.set()
                break

    except KeyboardInterrupt:
        print("\nChat session terminated by user.")
        logging.info("Chat session terminated by user.")
        terminate_event.set()
    except Exception as e:
        logging.error(f"Error during chat: {e}\n")
        print(f"Error during chat: {e}\n")
        terminate_event.set()

    # Close the socket after termination
    try:
        s.shutdown(socket.SHUT_RDWR)
        s.close()
    except Exception as e:
        logging.error(f"Error closing socket: {e}")
#FUNCTION TO START CLIENT
def start_client():
    
    host = '127.0.0.1'
    port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.connect((host, port))
            print("Connected to the server.")
            logging.info(f"Connected to server at {host}:{port}")
        except Exception as e:
            logging.error(f"Failed to connect to the server: {e}")
            print(f"Failed to connect to the server: {e}")
            return

        try:
            # Perform Diffie-Hellman key exchange
            shared_key = perform_dh_key_exchange(s)
        except Exception as e:
            logging.error(f"Key exchange failed: {e}")
            print(f"Key exchange failed: {e}")
            return

        while True:
            print("\n--- 💬 ------------- 💬 ---")
            print("📱 Maham's Chatting Application 📱")
            print("\n--- 💬 ------------- 💬 ---")
            print("\n--- 📋 Menu 📋 ---")
            print("1. 📝 Register")
            print("2. 🔑 Login")
            print("3. 🚪 Exit")
            choice = input("Select an option to proceed: ").strip()
            if choice == '1':
                register(s, shared_key)
            elif choice == '2':
                success = login(s, shared_key)
                if success:
                    chat(s, shared_key)
            elif choice == '3':
                print("Closing connection.")
                logging.info("Client initiated shutdown.")
                break
            else:
                print("Invalid option. Please try again.\n")
                logging.warning(f"Invalid menu option selected: {choice}")

        print("Client shutdown.")
        logging.info("Client shutdown.")

if __name__ == "__main__":
    start_client()