# Secure-Chat-System-with-Registration-Login-and-Encrypted-Communication
A secure client-server chat system implementing encrypted communication, user registration, login, and secure password handling using  SHA-256 .

## 📌 Features

- 🔑 **User Registration**
  - Email, username, password input
  - Encrypted transfer using AES (key via Diffie-Hellman)
  - Password hashing with SHA-256 and a unique salt

- 🔐 **Login System**
  - Username/password authentication
  - Secure password validation using stored hash + salt
 
- 💬 **Encrypted Chat**
  - Secure message exchange after login
 

## 🔧 Technologies Used

- 🔄 Diffie-Hellman Key Exchange
- 🐍 Python Sockets (for client-server communication)
- 📁 Text File Storage (`creds.txt` for storing credentials securely)

---

## 🚀 How to Run
- Open 2 terminals Simultaneously.
- On one terminal first run server.py
- On second terminal after running server run client.py

### Requirements
```bash
pip install -r requirements.txt
