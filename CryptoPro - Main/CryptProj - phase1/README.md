# Phase 1 – Basic Messaging & Symmetric Encryption

Phase 1 builds the foundation of the secure messaging project using a simple
client–server chat and **one shared AES key**.

## 🔐 Features
- Messages encrypted using a single shared AES-256 key
- Server stores **only ciphertext**
- Basic socket communication between clients and server

## 🧠 How It Works
1. Client encrypts plaintext with AES
2. Sends ciphertext to server
3. Server forwards ciphertext only
4. Receiver decrypts using same AES key

## ✔ Achievements
- Basic confidentiality
- Working encrypted chat
- Framework for later phases

## ▶ Run
python server.py
python client.py
