# Phase 2 – Multi-User Messaging + AES Encryption

In this phase, the system upgrades from simple messaging to **encrypted multi-user chat** using **AES symmetric encryption**.

## 🔐 Security Features in Phase 2
- AES-256-GCM encryption for all messages
- Each message uses a random 12-byte nonce
- Server stores **ciphertext only**
- Server cannot decrypt or read messages

## 🧠 How It Works
1. Client generates a random AES key (pre-shared or static in Phase 2).
2. Before sending a message:
   - A 12-byte nonce is generated
   - AES-GCM encrypts the plaintext
   - Ciphertext is Base64-encoded
3. Server relays ciphertext only.
4. Receiver decrypts using the same AES key.

## 🗂 Message Format Stored on the Server


## ▶ How to Run
Start Server:

Start Client:


Phase 2 successfully introduces **Confidentiality**.
