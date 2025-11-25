# Secure Instant Messaging Application – CryptoPro
DACS 3101 – Applied Cryptography | Term Project (Version C)

This project implements a fully end-to-end encrypted instant messaging system using modern cryptography. 
Clients exchange encrypted messages using AES session keys, RSA key exchange, and digital signatures.
The server stores ciphertext only and never sees plaintext.

This repository contains all phases (1–5), documentation, and the final GUI system.

------------------------------------------------------------
Repository Structure
------------------------------------------------------------

CryptoPro-Main/
|
|-- CryptProj - phase1/         (Basic AES-encrypted group chat)
|-- CryptProj - phase2/         (Multi-user encrypted messaging)
|-- CryptProj - phase3/         (RSA session key exchange)
|-- CryptProj - phase4/         (Digital signatures + integrity)
|-- CryptProj - phase5/         (Final GUI version)
|
|-- docs/
|     |-- Project_C_SecureInstantMessaging_v3.docx
|     |-- Secure_Instant_Messaging_Project_Report.docx
|     |-- Secure_Instant_Messaging_Presentation_Updated.pptx
|
|-- README.md
|-- .gitignore

------------------------------------------------------------
Security Overview
------------------------------------------------------------

The system guarantees:

- Confidentiality  
  *AES-256-GCM or AES-CBC is used to encrypt messages.*

- Integrity  
  *Messages are hashed using SHA-256. Any tampering is detected.*

- Authenticity  
  *Messages are signed using RSA-PSS digital signatures.*

- Secure Key Exchange  
  *AES session keys are exchanged using RSA-OAEP with SHA-256.*

- Minimal Trust in Server  
  The server only stores:
  - ciphertext  
  - timestamps  
  - usernames  
  - public keys  
  Never plaintext.

------------------------------------------------------------
Project Phases (Explanation)
------------------------------------------------------------

Phase 1 – Basic Messaging + AES Encryption  
(Folder: CryptProj - phase1)
- Simple socket-based chat server and client.
- Multiple clients can connect; the server broadcasts messages to all others.
- Messages are encrypted on the client using a single shared AES key.
- The server only sees base64 ciphertext and logs it; it never decrypts.

------------------------------------------------------------

Phase 2 – Multi-User Messaging + AES Encryption  
(Folder: CryptProj - phase2)
- Added support for multiple connected users.
- Added user-to-socket and socket-to-user mapping.
- Added delivered / unread states.
- Messages stored with:
  - ID
  - timestamp
  - sender
  - recipient
  - ciphertext
- AES symmetric encryption for all messages.

------------------------------------------------------------

Phase 3 – RSA Key Exchange + Session Keys  
(Folder: CryptProj - phase3)
- Each user has an RSA-2048 key pair.
- Private key stays on client device.
- Public key stored on server in public_keys/.
- When two users start a chat:
  - A random 32-byte AES session key is generated.
  - Sender encrypts session key with receiver's public key (RSA-OAEP).
  - Receiver decrypts using their private RSA key.
- Each conversation has its own AES session key.

------------------------------------------------------------

Phase 4 – Digital Signatures + Integrity Verification  
(Folder: CryptProj - phase4)
- Each outgoing message is:
  - Hashed using SHA-256
  - Signed using RSA-PSS
  - Encrypted using AES session key
- Receiver:
  - Decrypts
  - Recomputes SHA-256 hash
  - Verifies signature with sender's public key
- Tampering results in a "verification failed" warning.

------------------------------------------------------------

Phase 5 – Final GUI Client + Key Management  
(Folder: CryptProj - phase5)

Key Management:
- Generates RSA keys automatically on first use.
- Stores private key locally and securely.
- Uploads public key to server.

GUI (Tkinter):
- Chat window
- Message history
- Contacts
- Status indicators

Session Key Rotation:
- New AES session key generated every 120 seconds.
- Exchanged securely using RSA-OAEP.

Real-Time Messaging:
- Fully encrypted
- Digitally signed
- Integrity-checked
- Timestamped

------------------------------------------------------------
Running the Application
------------------------------------------------------------

1. Install Dependencies:
   pip install cryptography

   If using Python 3.12:
   py -3.12 -m pip install cryptography

------------------------------------------------------------

2. Run the Final Version (Phase 5):

   Start the server:
   cd "CryptProj - phase5"
   python server.py

   Start the client:
   (Open new terminal)
   cd "CryptProj - phase5"
   python client.py

   Test by running two clients at the same time.

------------------------------------------------------------
Technologies Used
------------------------------------------------------------

- Symmetric Encryption: AES-GCM / AES-CBC
- Asymmetric Encryption: RSA-2048 (OAEP + SHA-256)
- Digital Signatures: RSA-PSS
- Hashing: SHA-256
- GUI: Tkinter
- Networking: Python sockets
- Key Format: PEM (public keys only)
- Language: Python 3

------------------------------------------------------------
Security Summary
------------------------------------------------------------

- End-to-end encrypted messages  
- RSA signatures protect authenticity  
- SHA-256 hashing ensures integrity  
- AES session keys rotate periodically  
- Server stores only ciphertext  
- Public-key infrastructure for users  

------------------------------------------------------------
Documentation
------------------------------------------------------------

Documents inside /docs:
- Project specification
- Final report
- Presentation slides

------------------------------------------------------------
Team Members
------------------------------------------------------------

- Mustapha Sultan – 60301378
- Omar Ahmed – 60303791
- Ahmed Khoso – 60300920
- Abdulrahman Ba Wazir – 60105547

Course: DACS3101 – Applied Cryptography  
Instructor: Suzan Ali

------------------------------------------------------------
Notes
------------------------------------------------------------

- Private keys must not be uploaded (handled by .gitignore).
- Each phase can run independently.
- Phase 5 is the final integrated version.
