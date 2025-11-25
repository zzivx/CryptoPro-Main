# Phase 3 – RSA Key Exchange & Per-User Session Keys

Phase 3 introduces **public-key cryptography** so each chat session gets its own secure AES key.

## 🔐 New Security Features
- Automatic RSA-2048 key pair generation per user
- Public keys uploaded to the server (public_keys/)
- AES session keys exchanged securely using **RSA-OAEP**
- Each chat pair has its own unique session key

## 🧠 How Key Exchange Works
1. Client logs in → uploads base64 encoded public key
2. When user A starts chatting with B:
   - A requests B’s public key: `GETPUB B`
   - A generates a fresh AES-256 session key
   - A encrypts it using B’s public key (RSA-OAEP)
   - Server forwards encrypted key to B
3. B decrypts using private RSA key
4. Both sides now share the same AES session key

## ✔ Security Achievements
- Server cannot decrypt AES session keys
- No manual pre-shared key required
- Each conversation is isolated (per-peer AES keys)

## ▶ How to Run
python server.py
python client.py


Phase 3 successfully introduces **Secure Key Exchange** and **Session Isolation**.
