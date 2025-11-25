# Phase 4 – Digital Signatures & Message Integrity

Phase 4 adds **RSA-PSS digital signatures** and **SHA-256 hashing** to guarantee integrity and authenticity.

## 🔐 New Security Features
- Every message is:
  ✓ Hashed using SHA-256  
  ✓ Signed using RSA-PSS  
  ✓ Encrypted using AES  
- Receiver verifies signature against sender’s public key

## 🧠 Message Sending Process
1. SHA-256 digest computed
2. Digest signed with RSA-PSS using private key
3. Plaintext encrypted with AES session key
4. Client sends **{ciphertext, signature}**

## 🧠 Message Receiving Process
1. Receiver decrypts ciphertext using AES
2. Recomputes SHA-256 hash on plaintext
3. Verifies RSA-PSS signature
4. Shows status:
   - **Verified** (authentic)
   - **Warning** (tampered)
   - **Unknown key** (public key missing)

## ✔ Security Achievements
- Prevents impersonation  
- Detects tampering  
- Confirms sender identity  

Phase 4 successfully introduces **Authenticity + Integrity**.
