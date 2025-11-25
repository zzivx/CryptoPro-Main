What Phase 5 Includes

Automatic RSA key generation (first run)

Public key upload to server

AES session keys for each conversation

RSA-OAEP key exchange

RSA-PSS digital signatures

SHA-256 hashing

Automatic AES key rotation (every 120 sec)

Manual key rotation (/rotate)

Key backup & restore (ZIP file)

Clean terminal-based client with background threads

Server stores only ciphertext (never plaintext)

How it Works (Short)

User logs in → RSA keys created automatically

/start <user> → fetch pubkey + send encrypted AES key

/to <user> msg → message is:

signed (RSA-PSS)

encrypted (AES-GCM)

sent to server

Receiver decrypts + verifies signature

Session keys rotate every 2 minutes for forward secrecy

Users can backup or restore their keys

Commands
/start <user>     start secure session
/to <user> <msg>  send encrypted + signed message
/history          show last messages
/sendpub          resend your public key
/rotate <user>    force rotate key
/rotate-all       rotate all keys
/backup           create a ZIP backup of your keys
/restore          restore keys from ZIP
/quit             exit

How to Run
Server:
cd "CryptProj - phase5"
python server.py

Client:
python client.py


Run two clients to test.

Folder Structure
CryptProj - phase5/
│-- client.py
│-- server.py
│-- public_keys/
│-- keys/
│-- key_backups/
│-- ciphertexts.log

Security Summary

End-to-end encrypted

RSA-PSS signatures

AES-GCM encryption

RSA-OAEP key exchange

Key rotation enabled

Server stores ciphertext only
