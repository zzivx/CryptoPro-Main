# Phase 5 – Final System: Rotation, Signing, Backup, Full Security

Phase 5 integrates all previous phases and adds **key rotation**, **backup &
restore**, and full end-to-end functionality.

## 🔐 Features
- Automatic RSA key creation on first run
- Public key auto-upload to server
- AES session key rotation every 120 seconds
- Manual rotation (/rotate, /rotate-all)
- Digital signatures (RSA-PSS)
- Integrity verification (SHA-256)
- Key backup + ZIP restore

## 🧠 Client Commands
/start <user>          Start secure session  
/to <user> <message>   Send encrypted + signed message  
/history               View message history  
/sendpub               Resend public key  
/rotate <user>         Force rotate AES key  
/rotate-all            Rotate all keys  
/backup                Backup RSA keys to ZIP  
/restore               Restore keys from ZIP  
/quit                  Exit  

## ✔ Achievements
- End-to-end encryption  
- Authenticity + integrity  
- Forward secrecy (rotating AES keys)  
- Secure identity with key backups  
- Complete and functional secure chat platform  
