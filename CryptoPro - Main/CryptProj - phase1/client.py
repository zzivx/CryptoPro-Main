import socket, threading, os, base64, sys
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ======= SHARED SECRET (all clients must use the same) =======
# You can change this passphrase, but keep it identical on all clients.
PASSPHRASE = b"super-simple-shared-secret"
KEY = sha256(PASSPHRASE).digest()  # 32 bytes for AES-256
# ============================================================

SERVER_ADDRESS = '127.0.0.1'  # or LAN IP of the server
SERVER_PORT = 12000

def encrypt(plaintext: str) -> bytes:
    """
    AES-GCM encrypt. Returns base64-encoded bytes of (nonce || ciphertext+tag).
    We base64 so we can safely transmit as UTF-8 text through your existing server.
    """
    aes = AESGCM(KEY)
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    ct = aes.encrypt(nonce, plaintext.encode('utf-8'), None)  # ct includes tag
    blob = nonce + ct
    return base64.b64encode(blob)

def decrypt(b64_blob: str) -> str:
    """
    Base64-decodes and AES-GCM decrypts (nonce || ciphertext+tag) -> plaintext str.
    """
    try:
        blob = base64.b64decode(b64_blob.encode('utf-8'), validate=True)
        nonce, ct = blob[:12], blob[12:]
        aes = AESGCM(KEY)
        pt = aes.decrypt(nonce, ct, None)
        return pt.decode('utf-8', errors='replace')
    except Exception as e:
        # If decryption fails (e.g., corrupted/partial), show a hint instead of crashing.
        return f"[decryption failed: {e}]"

def handle_messages(connection: socket.socket):
    """
    Receive base64-encoded ciphertext messages from server,
    decrypt, and display to user.
    """
    buffer = ""
    while True:
        try:
            chunk = connection.recv(4096)
            if not chunk:
                print("Connection closed by server.")
                connection.close()
                break

            # The server relays UTF-8 text lines (base64). Accumulate and split by newline.
            buffer += chunk.decode('utf-8', errors='ignore')
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if not line:
                    continue
                # Server prepends "From ip:port - " before the ciphertext.
                # Try to split that prefix if present:
                prefix = " - "
                if prefix in line:
                    # Example: "From 127.0.0.1:55555 - <b64>"
                    try:
                        b64_payload = line.split(prefix, 1)[1].strip()
                    except Exception:
                        b64_payload = line.strip()
                else:
                    b64_payload = line

                plaintext = decrypt(b64_payload)
                print(plaintext)

        except Exception as e:
            print(f'Error handling message from server: {e}')
            connection.close()
            break

def client() -> None:
    """
    Connect to server, spawn receiver thread, read stdin, encrypt & send.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_ADDRESS, SERVER_PORT))

        threading.Thread(target=handle_messages, args=(sock,), daemon=True).start()
        print('Connected to secure chat! Type and press Enter. Type "quit" to exit.')

        while True:
            msg = input()
            if msg.strip().lower() == 'quit':
                break
            # Encrypt and send as a single UTF-8 line the server can relay.
            b64 = encrypt(msg).decode('utf-8')
            sock.sendall((b64 + '\n').encode('utf-8'))

        sock.close()

    except Exception as e:
        print(f'Error connecting to server socket: {e}')
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    client()
