import socket, threading, os, base64
from hashlib import sha256
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# ======= SHARED SECRET (same for all clients) =======
PASSPHRASE = b"super-simple-shared-secret"
KEY_MAT = sha256(PASSPHRASE).digest()      # 32 bytes
ENC_KEY = sha256(b"enc"+KEY_MAT).digest()  # 32 bytes AES-256
MAC_KEY = sha256(b"mac"+KEY_MAT).digest()  # 32 bytes HMAC-SHA256 key
# ====================================================

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

def encrypt(plaintext: str) -> str:
    """
    AES-CBC + HMAC (encrypt-then-MAC).
    Output base64(iv || ciphertext || tag).
    """
    # 1) PKCS7 pad
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode("utf-8")) + padder.finalize()

    # 2) Encrypt with AES-CBC using random 16B IV
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ENC_KEY), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()

    # 3) HMAC over (iv || ct)
    h = hmac.HMAC(MAC_KEY, hashes.SHA256())
    h.update(iv + ct)
    tag = h.finalize()  # 32 bytes

    return base64.b64encode(iv + ct + tag).decode("utf-8")

def decrypt(b64_blob: str) -> str:
    """
    Verify HMAC then decrypt AES-CBC and unpad.
    """
    try:
        blob = base64.b64decode(b64_blob.encode("utf-8"), validate=True)
        if len(blob) < 16 + 32:
            return "[decryption failed: blob too short]"
        iv, rest = blob[:16], blob[16:]
        if len(rest) < 32:
            return "[decryption failed: no tag]"
        ct, tag = rest[:-32], rest[-32:]

        # 1) Verify HMAC first (constant-time)
        h = hmac.HMAC(MAC_KEY, hashes.SHA256())
        h.update(iv + ct)
        h.verify(tag)  # raises if invalid

        # 2) Decrypt
        cipher = Cipher(algorithms.AES(ENC_KEY), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()

        # 3) Unpad
        unpadder = padding.PKCS7(128).unpadder()
        pt = unpadder.update(padded) + unpadder.finalize()
        return pt.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[decryption failed: {e}]"

def handle_messages(sock: socket.socket):
    buffer = ""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("SYS Disconnected from server.")
                break
            buffer += data.decode("utf-8", errors="ignore")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                # Frames from server:
                # SYS <text>
                # MSG <id> <ts> <sender> <b64>
                # HIST <id> <ts> <sender->recipient> <status> <b64>
                if line.startswith("SYS "):
                    print(line)
                elif line.startswith("MSG "):
                    parts = line.split(" ", 4)
                    if len(parts) >= 5:
                        _, mid, ts, sender, b64 = parts
                        plaintext = decrypt(b64)
                        print(f"[{ts}] {sender}: {plaintext}")
                    else:
                        print(f"SYS malformed MSG: {line}")
                elif line.startswith("HIST "):
                    parts = line.split(" ", 5)
                    if len(parts) >= 6:
                        _, mid, ts, path, status, b64 = parts
                        plaintext = decrypt(b64)
                        print(f"(history {status}) [{ts}] {path}: {plaintext}")
                    else:
                        print(f"SYS malformed HIST: {line}")
                else:
                    print(f"SYS {line}")
        except Exception as e:
            print(f"SYS recv error: {e}")
            break

def client():
    username = input("Enter username: ").strip()
    if not username:
        print("Username required.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_ADDRESS, SERVER_PORT))

    threading.Thread(target=handle_messages, args=(sock,), daemon=True).start()
    sock.sendall(f"LOGIN {username}\n".encode("utf-8"))

    print('Commands:')
    print('  /to <user> <message>   send direct message')
    print('  /history               show last 20 messages')
    print('  /quit                  exit')

    try:
        while True:
            msg = input()
            if not msg:
                continue
            if msg.lower().startswith("/quit"):
                break
            elif msg.lower().startswith("/history"):
                sock.sendall(b"HISTORY\n")
            elif msg.lower().startswith("/to "):
                try:
                    _, rest = msg.split(" ", 1)
                    target, text = rest.split(" ", 1)
                except ValueError:
                    print("Usage: /to <user> <message>")
                    continue
                b64 = encrypt(text)
                sock.sendall(f"MSG {target} {b64}\n".encode("utf-8"))
            else:
                print('Use commands: /to, /history, /quit')
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    client()
