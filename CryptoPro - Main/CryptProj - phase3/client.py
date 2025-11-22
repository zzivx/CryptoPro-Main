import socket, threading, os, base64, sys
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives import serialization, hashes

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

KEYS_DIR = "keys"        # local (per client machine)
os.makedirs(KEYS_DIR, exist_ok=True)

# Per-peer AES session keys after KEYEX
session_keys: dict[str, bytes] = {}  # peer -> 32B AES key

# ---------- RSA key handling ----------
def key_paths(username: str):
    return (
        os.path.join(KEYS_DIR, f"{username}_priv.pem"),
        os.path.join(KEYS_DIR, f"{username}_pub.pem"),
    )

def generate_or_load_rsa(username: str):
    priv_path, pub_path = key_paths(username)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        # load existing
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub

    # generate fresh
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    with open(priv_path, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(pub_path, "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
    return priv, pub

def pubkey_b64(pub) -> str:
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("utf-8")

def load_pub_from_b64(b64pem: str):
    pem = base64.b64decode(b64pem.encode("utf-8"))
    return serialization.load_pem_public_key(pem)

# ---------- AES-GCM helpers (per-session key) ----------
def encrypt_with_session(peer: str, plaintext: str) -> str:
    key = session_keys.get(peer)
    if not key:
        return "[no-session]"
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")

def decrypt_with_session(peer: str, b64_blob: str) -> str:
    try:
        key = session_keys.get(peer)
        if not key:
            return "[no-session]"
        blob = base64.b64decode(b64_blob.encode("utf-8"), validate=True)
        nonce, ct = blob[:12], blob[12:]
        aes = AESGCM(key)
        pt = aes.decrypt(nonce, ct, None)
        return pt.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[decryption failed: {e}]"

# ---------- Session key exchange ----------
def start_session(sock: socket.socket, my_username: str, peer: str):
    """
    Fetch peer public key, generate a fresh 32B AES key, RSA-OAEP encrypt it,
    and send via server. Store locally for me; peer will store after decrypt.
    """
    # ask server for peer's pubkey
    sock.sendall(f"GETPUB {peer}\n".encode("utf-8"))

def handle_pub_line(sock: socket.socket, line: str, my_username: str):
    # "PUB <user> <b64pem>"
    parts = line.split(" ", 2)
    if len(parts) < 3:
        print("SYS malformed PUB")
        return
    user, b64pem = parts[1], parts[2]
    try:
        peer_pub = load_pub_from_b64(b64pem)
    except Exception as e:
        print(f"SYS failed to load {user}'s public key: {e}")
        return

    # generate AES session key
    session_key = os.urandom(32)
    session_keys[user] = session_key

    # RSA-OAEP encrypt the session key to recipient's public key
    enc = peer_pub.encrypt(
        session_key,
        asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None),
    )
    b64key = base64.b64encode(enc).decode("utf-8")
    sock.sendall(f"KEYEX {user} {b64key}\n".encode("utf-8"))
    print(f"SYS Session key created and sent to {user}. You can now /to {user} ...")

def handle_keyex_from(line: str, my_priv):
    # "KEYEX_FROM <sender> <b64_rsa_encrypted_aeskey>"
    parts = line.split(" ", 2)
    if len(parts) < 3:
        print("SYS malformed KEYEX_FROM")
        return
    sender, b64key = parts[1], parts[2]
    try:
        enc = base64.b64decode(b64key.encode("utf-8"), validate=True)
        session_key = my_priv.decrypt(
            enc,
            asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None),
        )
        session_keys[sender] = session_key
        print(f"SYS Session with {sender} established.")
    except Exception as e:
        print(f"SYS failed to decrypt session key from {sender}: {e}")

# ---------- Networking ----------
def handle_messages(sock: socket.socket, my_username: str, my_priv):
    buffer = ""
    while True:
        try:
            data = sock.recv(4096)
            if not data:
                print("SYS Disconnected from server.")
                break
            buffer += data.decode("utf-8", errors="ignore")
            while "\n" in buffer:
                raw, buffer = buffer.split("\n", 1)
                line = raw.strip()
                if not line:
                    continue

                if line.startswith("SYS "):
                    print(line)
                elif line.startswith("PUB "):
                    handle_pub_line(sock, line, my_username)
                elif line.startswith("KEYEX_FROM "):
                    handle_keyex_from(line, my_priv)
                elif line.startswith("MSG "):
                    # MSG <id> <ts> <sender> <b64>
                    parts = line.split(" ", 4)
                    if len(parts) >= 5:
                        _, mid, ts, sender, b64 = parts
                        plaintext = decrypt_with_session(sender, b64)
                        print(f"[{ts}] {sender}: {plaintext}")
                    else:
                        print(f"SYS malformed MSG: {line}")
                elif line.startswith("HIST "):
                    # HIST ... content might include queued KEYEX markers; skip those here.
                    parts = line.split(" ", 5)
                    if len(parts) >= 6:
                        _, mid, ts, path, status, b64 = parts
                        if b64.startswith("__KEYEX__:"):
                            # pending key; server will convert to KEYEX_FROM after login
                            continue
                        # pick peer from path "A->B"
                        peer = path.split("->")[0]
                        plaintext = decrypt_with_session(peer, b64)
                        print(f"(history {status}) [{ts}] {path}: {plaintext}")
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

    # Ensure RSA keys exist (or create)
    my_priv, my_pub = generate_or_load_rsa(username)

    # Connect
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_ADDRESS, SERVER_PORT))

    threading.Thread(target=handle_messages, args=(sock, username, my_priv), daemon=True).start()

    # LOGIN and publish public key (base64 PEM)
    sock.sendall(f"LOGIN {username}\n".encode("utf-8"))
    my_pub_b64 = pubkey_b64(my_pub)
    sock.sendall(f"PUBKEY {my_pub_b64}\n".encode("utf-8"))

    print('Commands:')
    print('  /start <user>          establish secure session (RSA → fresh AES key)')
    print('  /to <user> <message>   send (requires session)')
    print('  /history               show last 20 metadata entries')
    print('  /sendpub               resend your public key to server')
    print('  /quit                  exit')

    try:
        while True:
            msg = input()
            if not msg:
                continue
            lower = msg.lower()
            if lower.startswith("/quit"):
                break
            elif lower.startswith("/history"):
                sock.sendall(b"HISTORY\n")
            elif lower.startswith("/sendpub"):
                my_pub_b64 = pubkey_b64(my_pub)
                sock.sendall(f"PUBKEY {my_pub_b64}\n".encode("utf-8"))
                print(f"SYS Public key re-sent ({len(my_pub_b64)} bytes)")
            elif lower.startswith("/start "):
                try:
                    _, peer = msg.split(" ", 1)
                    peer = peer.strip()
                except ValueError:
                    print("Usage: /start <user>")
                    continue
                start_session(sock, username, peer)
            elif lower.startswith("/to "):
                try:
                    _, rest = msg.split(" ", 1)
                    peer, text = rest.split(" ", 1)
                except ValueError:
                    print("Usage: /to <user> <message>")
                    continue
                if peer not in session_keys:
                    print("SYS No session. Run /start", peer)
                    continue
                b64 = encrypt_with_session(peer, text)
                if b64 == "[no-session]":
                    print("SYS No session key set.")
                    continue
                sock.sendall(f"MSG {peer} {b64}\n".encode("utf-8"))
            else:
                print('Use commands: /start, /to, /history, /sendpub, /quit')
    finally:
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    client()
