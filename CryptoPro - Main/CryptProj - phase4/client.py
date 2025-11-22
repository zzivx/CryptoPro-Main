import socket, threading, os, base64, sys, json, time, datetime
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.asymmetric import padding as sign_padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization, hashes
import zipfile, tempfile, shutil, pathlib
from getpass import getpass

SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

KEYS_DIR = "keys"        # local (per client machine)
os.makedirs(KEYS_DIR, exist_ok=True)

# --- rotation config ---
ROTATE_EVERY_SEC = 120  # default: rotate every 2 minutes
ROTATION_TOLERANCE = 1  # loop sleep granularity

# Per-peer state
session_keys: dict[str, bytes] = {}           # peer -> 32B AES key (current)
peer_public_keys: dict[str, object] = {}      # peer -> rsa.RSAPublicKey
pending_session_starts: set[str] = set()      # peers we asked GETPUB for via /start
pending_rotations: set[str] = set()           # peers waiting for pubkey to rotate
next_rotation_at: dict[str, float] = {}       # peer -> unix timestamp for next rotation

state_lock = threading.Lock()
running = True

# ---------- RSA key handling ----------
def key_paths(username: str):
    return (
        os.path.join(KEYS_DIR, f"{username}_priv.pem"),
        os.path.join(KEYS_DIR, f"{username}_pub.pem"),
    )

def generate_or_load_rsa(username: str):
    """
    Loads RSA keypair if present (prompts for password if encrypted),
    otherwise generates a new keypair, optionally password-protects
    the private key, and creates a ZIP backup in key_backups/.
    """
    priv_path, pub_path = key_paths(username)

    # Load existing keys (handle encrypted private key)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            data = f.read()
        try:
            priv = serialization.load_pem_private_key(data, password=None)
        except TypeError:
            # Encrypted key → ask for passphrase
            pwd = getpass("Enter password for your private key: ").encode()
            priv = serialization.load_pem_private_key(data, password=pwd)
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub

    # Generate fresh keys
    print(f"No keys found for {username}. Generating new RSA keypair...")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    # Ask if user wants to protect the private key with a password
    choice = input("Do you want to protect your private key with a password? (y/n): ").strip().lower()
    if choice == "y":
        password = getpass("Enter a password: ").encode()
        enc_alg = serialization.BestAvailableEncryption(password)
    else:
        enc_alg = serialization.NoEncryption()

    # Save private key
    with open(priv_path, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc_alg,
            )
        )

    # Save public key
    with open(pub_path, "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    # Create automatic backup ZIP of the whole keys/ folder
    create_backup(username)

    return priv, pub

# ---------- Backups & restore ----------
def create_backup(username: str):
    backup_dir = "key_backups"
    os.makedirs(backup_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = os.path.join(backup_dir, f"{username}_keys_{ts}")
    shutil.make_archive(archive_name, "zip", KEYS_DIR)
    print(f"🔐 Backup created: {archive_name}.zip")

def restore_keys_from_zip(username: str, archive_path: str):
    """
    Restore keys from backup ZIP.
    Accepts either files named for the current user (preferred) or any *_priv.pem/_pub.pem pair.
    """
    priv_path, pub_path = key_paths(username)

    archive_path = os.path.abspath(archive_path)
    if not os.path.exists(archive_path):
        raise FileNotFoundError(f"Backup file not found: {archive_path}")
    if not zipfile.is_zipfile(archive_path):
        raise ValueError("Provided file is not a valid ZIP archive.")

    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(tmpdir)

        # Candidates we’d like (current username)
        preferred = [
            os.path.join(tmpdir, "keys", f"{username}_priv.pem"),
            os.path.join(tmpdir, f"{username}_priv.pem"),
        ], [
            os.path.join(tmpdir, "keys", f"{username}_pub.pem"),
            os.path.join(tmpdir, f"{username}_pub.pem"),
        ]

        cand_priv = next((p for p in preferred[0] if os.path.exists(p)), None)
        cand_pub  = next((p for p in preferred[1] if os.path.exists(p)), None)

        # Fallback: any *_priv.pem & *_pub.pem in keys/ or root
        def find_any_pair(rootdir):
            found_priv, found_pub = None, None
            for p in pathlib.Path(rootdir).rglob("*_priv.pem"):
                found_priv = str(p); break
            for p in pathlib.Path(rootdir).rglob("*_pub.pem"):
                found_pub = str(p); break
            return found_priv, found_pub

        if not cand_priv or not cand_pub:
            any_priv, any_pub = find_any_pair(os.path.join(tmpdir, "keys"))
            if not any_priv or not any_pub:
                any_priv, any_pub = find_any_pair(tmpdir)
            cand_priv = cand_priv or any_priv
            cand_pub  = cand_pub  or any_pub

        if not cand_priv or not cand_pub:
            raise RuntimeError("Could not find private/public key files inside the ZIP (looked in keys/ and root).")

        # Warn if restoring a different user’s key pair
        # (derive guessed username from filename prefix before '_priv.pem')
        guessed = os.path.basename(cand_priv).split("_priv.pem")[0]
        if guessed != username:
            ans = input(f"Restoring keys for '{guessed}', but you are logged in as '{username}'. Continue? (y/n): ").strip().lower()
            if ans != "y":
                raise RuntimeError("Restore cancelled by user.")

        # Safety backup of current keys (if any)
        if os.path.exists(priv_path) or os.path.exists(pub_path):
            os.makedirs("key_backups", exist_ok=True)
            ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            if os.path.exists(priv_path):
                shutil.copy2(priv_path, f"key_backups/{username}_priv_before_restore_{ts}.pem")
            if os.path.exists(pub_path):
                shutil.copy2(pub_path,  f"key_backups/{username}_pub_before_restore_{ts}.pem")

        # Overwrite keys
        os.makedirs(KEYS_DIR, exist_ok=True)
        shutil.copy2(cand_priv, priv_path)
        shutil.copy2(cand_pub,  pub_path)

    # Load restored keys (prompt for passphrase if encrypted)
    with open(priv_path, "rb") as f:
        data = f.read()
    try:
        priv = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pwd = getpass("Enter password for the restored private key: ").encode()
        priv = serialization.load_pem_private_key(data, password=pwd)

    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())

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

# ---------- AES-GCM helpers ----------
def aes_encrypt_with_session(peer: str, plaintext: str) -> str:
    with state_lock:
        key = session_keys.get(peer)
    if not key:
        return "[no-session]"
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")

def aes_decrypt_with_session(peer: str, b64_blob: str) -> str:
    try:
        with state_lock:
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

# ---------- Sign / Verify ----------
def sha256_bytes(s: str) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    h.update(s.encode("utf-8"))
    return h.finalize()

def sign_plaintext(priv, plaintext: str) -> str:
    digest = sha256_bytes(plaintext)
    sig = priv.sign(
        digest,
        sign_padding.PSS(mgf=sign_padding.MGF1(hashes.SHA256()), salt_length=sign_padding.PSS.MAX_LENGTH),
        Prehashed(hashes.SHA256()),
    )
    return base64.b64encode(sig).decode("utf-8")

def verify_plaintext(pub, plaintext: str, sig_b64: str) -> bool:
    try:
        digest = sha256_bytes(plaintext)
        sig = base64.b64decode(sig_b64.encode("utf-8"), validate=True)
        pub.verify(
            sig,
            digest,
            sign_padding.PSS(mgf=sign_padding.MGF1(hashes.SHA256()), salt_length=sign_padding.PSS.MAX_LENGTH),
            Prehashed(hashes.SHA256()),
        )
        return True
    except Exception:
        return False

# ---------- Bundle/Unbundle (ciphertext + signature) ----------
def bundle_payload(ciphertext_b64: str, signature_b64: str) -> str:
    obj = {"c": ciphertext_b64, "s": signature_b64}
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("utf-8")

def unbundle_payload(outer_b64: str):
    try:
        raw = base64.b64decode(outer_b64.encode("utf-8"), validate=True)
        obj = json.loads(raw.decode("utf-8"))
        return obj.get("c"), obj.get("s")
    except Exception:
        return outer_b64, None

# ---------- Networking helpers ----------
def send_line(sock: socket.socket, text: str):
    sock.sendall((text + "\n").encode("utf-8"))

# ---------- Session key exchange (RSA-OAEP) ----------
def request_pubkey(sock: socket.socket, peer: str):
    send_line(sock, f"GETPUB {peer}")

def set_next_rotation(peer: str, seconds: int | None = None):
    when = time.time() + (seconds if seconds is not None else ROTATE_EVERY_SEC)
    with state_lock:
        next_rotation_at[peer] = when

def rotate_key_now(sock: socket.socket, my_username: str, peer: str):
    """Generate a fresh AES key for peer, encrypt with peer RSA pub, send KEYEX, forget old key."""
    with state_lock:
        peer_pub = peer_public_keys.get(peer)
    if not peer_pub:
        with state_lock:
            pending_rotations.add(peer)
        request_pubkey(sock, peer)
        print(f"SYS Rotation pending: fetching {peer}'s public key.")
        return

    new_key = os.urandom(32)
    enc = peer_pub.encrypt(
        new_key,
        asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(),
                         label=None),
    )
    b64key = base64.b64encode(enc).decode("utf-8")

    with state_lock:
        session_keys[peer] = new_key

    send_line(sock, f"KEYEX {peer} {b64key}")
    print(f"SYS Session key rotated for {peer}.")
    set_next_rotation(peer)

# ---------- Auto-rotation background loop ----------
def rotation_loop(sock: socket.socket):
    while running:
        now = time.time()
        due_peers = []
        with state_lock:
            for p, t in list(next_rotation_at.items()):
                if now >= t:
                    due_peers.append(p)
        for p in due_peers:
            try:
                rotate_key_now(sock, "<me>", p)
            except Exception as e:
                print(f"SYS rotation error for {p}: {e}")
        time.sleep(ROTATION_TOLERANCE)

# ---------- Protocol handlers ----------
def handle_pub_line(sock: socket.socket, line: str, my_username: str, my_priv):
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

    with state_lock:
        peer_public_keys[user] = peer_pub

    start_it = False
    with state_lock:
        if user in pending_session_starts:
            pending_session_starts.discard(user)
            start_it = True

    if start_it:
        new_key = os.urandom(32)
        enc = peer_pub.encrypt(
            new_key,
            asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(),
                             label=None),
        )
        b64key = base64.b64encode(enc).decode("utf-8")
        with state_lock:
            session_keys[user] = new_key
        send_line(sock, f"KEYEX {user} {b64key}")
        print(f"SYS Session key created and sent to {user}. You can now /to {user} ...")
        set_next_rotation(user)

    do_rotate = False
    with state_lock:
        if user in pending_rotations:
            pending_rotations.discard(user)
            do_rotate = True
    if do_rotate:
        rotate_key_now(sock, my_username, user)

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
        with state_lock:
            session_keys[sender] = session_key
        print(f"SYS Session with {sender} established.")
        set_next_rotation(sender)
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
                    handle_pub_line(sock, line, my_username, my_priv)
                elif line.startswith("KEYEX_FROM "):
                    handle_keyex_from(line, my_priv)
                elif line.startswith("MSG "):
                    parts = line.split(" ", 4)
                    if len(parts) < 5:
                        print(f"SYS malformed MSG: {line}")
                        continue
                    _, mid, ts, sender, outer_b64 = parts

                    ct_b64, sig_b64 = unbundle_payload(outer_b64)
                    plaintext = aes_decrypt_with_session(sender, ct_b64)

                    verdict = "no-signature"
                    with state_lock:
                        pub = peer_public_keys.get(sender)
                    if not pub:
                        request_pubkey(sock, sender)
                        verdict = "unknown-key"
                    elif sig_b64:
                        verdict = "verified" if verify_plaintext(pub, plaintext, sig_b64) else "warning"

                    tag = "✅ verified" if verdict == "verified" else ("❓ unknown-key" if verdict == "unknown-key" else ("⚠️ warning" if verdict == "warning" else "ℹ️ no-signature"))
                    print(f"[{ts}] {sender}: {plaintext}  [{tag}]")

                elif line.startswith("HIST "):
                    parts = line.split(" ", 5)
                    if len(parts) < 6:
                        print(f"SYS malformed HIST: {line}")
                        continue
                    _, mid, ts, path, status, outer_b64 = parts
                    if outer_b64.startswith("__KEYEX__:"):
                        continue
                    try:
                        A, B = path.split("->", 1)
                    except ValueError:
                        A, B = path, ""
                    peer = B if A == my_username else A

                    ct_b64, sig_b64 = unbundle_payload(outer_b64)
                    plaintext = aes_decrypt_with_session(peer, ct_b64)

                    verdict = "no-signature"
                    with state_lock:
                        pub = peer_public_keys.get(peer)
                    if not pub:
                        request_pubkey(sock, peer)
                        verdict = "unknown-key"
                    elif sig_b64:
                        verdict = "verified" if verify_plaintext(pub, plaintext, sig_b64) else "warning"

                    tag = "✅ verified" if verdict == "verified" else ("❓ unknown-key" if verdict == "unknown-key" else ("⚠️ warning" if verdict == "warning" else "ℹ️ no-signature"))
                    print(f"(history {status}) [{ts}] {path}: {plaintext}  [{tag}]")

                else:
                    print(f"SYS {line}")

        except Exception as e:
            print(f"SYS recv error: {e}")
            break

def client():
    global running, ROTATE_EVERY_SEC
    username = input("Enter username: ").strip()
    if not username:
        print("Username required.")
        return

    my_priv, my_pub = generate_or_load_rsa(username)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_ADDRESS, SERVER_PORT))

    threading.Thread(target=handle_messages, args=(sock, username, my_priv), daemon=True).start()
    threading.Thread(target=rotation_loop, args=(sock,), daemon=True).start()

    # LOGIN and publish public key (base64 PEM)
    send_line(sock, f"LOGIN {username}")
    send_line(sock, f"PUBKEY {pubkey_b64(my_pub)}")

    print('Commands:')
    print('  /start <user>             establish secure session (RSA → new AES key)')
    print('  /to <user> <message>      send (signed + encrypted)')
    print('  /history                  show last 20 entries')
    print('  /sendpub                  resend your public key')
    print('  /rotate <user>            force rotate AES key for a peer now')
    print('  /rotate-all               force rotate AES keys for all peers now')
    print('  /rotate-interval <sec>    change auto-rotation interval (default 120)')
    print('  /backup                   create a ZIP backup of your keys now')
    print('  /restore <zip>            restore keys from backup ZIP & re-publish pubkey')
    print('  /quit                     exit')

    try:
        while True:
            msg = input()
            if not msg:
                continue
            lower = msg.lower()
            if lower.startswith("/quit"):
                break
            elif lower.startswith("/history"):
                send_line(sock, "HISTORY")
            elif lower.startswith("/sendpub"):
                send_line(sock, f"PUBKEY {pubkey_b64(my_pub)}")
                print("SYS Public key re-sent.")
            elif lower.startswith("/backup"):
                create_backup(username)
            elif lower.startswith("/rotate-all"):
                with state_lock:
                    peers = list(session_keys.keys())
                for p in peers:
                    rotate_key_now(sock, username, p)
            elif lower.startswith("/rotate-interval"):
                try:
                    _, sval = msg.split(" ", 1)
                    new_int = int(sval.strip())
                    ROTATE_EVERY_SEC = max(10, new_int)
                    with state_lock:
                        for p in list(session_keys.keys()):
                            set_next_rotation(p, ROTATE_EVERY_SEC)
                    print(f"SYS Rotation interval set to {ROTATE_EVERY_SEC} seconds.")
                except Exception:
                    print("Usage: /rotate-interval <seconds>")
            elif lower.startswith("/rotate "):
                try:
                    _, peer = msg.split(" ", 1)
                    rotate_key_now(sock, username, peer.strip())
                except ValueError:
                    print("Usage: /rotate <user>")
            elif lower.startswith("/start "):
                try:
                    _, peer = msg.split(" ", 1)
                    peer = peer.strip()
                except ValueError:
                    print("Usage: /start <user>")
                    continue
                with state_lock:
                    pending_session_starts.add(peer)
                request_pubkey(sock, peer)
            elif lower.startswith("/restore"):
                try:
                    _, path = msg.split(" ", 1)
                    path = path.strip().strip('"').strip("'")
                except ValueError:
                    print("Usage: /restore <path-to-backup.zip>")
                    continue
                try:
                    my_priv, my_pub = restore_keys_from_zip(username, path)
                    send_line(sock, f"PUBKEY {pubkey_b64(my_pub)}")
                    print("SYS Keys restored and public key re-published.")
                except Exception as e:
                    print(f"SYS Restore failed: {e}")
            elif lower.startswith("/to "):
                try:
                    _, rest = msg.split(" ", 1)
                    peer, text = rest.split(" ", 1)
                except ValueError:
                    print("Usage: /to <user> <message>")
                    continue
                with state_lock:
                    has_key = peer in session_keys
                if not has_key:
                    print("SYS No session. Run /start", peer)
                    continue
                sig_b64 = sign_plaintext(my_priv, text)
                ct_b64 = aes_encrypt_with_session(peer, text)
                if ct_b64 == "[no-session]":
                    print("SYS No session key set.")
                    continue
                outer = bundle_payload(ct_b64, sig_b64)
                send_line(sock, f"MSG {peer} {outer}")
            else:
                print('Use commands: /start, /to, /history, /sendpub, /rotate, /rotate-all, /rotate-interval, /backup, /restore, /quit')
    finally:
        running = False
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    client()
