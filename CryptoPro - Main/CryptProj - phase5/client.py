# ui_client.py
import os, sys, json, base64, time, datetime, threading, socket, zipfile, tempfile, shutil, pathlib, queue
from hashlib import sha256
from tkinter import *
from tkinter import ttk, filedialog, simpledialog, messagebox

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asy_padding
from cryptography.hazmat.primitives.asymmetric import padding as sign_padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization, hashes

# ===================== Config =====================
SERVER_ADDRESS = "127.0.0.1"
SERVER_PORT = 12000

KEYS_DIR = "keys"
BACKUP_DIR = "key_backups"
os.makedirs(KEYS_DIR, exist_ok=True)
os.makedirs(BACKUP_DIR, exist_ok=True)

ROTATE_EVERY_SEC = 120
ROTATION_TOLERANCE = 1

# ===================== Client State =====================
sock: socket.socket | None = None
username: str | None = None

state_lock = threading.Lock()
running = True
inbox = queue.Queue()     # UI-thread safe message queue from network

session_keys: dict[str, bytes] = {}      # peer -> 32B AES key
peer_public_keys: dict[str, object] = {} # peer -> RSAPublicKey
pending_session_starts: set[str] = set()
pending_rotations: set[str] = set()
next_rotation_at: dict[str, float] = {}

my_priv = None
my_pub = None

# ===================== Crypto Helpers =====================
def key_paths(user: str):
    return (
        os.path.join(KEYS_DIR, f"{user}_priv.pem"),
        os.path.join(KEYS_DIR, f"{user}_pub.pem"),
    )

def generate_or_load_rsa(user: str):
    priv_path, pub_path = key_paths(user)
    # Load if present (handle encrypted private key)
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            data = f.read()
        try:
            priv = serialization.load_pem_private_key(data, password=None)
        except TypeError:
            pwd = simpledialog.askstring("Key Password", "Enter password for your private key:", show="*")
            if pwd is None: raise RuntimeError("Password required to load private key.")
            priv = serialization.load_pem_private_key(data, password=pwd.encode())
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        return priv, pub

    # Create new
    resp = messagebox.askyesno("Protect Private Key?", "Protect your private key with a password?")
    password = None
    if resp:
        password = simpledialog.askstring("Set Password", "Enter a password to protect your private key:", show="*")
        if password is None: password = ""

    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = priv.public_key()

    enc_alg = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()

    with open(priv_path, "wb") as f:
        f.write(
            priv.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=enc_alg,
            )
        )
    with open(pub_path, "wb") as f:
        f.write(
            pub.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    # Auto-backup
    create_backup(user)
    return priv, pub

def create_backup(user: str):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = os.path.join(BACKUP_DIR, f"{user}_keys_{ts}")
    # include the 'keys' folder inside the zip
    shutil.make_archive(archive_name, "zip", root_dir=".", base_dir="keys")
    ui_info(f"Backup created: {archive_name}.zip")

def restore_keys_from_zip(user: str, archive_path: str):
    priv_path, pub_path = key_paths(user)
    archive_path = os.path.abspath(archive_path)
    if not os.path.exists(archive_path) or not zipfile.is_zipfile(archive_path):
        raise FileNotFoundError("Backup file not found or not a ZIP.")

    with tempfile.TemporaryDirectory() as tmpdir:
        with zipfile.ZipFile(archive_path, "r") as zf:
            zf.extractall(tmpdir)

        # Try preferred layout keys/<user>_*.pem then root, then glob any *_priv/_pub
        cand_priv = None; cand_pub = None
        preferred = [
            os.path.join(tmpdir, "keys", f"{user}_priv.pem"),
            os.path.join(tmpdir, f"{user}_priv.pem"),
        ]
        preferred_pub = [
            os.path.join(tmpdir, "keys", f"{user}_pub.pem"),
            os.path.join(tmpdir, f"{user}_pub.pem"),
        ]
        for p in preferred:
            if os.path.exists(p): cand_priv = p; break
        for p in preferred_pub:
            if os.path.exists(p): cand_pub = p; break

        def find_any_pair(rootdir):
            a = next((str(p) for p in pathlib.Path(rootdir).rglob("*_priv.pem")), None)
            b = next((str(p) for p in pathlib.Path(rootdir).rglob("*_pub.pem")), None)
            return a, b

        if not cand_priv or not cand_pub:
            a, b = find_any_pair(os.path.join(tmpdir, "keys"))
            if not a or not b: a, b = find_any_pair(tmpdir)
            cand_priv = cand_priv or a
            cand_pub  = cand_pub  or b

        if not cand_priv or not cand_pub:
            raise RuntimeError("Could not find private/public key files in ZIP.")

        # Backup current keys before overwrite
        if os.path.exists(priv_path): shutil.copy2(priv_path, os.path.join(BACKUP_DIR, f"{user}_priv_before_restore.pem"))
        if os.path.exists(pub_path):  shutil.copy2(pub_path,  os.path.join(BACKUP_DIR, f"{user}_pub_before_restore.pem"))

        os.makedirs(KEYS_DIR, exist_ok=True)
        shutil.copy2(cand_priv, priv_path)
        shutil.copy2(cand_pub,  pub_path)

    # Load restored (prompt for passphrase if encrypted)
    with open(priv_path, "rb") as f:
        data = f.read()
    try:
        priv = serialization.load_pem_private_key(data, password=None)
    except TypeError:
        pwd = simpledialog.askstring("Key Password", "Enter password for the restored private key:", show="*")
        if pwd is None: raise RuntimeError("Password required to load restored key.")
        priv = serialization.load_pem_private_key(data, password=pwd.encode())
    with open(pub_path, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    return priv, pub

def pubkey_b64(pub) -> str:
    pem = pub.public_bytes(encoding=serialization.Encoding.PEM,
                           format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(pem).decode("utf-8")

def load_pub_from_b64(b64pem: str):
    pem = base64.b64decode(b64pem.encode("utf-8"))
    return serialization.load_pem_public_key(pem)

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

def aes_encrypt_with_session(peer: str, plaintext: str) -> str:
    with state_lock:
        key = session_keys.get(peer)
    if not key: return "[no-session]"
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("utf-8")

def aes_decrypt_with_session(peer: str, b64_blob: str) -> str:
    try:
        with state_lock:
            key = session_keys.get(peer)
        if not key: return "[no-session]"
        blob = base64.b64decode(b64_blob.encode("utf-8"), validate=True)
        nonce, ct = blob[:12], blob[12:]
        aes = AESGCM(key)
        pt = aes.decrypt(nonce, ct, None)
        return pt.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[decryption failed: {e}]"

def bundle_payload(ct_b64: str, sig_b64: str) -> str:
    obj = {"c": ct_b64, "s": sig_b64}
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("utf-8")

def unbundle_payload(outer_b64: str):
    try:
        raw = base64.b64decode(outer_b64.encode("utf-8"), validate=True)
        obj = json.loads(raw.decode("utf-8"))
        return obj.get("c"), obj.get("s")
    except Exception:
        return outer_b64, None

# ===================== Networking =====================
def send_line(text: str):
    global sock
    if sock:
        sock.sendall((text + "\n").encode("utf-8"))

def request_pubkey(peer: str):
    send_line(f"GETPUB {peer}")

def set_next_rotation(peer: str, seconds: int | None = None):
    when = time.time() + (seconds if seconds is not None else ROTATE_EVERY_SEC)
    with state_lock:
        next_rotation_at[peer] = when

def rotate_key_now(peer: str):
    with state_lock:
        peer_pub = peer_public_keys.get(peer)
    if not peer_pub:
        with state_lock:
            pending_rotations.add(peer)
        request_pubkey(peer)
        ui_info(f"Rotation pending: fetching {peer}'s public key.")
        return

    new_key = os.urandom(32)
    enc = peer_pub.encrypt(
        new_key,
        asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                         algorithm=hashes.SHA256(), label=None),
    )
    b64key = base64.b64encode(enc).decode("utf-8")
    with state_lock:
        session_keys[peer] = new_key
    send_line(f"KEYEX {peer} {b64key}")
    ui_info(f"Session key rotated for {peer}.")
    set_next_rotation(peer)

def rotation_loop():
    while running:
        now = time.time()
        due = []
        with state_lock:
            for p, t in list(next_rotation_at.items()):
                if now >= t: due.append(p)
        for p in due:
            try: rotate_key_now(p)
            except Exception as e: ui_info(f"Rotation error for {p}: {e}")
        time.sleep(ROTATION_TOLERANCE)

def net_loop():
    buffer = ""
    try:
        while running:
            data = sock.recv(4096)
            if not data:
                inbox.put(("sys", "Disconnected from server.")); break
            buffer += data.decode("utf-8", errors="ignore")
            while "\n" in buffer:
                raw, buffer = buffer.split("\n", 1)
                line = raw.strip()
                if not line: continue
                handle_protocol_line(line)
    except Exception as e:
        inbox.put(("sys", f"Network error: {e}"))

def handle_protocol_line(line: str):
    if line.startswith("SYS "):
        inbox.put(("sys", line[4:])); return
    if line.startswith("PUB "):
        handle_pub_line(line); return
    if line.startswith("KEYEX_FROM "):
        handle_keyex_from(line); return
    if line.startswith("MSG "):
        # MSG <id> <ts> <sender> <outer_b64>
        parts = line.split(" ", 4)
        if len(parts) < 5:
            inbox.put(("sys", f"Malformed MSG: {line}")); return
        _, mid, ts, sender, outer_b64 = parts
        ct_b64, sig_b64 = unbundle_payload(outer_b64)
        plaintext = aes_decrypt_with_session(sender, ct_b64)

        verdict = "no"
        with state_lock: pub = peer_public_keys.get(sender)
        if not pub:
            request_pubkey(sender); verdict = "unknown"
        elif sig_b64:
            verdict = "ok" if verify_plaintext(pub, plaintext, sig_b64) else "bad"
        inbox.put(("msg", ts, sender, plaintext, verdict))
        return
    if line.startswith("HIST "):
        # HIST <id> <ts> <A->B> <status> <outer_b64>
        parts = line.split(" ", 5)
        if len(parts) < 6:
            inbox.put(("sys", f"Malformed HIST: {line}")); return
        _, mid, ts, path, status, outer_b64 = parts
        if outer_b64.startswith("__KEYEX__:"):  # skip queued keyex in history
            return
        try:
            A, B = path.split("->", 1)
        except ValueError:
            A, B = path, ""
        peer = B if A == username else A
        ct_b64, sig_b64 = unbundle_payload(outer_b64)
        plaintext = aes_decrypt_with_session(peer, ct_b64)

        verdict = "no"
        with state_lock: pub = peer_public_keys.get(peer)
        if not pub:
            request_pubkey(peer); verdict = "unknown"
        elif sig_b64:
            verdict = "ok" if verify_plaintext(pub, plaintext, sig_b64) else "bad"
        inbox.put(("hist", ts, path, status, plaintext, verdict))
        return
    inbox.put(("sys", f"Unknown: {line}"))

def handle_pub_line(line: str):
    # "PUB <user> <b64pem>"
    parts = line.split(" ", 2)
    if len(parts) < 3:
        inbox.put(("sys", "Malformed PUB")); return
    user, b64pem = parts[1], parts[2]
    try:
        peer_pub = load_pub_from_b64(b64pem)
    except Exception as e:
        inbox.put(("sys", f"Failed loading {user}'s public key: {e}")); return
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
                             algorithm=hashes.SHA256(), label=None),
        )
        b64key = base64.b64encode(enc).decode("utf-8")
        with state_lock: session_keys[user] = new_key
        send_line(f"KEYEX {user} {b64key}")
        inbox.put(("sys", f"Session key created and sent to {user}. You can now send messages."))
        set_next_rotation(user)

    do_rotate = False
    with state_lock:
        if user in pending_rotations:
            pending_rotations.discard(user)
            do_rotate = True
    if do_rotate:
        rotate_key_now(user)

def handle_keyex_from(line: str):
    # "KEYEX_FROM <sender> <b64>"
    parts = line.split(" ", 2)
    if len(parts) < 3:
        inbox.put(("sys", "Malformed KEYEX_FROM")); return
    sender, b64key = parts[1], parts[2]
    try:
        enc = base64.b64decode(b64key.encode("utf-8"), validate=True)
        session_key = my_priv.decrypt(
            enc,
            asy_padding.OAEP(mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
                             algorithm=hashes.SHA256(), label=None),
        )
        with state_lock: session_keys[sender] = session_key
        inbox.put(("sys", f"Session with {sender} established."))
        set_next_rotation(sender)
    except Exception as e:
        inbox.put(("sys", f"Failed to decrypt session key from {sender}: {e}"))

# ===================== UI Helpers =====================
def ui_info(text: str):
    inbox.put(("sys", text))

def ui_pump():
    # Drain messages from net thread to UI
    try:
        while True:
            item = inbox.get_nowait()
            kind = item[0]
            if kind == "sys":
                log("[SYS] " + item[1])
            elif kind == "msg":
                _, ts, sender, plaintext, verdict = item
                badge = {"ok":"✅ verified", "bad":"⚠️ warning", "unknown":"❓ unknown-key", "no":"ℹ️ no-signature"}[verdict]
                log(f"[{ts}] {sender}: {plaintext}  [{badge}]")
            elif kind == "hist":
                _, ts, path, status, plaintext, verdict = item
                badge = {"ok":"✅ verified", "bad":"⚠️ warning", "unknown":"❓ unknown-key", "no":"ℹ️ no-signature"}[verdict]
                log(f"(history {status}) [{ts}] {path}: {plaintext}  [{badge}]")
    except queue.Empty:
        pass
    root.after(100, ui_pump)

def log(text: str):
    chat.configure(state="normal")
    chat.insert("end", text + "\n")
    chat.see("end")
    chat.configure(state="disabled")

# ===================== UI Actions =====================
def do_connect():
    global sock, username, my_priv, my_pub
    if sock: return
    username = user_var.get().strip()
    if not username:
        messagebox.showerror("Error", "Enter a username.")
        return
    try:
        my_priv, my_pub = generate_or_load_rsa(username)
    except Exception as e:
        messagebox.showerror("Key Error", str(e)); return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_ADDRESS, SERVER_PORT))
        sock = s
    except Exception as e:
        messagebox.showerror("Network", f"Failed to connect: {e}"); return

    send_line(f"LOGIN {username}")
    send_line(f"PUBKEY {pubkey_b64(my_pub)}")
    log(f"Connected as {username}. Public key registered.")

    threading.Thread(target=net_loop, daemon=True).start()
    threading.Thread(target=rotation_loop, daemon=True).start()
    connect_btn.config(state=DISABLED)
    start_btn.config(state=NORMAL)
    send_btn.config(state=NORMAL)
    hist_btn.config(state=NORMAL)
    rotate_btn.config(state=NORMAL)
    rotate_all_btn.config(state=NORMAL)
    backup_btn.config(state=NORMAL)
    restore_btn.config(state=NORMAL)
    interval_btn.config(state=NORMAL)

def do_start_session():
    peer = peer_var.get().strip()
    if not peer:
        messagebox.showwarning("Peer", "Enter a peer username.")
        return
    with state_lock: pending_session_starts.add(peer)
    request_pubkey(peer)
    log(f"Requested {peer}'s public key…")

def do_send():
    peer = peer_var.get().strip()
    text = msg_var.get().strip()
    if not peer or not text:
        return
    with state_lock: has = (peer in session_keys)
    if not has:
        log(f"SYS No session with {peer}. Click Start Session first.")
        return
    sig_b64 = sign_plaintext(my_priv, text)
    ct_b64 = aes_encrypt_with_session(peer, text)
    if ct_b64 == "[no-session]":
        log("SYS No session key set."); return
    outer = bundle_payload(ct_b64, sig_b64)
    send_line(f"MSG {peer} {outer}")
    msg_var.set("")

def do_history():
    send_line("HISTORY")

def do_rotate():
    peer = peer_var.get().strip()
    if not peer: return
    rotate_key_now(peer)

def do_rotate_all():
    with state_lock:
        peers = list(session_keys.keys())
    for p in peers:
        rotate_key_now(p)

def do_set_interval():
    global ROTATE_EVERY_SEC
    s = simpledialog.askinteger("Rotation Interval", "Seconds (min 10):", minvalue=10, initialvalue=ROTATE_EVERY_SEC)
    if not s: return
    ROTATE_EVERY_SEC = max(10, int(s))
    with state_lock:
        for p in list(session_keys.keys()):
            set_next_rotation(p, ROTATE_EVERY_SEC)
    log(f"Rotation interval set to {ROTATE_EVERY_SEC} seconds.")

def do_backup():
    create_backup(username)

def do_restore():
    global my_priv, my_pub
    path = filedialog.askopenfilename(title="Select backup ZIP", filetypes=[("Zip Files","*.zip"), ("All Files","*.*")])
    if not path: return
    try:
        my_priv, my_pub = restore_keys_from_zip(username, path)
        send_line(f"PUBKEY {pubkey_b64(my_pub)}")
        log("Keys restored and public key re-published.")
    except Exception as e:
        messagebox.showerror("Restore Failed", str(e))

# ===================== Build UI =====================
root = Tk()
root.title("Secure Chat (Phase 5 GUI)")

top = ttk.Frame(root, padding=8); top.pack(fill="x")
ttk.Label(top, text="Username:").pack(side="left")
user_var = StringVar(); ttk.Entry(top, textvariable=user_var, width=18).pack(side="left", padx=4)
connect_btn = ttk.Button(top, text="Connect", command=do_connect); connect_btn.pack(side="left", padx=4)

peer_row = ttk.Frame(root, padding=8); peer_row.pack(fill="x")
ttk.Label(peer_row, text="Peer:").pack(side="left")
peer_var = StringVar(); ttk.Entry(peer_row, textvariable=peer_var, width=18).pack(side="left", padx=4)
start_btn = ttk.Button(peer_row, text="Start Session", command=do_start_session, state=DISABLED); start_btn.pack(side="left", padx=4)
rotate_btn = ttk.Button(peer_row, text="Rotate", command=do_rotate, state=DISABLED); rotate_btn.pack(side="left", padx=4)
rotate_all_btn = ttk.Button(peer_row, text="Rotate All", command=do_rotate_all, state=DISABLED); rotate_all_btn.pack(side="left", padx=4)
interval_btn = ttk.Button(peer_row, text="Set Interval", command=do_set_interval, state=DISABLED); interval_btn.pack(side="left", padx=4)

mid = ttk.Frame(root, padding=(8,0,8,8)); mid.pack(fill="both", expand=True)
chat = Text(mid, height=20, state="disabled", wrap="word")
chat.pack(fill="both", expand=True)

entry_row = ttk.Frame(root, padding=8); entry_row.pack(fill="x")
msg_var = StringVar()
ttk.Entry(entry_row, textvariable=msg_var).pack(side="left", fill="x", expand=True, padx=4)
send_btn = ttk.Button(entry_row, text="Send", command=do_send, state=DISABLED); send_btn.pack(side="left", padx=4)

bottom = ttk.Frame(root, padding=8); bottom.pack(fill="x")
hist_btn = ttk.Button(bottom, text="History", command=do_history, state=DISABLED); hist_btn.pack(side="left", padx=4)
backup_btn = ttk.Button(bottom, text="Backup", command=do_backup, state=DISABLED); backup_btn.pack(side="left", padx=4)
restore_btn = ttk.Button(bottom, text="Restore", command=do_restore, state=DISABLED); restore_btn.pack(side="left", padx=4)

root.after(100, ui_pump)

def on_close():
    global running, sock
    running = False
    try:
        if sock: sock.close()
    except: pass
    root.destroy()
root.protocol("WM_DELETE_WINDOW", on_close)

root.mainloop()
