import os, sys, socket, threading, datetime

# ---------- Paths made absolute to this script's directory ----------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBDIR = os.path.join(BASE_DIR, "public_keys")
LOG_FILE = os.path.join(BASE_DIR, "ciphertexts.log")
os.makedirs(PUBDIR, exist_ok=True)

print(f"[server] cwd={os.getcwd()}")
print(f"[server] public keys folder: {PUBDIR}")
print(f"[server] ciphertext log:     {LOG_FILE}")

# ==== In-memory state ====
connections = {}       # username -> socket
user_by_socket = {}    # socket -> username
lock = threading.Lock()

# Ciphertext-only message log (in memory + file)
messages = []
next_id = 1

def utc_iso():
    return datetime.datetime.now(datetime.UTC).isoformat()

def send_line(sock: socket.socket, text: str):
    try:
        sock.sendall((text + "\n").encode("utf-8"))
    except Exception:
        pass

def save_public_key(username: str, b64pem: str):
    path = os.path.join(PUBDIR, f"{username}.pem.b64")
    with open(path, "w", encoding="utf-8") as f:
        f.write(b64pem)

def load_public_key(username: str) -> str | None:
    path = os.path.join(PUBDIR, f"{username}.pem.b64")
    if not os.path.exists(path):
        return None
    return open(path, "r", encoding="utf-8").read().strip()

def log_ciphertext(b64: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{utc_iso()} {b64}\n")
    except Exception as e:
        print(f"[warn] log failed: {e}", file=sys.stderr)

def deliver_pending(username: str):
    """Deliver undelivered messages for recipient == username."""
    r_sock = connections.get(username)
    if not r_sock:
        return
    for m in messages:
        if (m["recipient"] == username) and (not m["delivered"]):
            # If it's a queued KEYEX, convert to KEYEX_FROM on delivery
            if isinstance(m["ciphertext"], str) and m["ciphertext"].startswith("__KEYEX__:"):
                b64key = m["ciphertext"].split(":", 1)[1]
                send_line(r_sock, f"KEYEX_FROM {m['sender']} {b64key}")
            else:
                send_line(r_sock, f"MSG {m['id']} {m['ts']} {m['sender']} {m['ciphertext']}")
            m["delivered"] = True

def handle_client(sock: socket.socket, addr):
    global next_id  # must be at function scope
    buffer = ""
    username = None
    send_line(sock, "SYS Welcome. Please LOGIN <username>")

    try:
        while True:
            data = sock.recv(4096)
            if not data:
                break
            buffer += data.decode("utf-8", errors="ignore")

            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue

                # Commands:
                # LOGIN <username>
                # PUBKEY <b64pem>
                # GETPUB <username>
                # KEYEX <recipient> <b64_rsa_encrypted_aeskey>
                # MSG <recipient> <b64ciphertext>
                # HISTORY
                parts = line.split(" ", 2)
                cmd = parts[0].upper()

                if cmd == "LOGIN":
                    if len(parts) < 2:
                        send_line(sock, "SYS Usage: LOGIN <username>")
                        continue
                    requested = parts[1].strip()
                    with lock:
                        if requested in connections:
                            send_line(sock, "SYS Username in use. Pick another.")
                            continue
                        username = requested
                        connections[username] = sock
                        user_by_socket[sock] = username
                    print(f"[login] {username} connected from {addr[0]}:{addr[1]}")
                    send_line(sock, f"SYS Logged in as {username}")
                    deliver_pending(username)

                elif cmd == "PUBKEY":
                    if username is None:
                        send_line(sock, "SYS Please LOGIN first.")
                        print("[PUBKEY] rejected: not logged in")
                        continue
                    if len(parts) < 2:
                        send_line(sock, "SYS Usage: PUBKEY <b64pem>")
                        print("[PUBKEY] rejected: missing payload")
                        continue
                    # Base64 shouldn't contain spaces; but if it does, re-join remainder.
                    b64pem = parts[1] if len(parts) == 2 else parts[1].strip()
                    if len(parts) == 3:
                        b64pem = (parts[1] + " " + parts[2]).strip()

                    save_public_key(username, b64pem)
                    send_line(sock, "SYS Public key registered.")
                    print(f"[PUBKEY] stored for user={username}, bytes={len(b64pem)}")

                elif cmd == "GETPUB":
                    if len(parts) < 2:
                        send_line(sock, "SYS Usage: GETPUB <username>")
                        continue
                    target = parts[1].strip()
                    b64pem = load_public_key(target)
                    if b64pem:
                        send_line(sock, f"PUB {target} {b64pem}")
                        print(f"[GETPUB] served {target} public key to {username or addr}")
                    else:
                        send_line(sock, f"SYS No public key for {target}. Ask them to login and send PUBKEY.")
                        print(f"[GETPUB] no key for {target}")

                elif cmd == "KEYEX":
                    if username is None:
                        send_line(sock, "SYS Please LOGIN first.")
                        continue
                    if len(parts) < 3:
                        send_line(sock, "SYS Usage: KEYEX <recipient> <b64_rsa_encrypted_aeskey>")
                        continue
                    recipient = parts[1].strip()
                    b64key = parts[2].strip()
                    with lock:
                        r_sock = connections.get(recipient)
                    if r_sock:
                        send_line(r_sock, f"KEYEX_FROM {username} {b64key}")
                        send_line(sock, f"SYS Session key sent to {recipient}.")
                        print(f"[KEYEX] live delivered from {username} -> {recipient}")
                    else:
                        # queue as a special "message" so it gets delivered after login
                        with lock:
                            mid = next_id
                            next_id += 1
                            messages.append({
                                "id": mid,
                                "ts": utc_iso(),
                                "sender": username,
                                "recipient": recipient,
                                "ciphertext": f"__KEYEX__:{b64key}",
                                "delivered": False,
                            })
                        send_line(sock, "SYS Recipient offline. Session key will be delivered on login.")
                        print(f"[KEYEX] queued from {username} -> {recipient}")

                elif cmd == "MSG":
                    if username is None:
                        send_line(sock, "SYS Please LOGIN first.")
                        continue
                    if len(parts) < 3:
                        send_line(sock, "SYS Usage: MSG <recipient> <b64ciphertext>")
                        continue
                    recipient = parts[1].strip()
                    b64 = parts[2].strip()

                    with lock:
                        mid = next_id
                        next_id += 1
                        item = {
                            "id": mid,
                            "ts": utc_iso(),
                            "sender": username,
                            "recipient": recipient,
                            "ciphertext": b64,
                            "delivered": False,
                        }
                        messages.append(item)
                        log_ciphertext(b64)
                        r_sock = connections.get(recipient)

                    if r_sock:
                        send_line(r_sock, f"MSG {mid} {item['ts']} {username} {b64}")
                        item["delivered"] = True
                        send_line(sock, f"SYS Delivered to {recipient}")
                        print(f"[MSG] {username} -> {recipient} (delivered) id={mid}")
                    else:
                        send_line(sock, f"SYS Queued for {recipient} (unread)")
                        print(f"[MSG] {username} -> {recipient} (queued) id={mid}")

                elif cmd == "HISTORY":
                    if username is None:
                        send_line(sock, "SYS Please LOGIN first.")
                        continue
                    with lock:
                        relevant = [m for m in messages if m["sender"] == username or m["recipient"] == username]
                        for m in relevant[-20:]:
                            status = "delivered" if m["delivered"] else "unread"
                            send_line(sock, f"HIST {m['id']} {m['ts']} {m['sender']}->{m['recipient']} {status} {m['ciphertext']}")
                    print(f"[HISTORY] served to {username}")

                else:
                    send_line(sock, "SYS Unknown command.")
    except Exception as e:
        print(f"[err] client {addr} error: {e}")

    # cleanup
    with lock:
        if sock in user_by_socket:
            uname = user_by_socket.pop(sock)
            connections.pop(uname, None)
            print(f"[logout] {uname} disconnected")
    try:
        sock.close()
    except:
        pass

def server():
    LISTENING_PORT = 12000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', LISTENING_PORT))
    s.listen(32)
    print(f"Server running on 0.0.0.0:{LISTENING_PORT} (ciphertext-only, public-key directory).")
    try:
        while True:
            c, addr = s.accept()
            threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            s.close()
        except:
            pass

if __name__ == "__main__":
    server()
