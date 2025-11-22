import socket, threading, datetime, sys

# ==== In-memory state ====
connections = {}  # username -> socket
user_by_socket = {}  # socket -> username
lock = threading.Lock()

# message store with minimal metadata; content is ciphertext only
# each item: {"id": int, "ts": str(ISO UTC), "sender": str, "recipient": str,
#             "ciphertext": str(base64), "delivered": bool}
messages = []
next_id = 1

LOG_FILE = "ciphertexts.log"

def utc_iso():
    return datetime.datetime.now(datetime.UTC).isoformat()

def log_ciphertext(b64: str) -> None:
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{utc_iso()} {b64}\n")
    except Exception as e:
        print(f"[warn] log failed: {e}", file=sys.stderr)

def send_line(sock: socket.socket, text: str):
    try:
        sock.sendall((text + "\n").encode("utf-8"))
    except Exception:
        pass

def handle_client(sock: socket.socket, addr):
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

                # Commands from client:
                # LOGIN <username>
                # MSG <recipient> <base64ciphertext>
                # HISTORY
                parts = line.split(" ", 2)
                cmd = parts[0].upper()

                if cmd == "LOGIN":
                    if len(parts) < 2:
                        send_line(sock, "SYS Usage: LOGIN <username>")
                        continue
                    requested = parts[1].strip()

                    with lock:
                        # handle duplicate login
                        if requested in connections:
                            send_line(sock, "SYS Username in use. Pick another.")
                            continue
                        username = requested
                        connections[username] = sock
                        user_by_socket[sock] = username
                    send_line(sock, f"SYS Logged in as {username}")

                    # deliver any pending (undelivered) messages
                    deliver_pending(username)

                elif cmd == "MSG":
                    if username is None:
                        send_line(sock, "SYS Please LOGIN first.")
                        continue
                    if len(parts) < 3:
                        send_line(sock, "SYS Usage: MSG <recipient> <base64ciphertext>")
                        continue
                    subparts = parts[1].split(" ", 1)
                    recipient = parts[1].strip()
                    b64 = parts[2].strip()

                    # store message
                    with lock:
                        global next_id
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

                        # deliver if recipient online
                        r_sock = connections.get(recipient)
                        if r_sock:
                            send_line(r_sock, f"MSG {mid} {item['ts']} {username} {b64}")
                            item["delivered"] = True
                            send_line(sock, f"SYS Delivered to {recipient}")
                        else:
                            send_line(sock, f"SYS Queued for {recipient} (unread)")

                elif cmd == "HISTORY":
                    if username is None:
                        send_line(sock, "SYS Please LOGIN first.")
                        continue
                    # send last 20 messages involving this user (as sender or recipient)
                    with lock:
                        relevant = [m for m in messages if m["sender"] == username or m["recipient"] == username]
                        for m in relevant[-20:]:
                            status = "delivered" if m["delivered"] else "unread"
                            # Note: still not sending plaintext; just metadata + ciphertext
                            send_line(sock, f"HIST {m['id']} {m['ts']} {m['sender']}->{m['recipient']} {status} {m['ciphertext']}")

                else:
                    send_line(sock, "SYS Unknown command.")
    except Exception as e:
        print(f"[err] client {addr} error: {e}")

    # cleanup
    with lock:
        if sock in user_by_socket:
            uname = user_by_socket.pop(sock)
            connections.pop(uname, None)
    try:
        sock.close()
    except:
        pass

def deliver_pending(username: str):
    """Send all undelivered messages whose recipient == username."""
    r_sock = connections.get(username)
    if not r_sock:
        return
    for m in messages:
        if (m["recipient"] == username) and (not m["delivered"]):
            send_line(r_sock, f"MSG {m['id']} {m['ts']} {m['sender']} {m['ciphertext']}")
            m["delivered"] = True

def server():
    LISTENING_PORT = 12000
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('', LISTENING_PORT))
    s.listen(32)
    print(f"Server running on 0.0.0.0:{LISTENING_PORT} (ciphertext-only).")
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
