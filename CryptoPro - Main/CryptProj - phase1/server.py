import socket, threading, datetime

# Global list of client sockets
connections = []

# Simple ciphertext log file (server stores only encrypted data)
LOG_FILE = "ciphertexts.log"

def log_ciphertext(line: str) -> None:
    """
    Append the base64 ciphertext line to a log file with a timestamp.
    The server never sees plaintext.
    """
    try:
        ts = datetime.datetime.now(datetime.UTC).isoformat()
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{ts} {line}\n")
    except Exception as e:
        print(f"[warn] failed to log ciphertext: {e}")

def handle_user_connection(connection: socket.socket, address) -> None:
    """
    Receive base64 text (ciphertext) from a client and broadcast to others.
    The server does NOT decrypt; it only logs ciphertext and relays it.
    """
    buffer = ""
    while True:
        try:
            data = connection.recv(4096)
            if not data:
                remove_connection(connection)
                break

            buffer += data.decode('utf-8', errors='ignore')

            # Process full lines (messages are sent as single base64 lines)
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                line = line.strip()
                if not line:
                    continue

                # Log only ciphertext (base64). Do not print plaintext.
                log_ciphertext(line)

                # Broadcast in a readable format for clients: we keep the original
                # base64 and add a small prefix so clients can show the sender.
                msg_to_send = f"From {address[0]}:{address[1]} - {line}\n"
                broadcast(msg_to_send.encode('utf-8'), connection)

        except Exception as e:
            print(f'Error handling user {address}: {e}')
            remove_connection(connection)
            break

def broadcast(message: bytes, from_conn: socket.socket) -> None:
    """
    Send the ciphertext line to all clients except the sender.
    """
    for client_conn in list(connections):
        if client_conn is not from_conn:
            try:
                client_conn.sendall(message)
            except Exception as e:
                print(f'Error broadcasting: {e}')
                remove_connection(client_conn)

def remove_connection(conn: socket.socket) -> None:
    """
    Remove a client from the connections list and close the socket.
    """
    if conn in connections:
        try:
            conn.close()
        finally:
            connections.remove(conn)

def server() -> None:
    """
    Accept client connections and spin a thread per client.
    """
    LISTENING_PORT = 12000
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(('', LISTENING_PORT))
        sock.listen(16)
        print(f'Server running on 0.0.0.0:{LISTENING_PORT} (ciphertext-only).')

        while True:
            client_sock, address = sock.accept()
            connections.append(client_sock)
            threading.Thread(
                target=handle_user_connection,
                args=(client_sock, address),
                daemon=True
            ).start()

    except Exception as e:
        print(f'Server error: {e}')
    finally:
        for c in list(connections):
            remove_connection(c)
        try:
            sock.close()
        except:
            pass

if __name__ == "__main__":
    server()
