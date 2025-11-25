import socket
import threading
import sqlite3
import json
import time
import os

# --- Configuration ---
HOST = '0.0.0.0'  # Listen on all interfaces
PORT = 9999
DB_NAME = 'secure_chat.db'

def init_db():
    """Initialize the SQLite database with users and messages tables."""
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    # Users: Stores login auth hash and the user's public/encrypted private keys
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, 
                  password_hash TEXT, 
                  public_key TEXT, 
                  enc_private_key TEXT)''')
    
    # Messages: Stores the encrypted blob destined for a specific user
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  from_user TEXT, 
                  to_user TEXT, 
                  encrypted_content TEXT, 
                  timestamp REAL)''')
    conn.commit()
    conn.close()

def handle_client(client_socket, addr):
    """Handle individual client connection."""
    print(f"[+] New connection from {addr}")
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    
    current_user = None

    try:
        while True:
            # Receive data (length-prefixed for stability could be added, 
            # but raw recv 4096 is fine for this control logic)
            data = client_socket.recv(8192).decode('utf-8')
            if not data:
                break

            try:
                request = json.loads(data)
            except json.JSONDecodeError:
                continue

            command = request.get('cmd')
            response = {'status': 'error', 'msg': 'Unknown command'}

            # --- REGISTER ---
            if command == 'REGISTER':
                username = request['username']
                pwd_hash = request['password_hash']
                pub_key = request['public_key']
                priv_key = request['enc_private_key']

                try:
                    c.execute("INSERT INTO users VALUES (?, ?, ?, ?)", 
                              (username, pwd_hash, pub_key, priv_key))
                    conn.commit()
                    response = {'status': 'success', 'msg': 'Account created.'}
                    print(f"[Register] User {username} registered.")
                except sqlite3.IntegrityError:
                    response = {'status': 'error', 'msg': 'Username taken.'}

            # --- LOGIN ---
            elif command == 'LOGIN':
                username = request['username']
                pwd_hash = request['password_hash']
                
                c.execute("SELECT password_hash, enc_private_key FROM users WHERE username=?", (username,))
                row = c.fetchone()
                
                if row and row[0] == pwd_hash:
                    current_user = username
                    response = {
                        'status': 'success', 
                        'msg': 'Logged in.',
                        'enc_private_key': row[1]
                    }
                    print(f"[Login] {username} logged in.")
                else:
                    response = {'status': 'error', 'msg': 'Invalid credentials.'}

            # --- GET PUBLIC KEY (for sending messages) ---
            elif command == 'GET_KEY':
                target_user = request['target']
                c.execute("SELECT public_key FROM users WHERE username=?", (target_user,))
                row = c.fetchone()
                if row:
                    response = {'status': 'success', 'public_key': row[0]}
                else:
                    response = {'status': 'error', 'msg': 'User not found.'}

            # --- SEND MESSAGE ---
            elif command == 'SEND':
                if not current_user:
                    response = {'status': 'error', 'msg': 'Auth required.'}
                else:
                    recipient = request['to']
                    enc_content = request['content'] # This is a JSON string containing aes_key and cipher_text
                    
                    # Verify recipient exists
                    c.execute("SELECT username FROM users WHERE username=?", (recipient,))
                    if c.fetchone():
                        c.execute("INSERT INTO messages (from_user, to_user, encrypted_content, timestamp) VALUES (?, ?, ?, ?)",
                                  (current_user, recipient, enc_content, time.time()))
                        conn.commit()
                        response = {'status': 'success', 'msg': 'Sent.'}
                    else:
                        response = {'status': 'error', 'msg': 'Recipient not found.'}

            # --- POLL MESSAGES ---
            elif command == 'POLL':
                if not current_user:
                    response = {'status': 'error', 'msg': 'Auth required.'}
                else:
                    # Get messages sent TO the current user
                    c.execute("SELECT id, from_user, encrypted_content, timestamp FROM messages WHERE to_user=?", (current_user,))
                    rows = c.fetchall()
                    
                    msgs = []
                    ids_to_delete = []
                    for r in rows:
                        msgs.append({
                            'from': r[1],
                            'content': r[2],
                            'timestamp': r[3]
                        })
                        ids_to_delete.append((r[0],))
                    
                    # Delete fetched messages so they aren't sent again.
                    if ids_to_delete:
                        c.executemany("DELETE FROM messages WHERE id=?", ids_to_delete)
                        conn.commit()

                    response = {'status': 'success', 'messages': msgs}

            # --- GET ALL USERS ---
            elif command == 'GET_USERS':
                c.execute("SELECT username FROM users")
                users = [row[0] for row in c.fetchall()]
                response = {'status': 'success', 'users': users}

            client_socket.send(json.dumps(response).encode('utf-8'))

    except ConnectionResetError:
        pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print(f"[-] Disconnected {addr}")
        conn.close()
        client_socket.close()

def start_server():
    init_db()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[*] Server listening on {HOST}:{PORT}")
    print("[*] Security: Zero-Knowledge (Server stores only encrypted blobs)")

    while True:
        client, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(client, addr))
        thread.start()

if __name__ == '__main__':
    start_server()