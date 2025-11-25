import socket
import threading
import json
import time
import curses
import base64
import hashlib
from datetime import datetime
from textual.app import App, ComposeResult
from textual.containers import Container, VerticalScroll
from textual.widgets import Header, Footer, Static, Input, Button, Label, ListView, ListItem
from textual.screen import Screen
from textual.reactive import reactive
from textual import work

# Suppress curses error on exit with Textual
import sys

# Cryptography Imports
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- Configuration ---
SERVER_IP = 'gus' # tailscale
SERVER_PORT = 9999

class CryptoManager:
    """Handles all client-side encryption logic."""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None
        self.username = None

    def generate_keys(self):
        """Generate a new RSA keypair."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()

    def serialize_pub_key(self):
        """Convert public key to PEM format for server storage."""
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def serialize_priv_key(self, password):
        """Encrypt private key with password and convert to PEM."""
        # Derive a key from password strictly for local encryption
        salt = b'static_salt_for_portability' # In prod, use random salt stored with user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return f.encrypt(pem).decode('utf-8')

    def load_priv_key(self, encrypted_pem, password):
        """Decrypt private key using password."""
        salt = b'static_salt_for_portability'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        f = Fernet(key)
        
        try:
            pem_bytes = f.decrypt(encrypted_pem.encode())
            self.private_key = serialization.load_pem_private_key(
                pem_bytes,
                password=None,
                backend=default_backend()
            )
            self.public_key = self.private_key.public_key()
            return True
        except:
            return False

    def hash_password_for_auth(self, password):
        """Create a hash solely for server authentication (different from encryption key)."""
        return hashlib.sha256(password.encode()).hexdigest()

    def hybrid_encrypt(self, message, recipient_pub_key_pem):
        """
        Encrypts message:
        1. Generate random AES (Fernet) key.
        2. Encrypt message with AES key.
        3. Encrypt AES key with Recipient's RSA Public Key.
        """
        # Load Recipient Pub Key
        recipient_key = serialization.load_pem_public_key(
            recipient_pub_key_pem.encode(),
            backend=default_backend()
        )

        # 1. AES Encrypt Message
        fernet_key = Fernet.generate_key()
        f = Fernet(fernet_key)
        encrypted_message = f.encrypt(message.encode())

        # 2. RSA Encrypt AES Key
        encrypted_key = recipient_key.encrypt(
            fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Package it
        payload = {
            'key': base64.b64encode(encrypted_key).decode('utf-8'),
            'msg': base64.b64encode(encrypted_message).decode('utf-8')
        }
        return json.dumps(payload)

    def hybrid_decrypt(self, payload_json):
        """Decrypts the hybrid package."""
        payload = json.loads(payload_json)
        enc_key = base64.b64decode(payload['key'])
        enc_msg = base64.b64decode(payload['msg'])

        # 1. Decrypt AES Key using My Private Key
        fernet_key = self.private_key.decrypt(
            enc_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Decrypt Message using AES Key
        f = Fernet(fernet_key)
        decrypted_msg = f.decrypt(enc_msg)
        return decrypted_msg.decode('utf-8')

class NetworkClient:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
    def connect(self):
        try:
            self.sock.connect((SERVER_IP, SERVER_PORT))
            return True
        except:
            return False

    def send_request(self, req):
        try:
            self.sock.send(json.dumps(req).encode('utf-8'))
            data = self.sock.recv(16384).decode('utf-8') # Large buffer for keys
            return json.loads(data)
        except Exception as e:
            return {'status': 'error', 'msg': str(e)}

    def close(self):
        self.sock.close()

# --- Textual TUI Logic ---

class MessageArea(VerticalScroll):
    """A widget to display messages."""
    def add_message(self, message: str, sender: str, is_me: bool):
        timestamp = datetime.now().strftime('%H:%M')
        align = "right" if is_me else "left"
        
        # Simple styling
        style = "reverse" if is_me else ""
        sender_display = "Me" if is_me else sender

        msg_widget = Static(f"[{timestamp}] {sender_display}:\n{message}", classes=f"message {align}")
        msg_widget.styles.background = "darkblue" if is_me else "rgb(50,50,50)"
        msg_widget.styles.text_align = align
        msg_widget.styles.width = "80%"
        msg_widget.styles.align_horizontal = align

        self.mount(msg_widget)
        self.scroll_end(animate=True)

class ChatScreen(Screen):
    """The main chat screen after login."""
    
    current_chat_user = reactive(None)

    def __init__(self, net: NetworkClient, crypto: CryptoManager):
        self.net = net
        self.crypto = crypto
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Header(f"Encrypted Messenger - Logged in as {self.crypto.username}")
        with Container(id="app-grid"):
            yield ListView(id="user-list")
            yield MessageArea(id="message-area")
            yield Input(placeholder="Select a user to start chatting", id="message-input", disabled=True)
        yield Footer()

    def on_mount(self) -> None:
        """Fetch users and start polling for messages."""
        self.fetch_users()
        self.set_interval(3, self.poll_messages)

    @work(exclusive=True, thread=True)
    def fetch_users(self):
        """Fetches the list of users from the server."""
        res = self.net.send_request({'cmd': 'GET_USERS'})
        user_list = self.query_one("#user-list", ListView)
        if res and res['status'] == 'success':
            for user in res['users']:
                if user != self.crypto.username: # Don't list self
                    user_list.append(ListItem(Label(user)))

    @work(exclusive=True, thread=True)
    def poll_messages(self):
        """Polls the server for new messages."""
        res = self.net.send_request({'cmd': 'POLL'})
        if res and res['status'] == 'success' and res['messages']:
            message_area = self.query_one(MessageArea)
            for m in res['messages']:
                try:
                    decrypted = self.crypto.hybrid_decrypt(m['content'])
                    # Use call_from_thread to safely update the UI
                    def add_msg():
                        # Only display if it's from the currently active chat
                        if m['from'] == self.current_chat_user:
                            message_area.add_message(decrypted, m['from'], is_me=False)
                    self.app.call_from_thread(add_msg)
                except Exception:
                    self.app.call_from_thread(message_area.add_message, f"[System] Error decrypting message from {m['from']}", "System", is_me=False)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        """Handle user selection from the list."""
        self.current_chat_user = event.item.children[0].renderable
        self.query_one("#message-area", MessageArea).remove_children()
        self.query_one("#message-area", MessageArea).mount(Static(f"Chat with {self.current_chat_user}", classes="system-message"))
        input_widget = self.query_one("#message-input", Input)
        input_widget.placeholder = f"Message {self.current_chat_user}..."
        input_widget.disabled = False
        input_widget.focus()

    @work(exclusive=True)
    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle sending a message."""
        msg_text = event.value
        target = self.current_chat_user
        if not msg_text or not target:
            return

        input_widget = self.query_one("#message-input", Input)
        input_widget.clear()

        # Fetch Key
        key_res = self.net.send_request({'cmd': 'GET_KEY', 'target': target})
        message_area = self.query_one(MessageArea)

        if key_res['status'] == 'success':
            try:
                # Encrypt
                payload = self.crypto.hybrid_encrypt(msg_text, key_res['public_key'])
                # Send
                send_res = self.net.send_request({
                    'cmd': 'SEND',
                    'to': target,
                    'content': payload
                })
                if send_res['status'] == 'success':
                    message_area.add_message(msg_text, self.crypto.username, is_me=True)
                else:
                    message_area.add_message(f"[Error] {send_res.get('msg')}", "System", is_me=False)
            except Exception as e:
                message_area.add_message(f"[Error] Encryption failed: {str(e)}", "System", is_me=False)
        else:
            message_area.add_message(f"[Error] User {target} not found.", "System", is_me=False)

class LoginScreen(Screen):
    """Screen for user login and registration."""

    def __init__(self, net: NetworkClient, crypto: CryptoManager):
        self.net = net
        self.crypto = crypto
        super().__init__()

    def compose(self) -> ComposeResult:
        yield Container(
            Static("E2E Encrypted Messenger", id="title"),
            Label("Username"),
            Input(placeholder="username", id="username"),
            Label("Password"),
            Input(placeholder="password", password=True, id="password"),
            Container(
                Button("Login", variant="primary", id="login"),
                Button("Register", id="register"),
                id="buttons"
            ),
            Static("", id="status"),
            id="login-box"
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle login or registration button presses."""
        username = self.query_one("#username", Input).value
        password = self.query_one("#password", Input).value
        status = self.query_one("#status", Static)

        if not username or not password:
            status.update("Username and password are required.")
            return

        if event.button.id == "login":
            self.do_login(username, password)
        elif event.button.id == "register":
            self.do_register(username, password)

    @work(exclusive=True, thread=True)
    def do_login(self, user, pwd):
        status = self.query_one("#status", Static)
        status.update("Logging in...")
        req = {
            'cmd': 'LOGIN', 'username': user,
            'password_hash': self.crypto.hash_password_for_auth(pwd)
        }
        res = self.net.send_request(req)
        if res['status'] == 'success':
            if self.crypto.load_priv_key(res['enc_private_key'], pwd):
                self.crypto.username = user
                self.app.call_from_thread(self.app.push_screen, ChatScreen(self.net, self.crypto))
            else:
                status.update("Decryption failed! Wrong password for key?")
        else:
            status.update(f"Login failed: {res.get('msg')}")

    @work(exclusive=True, thread=True)
    def do_register(self, user, pwd):
        status = self.query_one("#status", Static)
        status.update("Generating keys (this may take a moment)...")
        self.crypto.generate_keys()
        req = {
            'cmd': 'REGISTER', 'username': user,
            'password_hash': self.crypto.hash_password_for_auth(pwd),
            'public_key': self.crypto.serialize_pub_key(),
            'enc_private_key': self.crypto.serialize_priv_key(pwd)
        }
        res = self.net.send_request(req)
        if res['status'] == 'success':
            status.update("Registration successful! You can now log in.")
        else:
            status.update(f"Error: {res.get('msg')}")

class MessengerApp(App):
    """The main Textual application."""
    CSS_PATH = "client.css"

    def on_mount(self) -> None:
        self.net = NetworkClient()
        self.crypto = CryptoManager()
        if not self.net.connect():
            self.exit("Could not connect to server.")
            return
        self.push_screen(LoginScreen(self.net, self.crypto))

    def on_unmount(self) -> None:
        if hasattr(self, 'net'):
            self.net.close()

if __name__ == '__main__':
    # This is a hack to prevent Textual from showing a traceback on exit
    # when the server is not running.
    try:
        app = MessengerApp()
        app.run()
    except Exception as e:
        print(f"Failed to start: {e}")
        # A clean exit is better than a traceback for the user.
        # The error message from on_mount will be printed.
        sys.exit(0)