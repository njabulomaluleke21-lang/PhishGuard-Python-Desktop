"""PhishGuard local web application using only the Python standard library."""
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import csv, json
from urllib.parse import urlparse
from detector import analyse_email

BASE_DIR = Path(__file__).resolve().parent
HISTORY_FILE = BASE_DIR / "scan_history.csv"
HOST, PORT = "127.0.0.1", 5000

def save_history(email_text, result):
    new_file = not HISTORY_FILE.exists()
    with HISTORY_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        if new_file: writer.writerow(["date_time", "email_excerpt", "score", "risk"])
        writer.writerow([datetime.now().isoformat(timespec="seconds"), " ".join(email_text.split())[:120], result["score"], result["risk"]])

def read_history():
    if not HISTORY_FILE.exists(): return []
    with HISTORY_FILE.open("r", newline="", encoding="utf-8") as file:
        return list(csv.DictReader(file))[-8:][::-1]

class PhishGuardHandler(BaseHTTPRequestHandler):
    def send_bytes(self, status, content, content_type):
        body = content if isinstance(content, bytes) else content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, status, data):
        self.send_bytes(status, json.dumps(data).encode("utf-8"), "application/json; charset=utf-8")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/": self.send_bytes(200, (BASE_DIR / "index.html").read_bytes(), "text/html; charset=utf-8")
        elif path == "/style.css": self.send_bytes(200, (BASE_DIR / "style.css").read_bytes(), "text/css; charset=utf-8")
        elif path == "/api/history": self.send_json(200, {"history": read_history()})
        else: self.send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 25000:
                self.send_json(413, {"error": "Request is too large. Limit is 20,000 characters."})
                return
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError):
            self.send_json(400, {"error": "Invalid request."})
            return
        if path == "/api/analyse":
            email_text = str(payload.get("email_text", ""))
            if not email_text.strip():
                self.send_json(400, {"error": "Paste an email message before analysing it."})
                return
            if len(email_text) > 20000:
                self.send_json(413, {"error": "Please limit the email text to 20,000 characters."})
                return
            result = analyse_email(email_text)
            save_history(email_text, result)
            self.send_json(200, {"result": result, "history": read_history()})
        elif path == "/api/clear-history":
            if HISTORY_FILE.exists(): HISTORY_FILE.unlink()
            self.send_json(200, {"message": "Local scan history cleared.", "history": []})
        else: self.send_json(404, {"error": "Not found"})

    def log_message(self, format, *args):
        print("[PhishGuard] " + (format % args))

if __name__ == "__main__":
    server = ThreadingHTTPServer((HOST, PORT), PhishGuardHandler)
    print(f"PhishGuard is running at http://{HOST}:{PORT}")
    print("Press Ctrl+C to stop the local server.")
    try: server.serve_forever()
    except KeyboardInterrupt: print("\nShutting down PhishGuard...")
    finally: server.server_close()
