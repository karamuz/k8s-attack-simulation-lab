#!/usr/bin/env python3
import http.server
import socketserver
import os
import cgi
from datetime import datetime

PORT = int(os.environ.get("HTTP_PORT", 8080))
UPLOAD_DIR = "/payloads/uploads"
PAYLOAD_DIR = "/payloads"

os.makedirs(UPLOAD_DIR, exist_ok=True)

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=PAYLOAD_DIR, **kwargs)

    def do_GET(self):
        print(f"[{datetime.now()}] GET request received for: {self.path} from {self.client_address[0]}")
        super().do_GET()

    def do_POST(self):
        print(f"[{datetime.now()}] POST request received for: {self.path} from {self.client_address[0]}")
        try:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            if 'file' in form:
                fileitem = form['file']
                if fileitem.filename:
                    filename = f"{timestamp}_{os.path.basename(fileitem.filename)}"
                    filepath = os.path.join(UPLOAD_DIR, filename)
                    with open(filepath, 'wb') as f:
                        f.write(fileitem.file.read())
                    print(f"[{datetime.now()}] File '{filename}' uploaded successfully.")
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"File uploaded successfully")
                else:
                    self.send_response(400)
                    self.end_headers()
                    self.wfile.write(b"No file content in 'file' field.")
            else:
                content_length = int(self.headers.get('Content-Length', 0))
                post_data = self.rfile.read(content_length)
                filename = f"{timestamp}_data.bin"
                filepath = os.path.join(UPLOAD_DIR, filename)
                with open(filepath, 'wb') as f:
                    f.write(post_data)
                print(f"[{datetime.now()}] Raw data saved to '{filename}'.")
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Data received")
        except Exception as e:
            print(f"[{datetime.now()}] Error processing POST request: {e}")
            self.send_response(500)
            self.end_headers()
            self.wfile.write(f"Server error: {e}".encode())

Handler = CustomHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"[{datetime.now()}] Serving HTTP on port {PORT}")
    httpd.serve_forever()