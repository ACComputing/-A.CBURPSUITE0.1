import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import ssl
import urllib.parse
import base64
import binascii
import html
import re
from http.server import HTTPServer, BaseHTTPRequestHandler
import queue

class A_C_Burp_Suite_0_1:
    def __init__(self, root):
        self.root = root
        self.root.title("A.C Burp Suite 0.1")
        self.root.geometry("1100x700")
        
        # Interception state
        self.intercept_on = False
        self.proxy_running = False
        self.proxy_server = None
        self.proxy_port = 8080
        self.request_queue = queue.Queue()
        self.pending_request = None
        self.modified_request = None
        
        # History storage
        self.history = []
        self.history_id = 0
        
        self.setup_ui()
        self.setup_styles()
    
    def setup_styles(self):
        style = ttk.Style()
        style.configure("TNotebook", background="#1e1e1e")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#d4d4d4")
        style.configure("TButton", background="#2d2d2d", foreground="#d4d4d4")
        style.map("TButton", background=[("active", "#3e3e3e")])
    
    def setup_ui(self):
        # Main container
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True)
        
        # Control bar
        control_frame = ttk.Frame(main_frame)
        control_frame.pack(fill="x", padx=5, pady=5)
        
        self.proxy_btn = ttk.Button(control_frame, text="▶ Start Proxy", command=self.toggle_proxy)
        self.proxy_btn.pack(side="left", padx=2)
        
        self.intercept_btn = ttk.Button(control_frame, text="● Intercept is off", command=self.toggle_intercept)
        self.intercept_btn.pack(side="left", padx=2)
        
        ttk.Label(control_frame, text="Port:").pack(side="left", padx=(20, 2))
        self.port_var = tk.StringVar(value="8080")
        port_entry = ttk.Entry(control_frame, textvariable=self.port_var, width=6)
        port_entry.pack(side="left", padx=2)
        
        self.clear_btn = ttk.Button(control_frame, text="Clear History", command=self.clear_history)
        self.clear_btn.pack(side="right", padx=2)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Tab 1: Proxy / Intercept
        self.proxy_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.proxy_tab, text="Proxy")
        self.setup_proxy_tab()
        
        # Tab 2: Repeater
        self.repeater_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.repeater_tab, text="Repeater")
        self.setup_repeater_tab()
        
        # Tab 3: Decoder
        self.decoder_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.decoder_tab, text="Decoder")
        self.setup_decoder_tab()
        
        # Tab 4: Logger / History
        self.logger_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logger_tab, text="Logger")
        self.setup_logger_tab()
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready | Proxy stopped")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief="sunken", anchor="w")
        status_bar.pack(fill="x", side="bottom")
    
    def setup_proxy_tab(self):
        # Split pane: left for pending intercept, right for request/response
        paned = ttk.PanedWindow(self.proxy_tab, orient="horizontal")
        paned.pack(fill="both", expand=True)
        
        # Left frame - Intercepted request
        left_frame = ttk.Frame(paned)
        paned.add(left_frame, weight=1)
        
        ttk.Label(left_frame, text="Intercepted Request", font=("Arial", 10, "bold")).pack(anchor="w", pady=5)
        
        self.intercept_text = scrolledtext.ScrolledText(left_frame, wrap=tk.WORD, bg="#1e1e1e", fg="#d4d4d4", 
                                                         insertbackground="white", height=15)
        self.intercept_text.pack(fill="both", expand=True, padx=5)
        
        btn_frame = ttk.Frame(left_frame)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Forward", command=self.forward_request).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Drop", command=self.drop_request).pack(side="left", padx=2)
        
        # Right frame - Modified request / Response
        right_frame = ttk.Frame(paned)
        paned.add(right_frame, weight=1)
        
        ttk.Label(right_frame, text="Edit & Send", font=("Arial", 10, "bold")).pack(anchor="w", pady=5)
        
        self.edit_text = scrolledtext.ScrolledText(right_frame, wrap=tk.WORD, bg="#1e1e1e", fg="#d4d4d4",
                                                    insertbackground="white")
        self.edit_text.pack(fill="both", expand=True, padx=5)
        
        ttk.Button(right_frame, text="Send Modified", command=self.send_modified).pack(pady=5)
    
    def setup_repeater_tab(self):
        # Request section
        req_label = ttk.Label(self.repeater_tab, text="Request", font=("Arial", 10, "bold"))
        req_label.pack(anchor="w", padx=5, pady=(5,0))
        
        self.repeater_request = scrolledtext.ScrolledText(self.repeater_tab, wrap=tk.WORD, bg="#1e1e1e", 
                                                           fg="#d4d4d4", insertbackground="white", height=12)
        self.repeater_request.pack(fill="both", expand=True, padx=5, pady=5)
        self.repeater_request.insert("1.0", "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        
        # Send button
        btn_frame = ttk.Frame(self.repeater_tab)
        btn_frame.pack(fill="x", padx=5)
        ttk.Button(btn_frame, text="▶ Send", command=self.repeater_send).pack(side="left")
        ttk.Button(btn_frame, text="Clear", command=lambda: self.repeater_request.delete("1.0", tk.END)).pack(side="left", padx=5)
        
        # Response section
        resp_label = ttk.Label(self.repeater_tab, text="Response", font=("Arial", 10, "bold"))
        resp_label.pack(anchor="w", padx=5, pady=(10,0))
        
        self.repeater_response = scrolledtext.ScrolledText(self.repeater_tab, wrap=tk.WORD, bg="#1e1e1e", 
                                                            fg="#d4d4d4", state="disabled", height=12)
        self.repeater_response.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_decoder_tab(self):
        input_label = ttk.Label(self.decoder_tab, text="Input", font=("Arial", 10, "bold"))
        input_label.pack(anchor="w", padx=5, pady=(5,0))
        
        self.decoder_input = scrolledtext.ScrolledText(self.decoder_tab, wrap=tk.WORD, bg="#1e1e1e", 
                                                        fg="#d4d4d4", insertbackground="white", height=8)
        self.decoder_input.pack(fill="both", expand=True, padx=5, pady=5)
        
        # Encode/Decode buttons
        btn_frame = ttk.Frame(self.decoder_tab)
        btn_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Button(btn_frame, text="URL Encode", command=lambda: self.decode_op("url_enc")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="URL Decode", command=lambda: self.decode_op("url_dec")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Base64 Encode", command=lambda: self.decode_op("b64_enc")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Base64 Decode", command=lambda: self.decode_op("b64_dec")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="HTML Encode", command=lambda: self.decode_op("html_enc")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="HTML Decode", command=lambda: self.decode_op("html_dec")).pack(side="left", padx=2)
        ttk.Button(btn_frame, text="Hex", command=lambda: self.decode_op("hex")).pack(side="left", padx=2)
        
        output_label = ttk.Label(self.decoder_tab, text="Output", font=("Arial", 10, "bold"))
        output_label.pack(anchor="w", padx=5, pady=(10,0))
        
        self.decoder_output = scrolledtext.ScrolledText(self.decoder_tab, wrap=tk.WORD, bg="#1e1e1e", 
                                                         fg="#d4d4d4", height=8)
        self.decoder_output.pack(fill="both", expand=True, padx=5, pady=5)
    
    def setup_logger_tab(self):
        # Treeview for HTTP history
        columns = ("id", "method", "host", "path", "status", "length")
        self.history_tree = ttk.Treeview(self.logger_tab, columns=columns, show="headings", height=15)
        
        self.history_tree.heading("id", text="#")
        self.history_tree.heading("method", text="Method")
        self.history_tree.heading("host", text="Host")
        self.history_tree.heading("path", text="Path")
        self.history_tree.heading("status", text="Status")
        self.history_tree.heading("length", text="Length")
        
        self.history_tree.column("id", width=50)
        self.history_tree.column("method", width=70)
        self.history_tree.column("host", width=200)
        self.history_tree.column("path", width=300)
        self.history_tree.column("status", width=70)
        self.history_tree.column("length", width=70)
        
        scrollbar = ttk.Scrollbar(self.logger_tab, orient="vertical", command=self.history_tree.yview)
        self.history_tree.configure(yscrollcommand=scrollbar.set)
        
        self.history_tree.pack(side="left", fill="both", expand=True, padx=5, pady=5)
        scrollbar.pack(side="right", fill="y", pady=5)
        
        self.history_tree.bind("<Double-1>", self.on_history_select)
        
        # Detail view
        detail_frame = ttk.Frame(self.logger_tab)
        detail_frame.pack(fill="x", padx=5, pady=5)
        
        self.logger_detail = scrolledtext.ScrolledText(detail_frame, wrap=tk.WORD, bg="#1e1e1e", 
                                                        fg="#d4d4d4", height=8)
        self.logger_detail.pack(fill="both", expand=True)
    
    def toggle_proxy(self):
        if not self.proxy_running:
            try:
                self.proxy_port = int(self.port_var.get())
                self.proxy_server = ProxyServer(self, self.proxy_port)
                self.proxy_thread = threading.Thread(target=self.proxy_server.start, daemon=True)
                self.proxy_thread.start()
                self.proxy_running = True
                self.proxy_btn.config(text="■ Stop Proxy")
                self.status_var.set(f"Proxy running on port {self.proxy_port} | Intercept {'ON' if self.intercept_on else 'OFF'}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to start proxy: {e}")
        else:
            if self.proxy_server:
                self.proxy_server.stop()
            self.proxy_running = False
            self.proxy_btn.config(text="▶ Start Proxy")
            self.status_var.set("Ready | Proxy stopped")
    
    def toggle_intercept(self):
        self.intercept_on = not self.intercept_on
        self.intercept_btn.config(text=f"{'●' if self.intercept_on else '○'} Intercept is {'on' if self.intercept_on else 'off'}")
        self.status_var.set(f"Proxy {'running' if self.proxy_running else 'stopped'} on port {self.proxy_port} | Intercept {'ON' if self.intercept_on else 'OFF'}")
    
    def forward_request(self):
        if self.pending_request:
            modified = self.edit_text.get("1.0", tk.END).strip()
            self.modified_request = modified if modified else None
            self.pending_request["forward"] = True
            self.request_queue.put(self.pending_request)
            self.intercept_text.delete("1.0", tk.END)
            self.edit_text.delete("1.0", tk.END)
            self.pending_request = None
    
    def drop_request(self):
        if self.pending_request:
            self.pending_request["drop"] = True
            self.request_queue.put(self.pending_request)
            self.intercept_text.delete("1.0", tk.END)
            self.edit_text.delete("1.0", tk.END)
            self.pending_request = None
    
    def send_modified(self):
        """Send modified request from intercept tab"""
        if self.pending_request:
            modified = self.edit_text.get("1.0", tk.END).strip()
            if modified:
                self.modified_request = modified
                self.forward_request()
    
    def add_to_history(self, method, host, path, status, length, request_data, response_data):
        self.history_id += 1
        self.history.append({
            "id": self.history_id,
            "method": method,
            "host": host,
            "path": path,
            "status": status,
            "length": length,
            "request": request_data,
            "response": response_data
        })
        
        self.history_tree.insert("", "end", values=(self.history_id, method, host, path[:100], status, length))
        
        if len(self.history) > 1000:
            self.history.pop(0)
            children = self.history_tree.get_children()
            if children:
                self.history_tree.delete(children[0])
    
    def clear_history(self):
        self.history = []
        self.history_id = 0
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.logger_detail.config(state="normal")
        self.logger_detail.delete("1.0", tk.END)
        self.logger_detail.config(state="disabled")
    
    def on_history_select(self, event):
        selection = self.history_tree.selection()
        if selection:
            item = self.history_tree.item(selection[0])
            history_id = item["values"][0]
            
            for entry in self.history:
                if entry["id"] == history_id:
                    self.logger_detail.config(state="normal")
                    self.logger_detail.delete("1.0", tk.END)
                    self.logger_detail.insert("1.0", f"=== REQUEST ===\n{entry['request']}\n\n=== RESPONSE ===\n{entry['response']}")
                    self.logger_detail.config(state="disabled")
                    break
    
    def repeater_send(self):
        request_text = self.repeater_request.get("1.0", tk.END).strip()
        if not request_text:
            return
        
        threading.Thread(target=self._repeater_send_thread, args=(request_text,), daemon=True).start()
    
    def _repeater_send_thread(self, request_text):
        try:
            # Parse request
            lines = request_text.split("\r\n")
            request_line = lines[0]
            method, path, version = request_line.split(" ")
            
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.lower()] = value
            
            host = headers.get("host", "localhost")
            
            body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""
            
            # Make request
            response = self.make_http_request(method, host, path, headers, body)
            
            self.repeater_response.config(state="normal")
            self.repeater_response.delete("1.0", tk.END)
            self.repeater_response.insert("1.0", response)
            self.repeater_response.config(state="disabled")
            
            # Add to history
            status = response.split(" ")[1] if response else "Error"
            self.add_to_history(method, host, path, status, len(response), request_text, response)
            
        except Exception as e:
            self.repeater_response.config(state="normal")
            self.repeater_response.delete("1.0", tk.END)
            self.repeater_response.insert("1.0", f"Error: {str(e)}")
            self.repeater_response.config(state="disabled")
    
    def make_http_request(self, method, host, path, headers, body, use_ssl=False):
        try:
            port = 443 if use_ssl else 80
            if ":" in host:
                host, port_str = host.split(":")
                port = int(port_str)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            if use_ssl:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            
            # Build request
            request = f"{method} {path} HTTP/1.1\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            request += f"Content-Length: {len(body)}\r\n"
            request += "\r\n"
            request += body
            
            sock.send(request.encode())
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            
            return response.decode("utf-8", errors="replace")
            
        except Exception as e:
            return f"HTTP/1.1 500 Internal Error\r\n\r\n{str(e)}"
    
    def decode_op(self, operation):
        input_text = self.decoder_input.get("1.0", tk.END).strip()
        if not input_text:
            return
        
        result = ""
        try:
            if operation == "url_enc":
                result = urllib.parse.quote(input_text)
            elif operation == "url_dec":
                result = urllib.parse.unquote(input_text)
            elif operation == "b64_enc":
                result = base64.b64encode(input_text.encode()).decode()
            elif operation == "b64_dec":
                result = base64.b64decode(input_text).decode("utf-8", errors="replace")
            elif operation == "html_enc":
                result = html.escape(input_text)
            elif operation == "html_dec":
                result = html.unescape(input_text)
            elif operation == "hex":
                result = binascii.hexlify(input_text.encode()).decode()
        except Exception as e:
            result = f"Error: {str(e)}"
        
        self.decoder_output.delete("1.0", tk.END)
        self.decoder_output.insert("1.0", result)


class ProxyHandler(BaseHTTPRequestHandler):
    def do_CONNECT(self):
        """Handle HTTPS CONNECT tunneling"""
        host, port = self.path.split(":")
        port = int(port)
        
        try:
            self.send_response(200, "Connection Established")
            self.end_headers()
            
            # Tunnel the connection
            self.server.app.handle_tunnel(self, host, port)
            
        except Exception as e:
            self.send_error(500, str(e))
    
    def do_GET(self):
        self.handle_request("GET")
    
    def do_POST(self):
        self.handle_request("POST")
    
    def do_PUT(self):
        self.handle_request("PUT")
    
    def do_DELETE(self):
        self.handle_request("DELETE")
    
    def do_HEAD(self):
        self.handle_request("HEAD")
    
    def do_OPTIONS(self):
        self.handle_request("OPTIONS")
    
    def handle_request(self, method):
        app = self.server.app
        host = self.headers.get("Host", "localhost")
        
        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""
        
        # Build raw request
        request = f"{method} {self.path} {self.request_version}\r\n"
        for key, value in self.headers.items():
            request += f"{key}: {value}\r\n"
        request += f"\r\n{body}"
        
        # Check intercept
        if app.intercept_on:
            request_data = {
                "method": method,
                "host": host,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
                "raw": request,
                "forward": False,
                "drop": False,
                "handler": self
            }
            
            app.pending_request = request_data
            app.root.after(0, lambda: app.intercept_text.insert("1.0", request))
            app.root.after(0, lambda: app.edit_text.insert("1.0", request))
            
            # Wait for user action
            result = app.request_queue.get()
            
            if result.get("drop"):
                self.send_error(403, "Request dropped by user")
                return
            
            if app.modified_request:
                # Parse modified request and forward
                self.forward_modified_request(app.modified_request)
                app.modified_request = None
                return
        
        # Forward normally
        response = self.forward_request(method, host, self.path, self.headers, body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(response.encode())
        
        # Log to history
        status = response.split(" ")[1] if response else "200"
        app.add_to_history(method, host, self.path, status, len(response), request, response)
    
    def forward_request(self, method, host, path, headers, body):
        """Forward request to target server"""
        try:
            port = 80
            if ":" in host:
                host, port_str = host.split(":")
                port = int(port_str)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            request = f"{method} {path} HTTP/1.1\r\n"
            for key, value in headers.items():
                request += f"{key}: {value}\r\n"
            request += f"\r\n{body}"
            
            sock.send(request.encode())
            
            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            
            sock.close()
            return response.decode("utf-8", errors="replace")
            
        except Exception as e:
            return f"HTTP/1.1 500 Internal Error\r\n\r\n{str(e)}"
    
    def forward_modified_request(self, modified_raw):
        """Forward a modified request"""
        try:
            lines = modified_raw.split("\r\n")
            request_line = lines[0]
            method, path, version = request_line.split(" ")
            
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == "":
                    body_start = i + 1
                    break
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key.lower()] = value
            
            host = headers.get("host", "localhost")
            body = "\r\n".join(lines[body_start:]) if body_start < len(lines) else ""
            
            response = self.forward_request(method, host, path, headers, body)
            
            self.send_response(200)
            self.end_headers()
            self.wfile.write(response.encode())
            
        except Exception as e:
            self.send_error(500, str(e))
    
    def log_message(self, format, *args):
        pass


class ProxyServer:
    def __init__(self, app, port=8080):
        self.app = app
        self.port = port
        self.server = HTTPServer(("0.0.0.0", port), ProxyHandler)
        self.server.app = app
    
    def start(self):
        self.server.serve_forever()
    
    def stop(self):
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    root = tk.Tk()
    app = A_C_Burp_Suite_0_1(root)
    root.mainloop()