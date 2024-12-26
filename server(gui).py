import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import threading
from scapy.all import sniff, Raw
import scapy.all as scapy
import socket
import os
import mimetypes
import urllib
import csv
import base64

class ModernHTTPServerGUI:

    def __init__(self, root):
        self.root = root
        self.root.title("HTTP Server")

        # Center the window on the screen
        window_width = 900
        window_height = 700
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        position_top = int((screen_height / 2) - (window_height / 2))
        position_right = int((screen_width / 2) - (window_width / 2))
        self.root.geometry(f"{window_width}x{window_height}+{position_right}+{position_top}")
        self.root.configure(bg="#212121")

        self.server_running = False
        self.server_socket = None

        # Style
        self.button_style = {"bg": "#00F798", "fg": "#212121", "font": ("Helvetica", 12, "bold"), "relief": "flat"}
        self.label_style = {"bg": "#212121", "fg": "#FFFFFF", "font": ("Helvetica", 12)}
        self.entry_style = {"bg": "#2C2C2C", "fg": "#FFFFFF", "font": ("Helvetica", 12), "insertbackground": "#FFFFFF"}

        # Input and Buttons Frame
        input_button_frame = tk.Frame(root, bg="#212121")
        input_button_frame.grid(row=0, column=0, columnspan=4, padx=20, pady=20, sticky="n")

        # Port Number Input
        tk.Label(input_button_frame, text="Port Number:", **self.label_style).grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.port_entry = tk.Entry(input_button_frame, **self.entry_style, width=30)
        self.port_entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")

        # Buttons
        button_frame = tk.Frame(root, bg="#212121")
        button_frame.grid(row=1, column=0, columnspan=4, padx=20, pady=10, sticky="ew")
        self.start_button = tk.Button(button_frame, text="Start Server", command=self.start_server, **self.button_style, width=15)
        self.start_button.grid(row=1, column=0, padx=10, pady=10)

        self.stop_button = tk.Button(button_frame, text="Stop Server", command=self.stop_server, state="disabled", **self.button_style, width=15)
        self.stop_button.grid(row=1, column=1, padx=10, pady=10)

        self.add_file_button = tk.Button(button_frame, text="Add File", command=self.add_file_to_server, **self.button_style, width=15)
        self.add_file_button.grid(row=1, column=2, padx=10, pady=10)

        self.toggle_button = tk.Button(button_frame, text="Hide Output", command=self.toggle_output, **self.button_style, width=15)
        self.toggle_button.grid(row=1, column=3, padx=10, pady=10)

        self.log_toggle_button = tk.Button(button_frame, text="Hide Logs", command=self.toggle_logs, **self.button_style, width=15)
        self.log_toggle_button.grid(row=1, column=4, padx=10, pady=10)

        button_frame.grid_columnconfigure(0, weight=1)  # Add weight to center align
        button_frame.grid_columnconfigure(1, weight=1)  # Add weight to center align
        button_frame.grid_columnconfigure(2, weight=1)  # Add weight to center align
        button_frame.grid_columnconfigure(3, weight=1)  # Add weight to center align
        button_frame.grid_columnconfigure(4, weight=1)  # Add weight to center align
        button_frame.grid_columnconfigure(5, weight=1)
        # Output Box
        self.output_frame = tk.LabelFrame(root, text="Server Output", bg="#212121", fg="#FFFFFF", font=("Helvetica", 12, "bold"))
        self.output_frame.grid(row=2, column=0, columnspan=4, padx=20, pady=10, sticky="nsew")

        self.output_text = scrolledtext.ScrolledText(self.output_frame, wrap="word", bg="#2C2C2C", fg="#FFFFFF",
                                                     font=("Consolas", 12), state="disabled", insertbackground="#FFFFFF")
        self.output_text.pack(fill="both", expand=True)

        # Backend Log Box 
        self.backend_frame = tk.LabelFrame(root, text="Backend Logs", bg="#212121", fg="#FFFFFF", font=("Helvetica", 12, "bold"))
        self.backend_frame.grid(row=3, column=0, columnspan=4, padx=20, pady=10, sticky="nsew")

        self.backend_text = scrolledtext.ScrolledText(self.backend_frame, wrap="word", bg="#2C2C2C", fg="#FFFFFF",
                                                      font=("Consolas", 10), state="disabled", height=18, insertbackground="#FFFFFF")
        self.backend_text.pack(fill="both", expand=True)

        # Grid configuration
        self.root.grid_rowconfigure(2, weight=1)  # More weight for output
        self.root.grid_rowconfigure(3, weight=1)  # Less weight for backend logs
        self.root.grid_columnconfigure(0, weight=1)

        # Visibility flags
        self.output_visible = True
        self.logs_visible = True


    def toggle_output(self):
        if self.output_visible:
            self.output_frame.grid_remove()
            self.toggle_button.config(text="Show Output")
        else:
            self.output_frame.grid()
            self.toggle_button.config(text="Hide Output")
        self.output_visible = not self.output_visible

    def add_file_to_server(self):
        file_path = filedialog.askopenfilename(title="Select a file to upload")
        if file_path:
            try:
                server_directory = "./uploads"  # Directory to store files
                os.makedirs(server_directory, exist_ok=True)

                file_name = os.path.basename(file_path)
                destination_path = os.path.join(server_directory, file_name)
                
                with open(file_path, 'rb') as source_file:
                    with open(destination_path, 'wb') as dest_file:
                        dest_file.write(source_file.read())

                self.log_message(f"File '{file_name}' added to the server directory.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to add file: {e}")
        else:
            self.log_message("File selection was cancelled.")


    def toggle_logs(self):
        if self.logs_visible:
            self.backend_frame.grid_remove()
            self.log_toggle_button.config(text="Show Logs")
        else:
            self.backend_frame.grid()
            self.log_toggle_button.config(text="Hide Logs")
        self.logs_visible = not self.logs_visible


    def log_message(self, message):
        self.output_text.configure(state="normal")
        self.output_text.insert("end", message + "\n")
        self.output_text.configure(state="disabled")
        self.output_text.see("end")

    def backend_log_message(self, message):
        self.backend_text.configure(state="normal")
        self.backend_text.insert("end", message + "\n")
        self.backend_text.configure(state="disabled")
        self.backend_text.see("end")

    def start_server(self):
        if self.server_running:
            messagebox.showwarning("Warning", "Server is already running!")
            return
        
        port = self.port_entry.get()
        if not port.isdigit():
            messagebox.showerror("Error", "Invalid port number!")
            return

        self.server_running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

        self.log_message(f"Server started on port {port}.")
        threading.Thread(target=self.run_server, args=("127.0.0.1", int(port)), daemon=True).start()

    def stop_server(self):
        if not self.server_running:
            messagebox.showwarning("Warning", "Server is not running!")
            return

        self.server_running = False
        if self.server_socket:
            self.server_socket.close()
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.log_message("Server stopped.")

    # Main function to run the HTTP server and capture packets
    def run_server(self, host='127.0.0.1', port=8080):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((host, port))
            self.server_socket.listen(5)
            self.log_message(f"Server listening on {host}:{port}...")
            self.backend_log_message("Server socket created successfully.")
            
            # Start sniffing in a separate thread
            sniff_thread = threading.Thread(target=self.sniff_packets, args=(port,))
            sniff_thread.daemon = True  # Ensures the thread terminates with the main program
            sniff_thread.start()
            self.backend_log_message("Packet sniffing thread started.")

            while self.server_running:
                try:
                    # Accept incoming connections
                    client_socket, client_address = self.server_socket.accept()
                    self.log_message(f"Connection established from {client_address}.")
                    self.backend_log_message(f"Handling connection from {client_address}.")

                    # Handle the client in a separate thread
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    self.backend_log_message(f"Error handling client connection: {e}")
                    break
        except Exception as e:
            self.log_message(f"Error starting server: {e}")
            self.backend_log_message(f"Server error: {e}")
        finally:
            # Cleanup server socket
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            self.server_running = False
            self.log_message("Server stopped.")
            self.backend_log_message("Server socket closed.")

    # Function to handle sniffing of network packets
    def sniff_packets(self, port):
        try:
            def packet_callback(packet):
                if packet.haslayer(scapy.Raw):
                    self.backend_log_message("(sniff_packets): Packet has Raw layer.")
                    self.log_packet_info(packet)

            self.backend_log_message("(sniff_packets): Starting packet sniffing...")
            scapy.sniff(
                prn=packet_callback, 
                store=0, 
                filter=f'tcp port {port}', 
                iface="Software Loopback Interface 1"  # Change to the correct interface if needed
            )
        except Exception as e:
            self.backend_log_message(f"(sniff_packets): Error during sniffing: {e}")

    def validate_auth(self, headers):
        auth_header = headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Basic "):
            self.backend_log_message("(validate_auth): Missing or invalid Authorization header.")
            return False, None

        # Decode the Base64 encoded credentials
        try:
            encoded_credentials = auth_header.split("Basic ")[1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('utf-8')
            username, password = decoded_credentials.split(":", 1)
        except Exception as e:
            self.backend_log_message(f"(validate_auth): Error decoding credentials: {e}")
            return False, None

        # Validate against the users.csv file
        try:
            with open("./users.csv", "r") as file:
                csv_reader = csv.DictReader(file)
                for row in csv_reader:
                    if row["username"] == username and row["password"] == password:
                        self.backend_log_message(f"(validate_auth): User '{username}' authenticated successfully.")
                        return True, row["role"]  # Return role for authorization purposes
        except FileNotFoundError:
            self.backend_log_message("(validate_auth): users.csv file not found.")
            return False, None
        except Exception as e:
            self.backend_log_message(f"(validate_auth): Error reading users.csv: {e}")
            return False, None

        self.backend_log_message(f"(validate_auth): Authentication failed for user '{username}'.")
        return False, None


    def handle_client(self, client_socket):
        try:
            request = self.receive_request(client_socket)
            if request:
                self.backend_log_message(f"(handle_client): Received request: {request}")
                response = self.generate_response(request)
                client_socket.send(response)
                self.backend_log_message("(handle_client): Response sent.")
        except Exception as e:
            self.backend_log_message(f"(handle_client): Error handling client: {e}")
        finally:
            client_socket.close()
            self.backend_log_message("(handle_client): Client connection closed.")

    def receive_request(self, client_socket):
        request = b""
        while True:
            data = client_socket.recv(1024)
            if not data:
                break
            request += data
            if b"\r\n\r\n" in request:
                break
        return request.decode("utf-8", errors="ignore")

    # Helper function to serve static files
        
    def serve_static_file(self, filepath):
        if not os.path.exists(filepath):
            # Log and notify about missing file
            self.backend_log_message(f"(serve_static_file): File not found: {filepath} -> HTTP/1.1 404 Not Found")
            return (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode('utf-8')  # 404 response in bytes

        try:
            with open(filepath, 'rb') as file:
                body = file.read()
                content_type, _ = mimetypes.guess_type(filepath)
                if content_type is None:
                    self.backend_log_message(f"(serve_static_file): Unable to determine content type for {filepath}. Using default 'application/octet-stream'.")
                    content_type = 'application/octet-stream'

                response = (
                    "HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode('utf-8')
                self.backend_log_message(f"(serve_static_file): Successfully served file: {filepath} -> HTTP/1.1 200 OK.")
                return response + body  # Return headers and file content as bytes
        except Exception as e:
            self.backend_log_message(f"(serve_static_file): Error while serving file {filepath}: {e}")
            return (
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode('utf-8')  # 500 response in case of an error

    
    
    # Log the packet information at each layer dynamically

    def log_packet_info(self, packet):
        print("\n--- Dynamic Packet Analysis ---")
        self.log_message("\n--- Dynamic Packet Analysis ---")

        # Layer 7: Application Layer (HTTP Request and Response)
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load.decode(errors="ignore")
            print("\n[Application Layer] HTTP Data:")
            self.log_message("\n[Application Layer] HTTP Data:")
            print(raw_data)
            self.log_message(raw_data)

        # Layer 4: Transport Layer (TCP Details)
        if packet.haslayer(scapy.TCP):
            print("\n[Transport Layer] TCP Connection Info:")
            self.log_message("\n[Transport Layer] TCP Connection Info:")
            tcp_layer = packet[scapy.TCP]
            print(f"Source Port: {tcp_layer.sport}")
            self.log_message(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            self.log_message(f"Destination Port: {tcp_layer.dport}")
            print(f"Sequence Number: {tcp_layer.seq}")
            self.log_message(f"Sequence Number: {tcp_layer.seq}")
            print(f"Acknowledgment Number: {tcp_layer.ack}")
            self.log_message(f"Acknowledgment Number: {tcp_layer.ack}")
            print(f"Flags: {tcp_layer.flags}")
            self.log_message(f"Flags: {tcp_layer.flags}")
            print(f"Window Size: {tcp_layer.window}")
            self.log_message(f"Window Size: {tcp_layer.window}")
            print(f"Checksum: {tcp_layer.chksum}")
            self.log_message(f"Checksum: {tcp_layer.chksum}")

        # Layer 3: Network Layer (IP Information)
        if packet.haslayer(scapy.IP):
            print("\n[Network Layer] IP Information:")
            self.log_message("\n[Network Layer] IP Information:")
            ip_layer = packet[scapy.IP]
            print(f"Source IP: {ip_layer.src}")
            self.log_message(f"Source IP: {ip_layer.src}")
            print(f"Destination IP: {ip_layer.dst}")
            self.log_message(f"Destination IP: {ip_layer.dst}")
            print(f"Protocol: {ip_layer.proto}")
            self.log_message(f"Protocol: {ip_layer.proto}")
            print(f"Total Length: {len(packet)} bytes")
            self.log_message(f"Total Length: {len(packet)} bytes")

        # Layer 2: Data Link Layer (Ethernet Info)
        if packet.haslayer(scapy.Ether):
            print("\n[Data Link Layer] Ethernet Frame Info:")
            self.log_message("\n[Data Link Layer] Ethernet Frame Info:")
            ether_layer = packet[scapy.Ether]
            print(f"Source MAC: {ether_layer.src}")
            self.log_message(f"Source MAC: {ether_layer.src}")
            print(f"Destination MAC: {ether_layer.dst}")
            self.log_message(f"Destination MAC: {ether_layer.dst}")
            print(f"Ethernet Type: {hex(ether_layer.type)}")
            self.log_message(f"Ethernet Type: {hex(ether_layer.type)}")

        # Additional Layer 1: Physical Layer (Wi-Fi Information)
        if packet.haslayer(scapy.Dot11):
            print("\n[Physical Layer] Wi-Fi Info:")
            self.log_message("\n[Physical Layer] Wi-Fi Info:")
            if packet.haslayer(scapy.Dot11Radiotap):
                rssi = packet[scapy.Dot11Radiotap].dBm_AntSignal
                print(f"Signal Strength (RSSI): {rssi} dBm")
                self.log_message(f"Signal Strength (RSSI): {rssi} dBm")
            if hasattr(packet[scapy.Dot11], 'channel'):
                channel = getattr(packet[scapy.Dot11], 'channel', 'Unknown')
                print(f"Channel Frequency: {channel} MHz")
                self.log_message(f"Channel Frequency: {channel} MHz")

        print("\n--- End of Packet Analysis ---\n")
        self.log_message("\n--- End of Packet Analysis ---\n")


    def parse_multipart_form_data(self, body, boundary):
        # Decode body if in bytes format
        if isinstance(body, bytes):
            self.backend_log_message(f"(parse_multipart_form_data): Decoding body from bytes to string.")
            body = body.decode('utf-8', errors="ignore")

        # Ensure boundary format includes "--"
        boundary = f'--{boundary}'

        # Split the body into parts using the boundary
        parts = body.split(boundary)
        files = {}

        # Process each part
        for part in parts:
            if "Content-Disposition" in part:
                try:
                    # Extract filename and field details from Content-Disposition
                    disposition = part.split("Content-Disposition: ")[1].split("\r\n")[0]
                    filename = None
                    if 'filename=' in disposition:
                        filename = disposition.split('filename="')[1].split('"')[0]
                        self.backend_log_message(f"(parse_multipart_form_data): Found filename: {filename}")

                    if filename:
                        # Extract file data after headers
                        file_data = part.split("\r\n\r\n", 1)[1].rsplit("\r\n", 1)[0]
                        files["file"] = (filename, file_data.encode('utf-8'))  # Save as bytes
                        self.backend_log_message(f"(parse_multipart_form_data): File '{filename}' extracted and saved.")
                except Exception as e:
                    self.backend_log_message(f"(parse_multipart_form_data): Error processing part: {e}")

        return files


    def serve_file(self, file_name):
        file_path = os.path.join('uploads', file_name)
        if not os.path.exists(file_path):
            self.backend_log_message(f"(serve_file): File not found: {file_path}")
            return (
                "HTTP/1.1 404 Not Found\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode('utf-8')

        try:
            with open(file_path, 'rb') as file:
                body = file.read()
                content_type, _ = mimetypes.guess_type(file_path)
                content_type = content_type or 'application/octet-stream'

                response = (
                    "HTTP/1.1 200 OK\r\n"
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {len(body)}\r\n\r\n"
                ).encode('utf-8')
                self.backend_log_message(f"(serve_file): Serving file '{file_path}' with HTTP 200 OK.")
                return response + body
        except Exception as e:
            self.backend_log_message(f"(serve_file): Error serving file '{file_name}': {e}")
            return (
                "HTTP/1.1 500 Internal Server Error\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: 0\r\n\r\n"
            ).encode('utf-8')

    def check_permissions(self, user, resource, method):
        # Example logic: Adjust this to your actual permission model
        permissions = {
            "user": {"GET": ["/*"]},
            "admin": {"GET": ["/*"], "POST": ["/*"], "PUT": ["/*"], "DELETE": ["/*"]}
        }
        user_permissions = permissions.get(user, {})
        allowed_resources = user_permissions.get(method, [])
        return resource in allowed_resources or "/*" in allowed_resources


    def receive_request(self, client_socket):
        request = ""
        try:
            while True:
                data = client_socket.recv(1024)
                if not data:
                    self.backend_log_message(f"(receive_request): No more data received. Ending reception.")
                    break
                request += data.decode("utf-8", errors="ignore")
                self.backend_log_message(f"(receive_request): Partial request received: {data.decode('utf-8', errors='ignore')}")
                if "\r\n\r\n" in request:  # End of headers detected
                    self.backend_log_message(f"(receive_request): Headers end detected.")
                    break
            self.backend_log_message(f"(receive_request): Full request received: {request}")
        except Exception as e:
            self.backend_log_message(f"(receive_request): Error receiving request: {e}")
        return request

        
    # Function to handle HTTP requests and generate appropriate responses
    def generate_response(self, request):
        try:
            # Parse the request line
            lines = request.split('\r\n')
            request_line = lines[0]
            parts = request_line.split(' ', 2)
            
            if len(parts) != 3:
                self.log_message("Invalid request line")
                self.backend_log_message("(Generate Response): Invalid request line. Returning 400 Bad Request.")
                return self.build_response(400, "Bad Request")

            method, path, _ = parts
            url_parts = urllib.parse.urlparse(path)
            query_params = urllib.parse.parse_qs(url_parts.query)
            path = url_parts.path
            headers = {}
            for line in lines[1:]:
                if ": " in line:
                    key, value = line.split(": ", 1)
                    headers[key] = value
            if method in ["POST", "PUT", "DELETE"]:
                is_authenticated, role = self.validate_auth(headers)
                if not is_authenticated:
                    self.backend_log_message("(generate_response): Authentication failed.")
                    return self.build_response(401, "Unauthorized", "text/plain")
                
                if not self.check_permissions(role, path, method):
                    self.backend_log_message("(generate_response): Authorization failed.")
                    return self.build_response(403, "Forbidden", "text/plain")
            # Handle GET requests
            if method == "GET":
                if path.startswith('/download'):
                    file_name = query_params.get('file', [None])[0]
                    print(file_name)
                    if file_name:
                        return self.serve_file(file_name)
                    self.backend_log_message("(Generate Response): File not found for GET request.")
                    return self.build_response(404, "Not Found")
                file_name = query_params.get('file', [None])[0]
                if file_name:
                    file_path = os.path.join('./data', file_name)
                    if os.path.isfile(file_path):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        return self.build_response(200, content)
                    self.backend_log_message(f"(Generate Response): File {file_name} not found. Returning 404 Not Found.")
                    return self.build_response(404, "File Not Found")
                if path == '/':
                    return self.serve_static_file('./index.html')
                if os.path.isfile('.' + path):
                    return self.serve_static_file('.' + path)
                self.backend_log_message("(Generate Response): No file specified. Returning 400 Bad Request.")
                return self.build_response(400, "Bad Request")

            # Handle POST requests
            elif method == "POST":
                if path == '/upload':
                    content_type = next((line.split(":")[1].strip() for line in lines if line.lower().startswith("content-type")), None)
                    if content_type and "multipart/form-data" in content_type:
                        boundary = content_type.split('boundary=')[1]
                        body = request.split("\r\n\r\n", 1)[1]
                        files = self.parse_multipart_form_data(body, boundary)
                        if files:
                            file_name, file_data = files.get("file", (None, None))
                            if file_name:
                                with open(f'./uploads/{file_name}', 'wb') as f:
                                    f.write(file_data)
                                self.backend_log_message(f"File {file_name} uploaded successfully.")
                                return self.build_response(200, "OK")
                file_name = query_params.get('file', [None])[0]
                if file_name:
                    content_length = int(next((line.split(":")[1].strip() for line in lines if line.startswith("Content-Length")), 0))
                    body = request[-content_length:]
                    file_path = os.path.join('./data', file_name)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(body)
                    self.backend_log_message(f"(Generate Response): File {file_name} created/updated successfully.")
                    return self.build_response(200, f"File {file_name} saved successfully")
                self.backend_log_message("(Generate Response): Invalid or missing form data for POST request.")
                return self.build_response(400, "Bad Request")

            # Handle PUT requests
            elif method == "PUT":
                file_name = query_params.get('file', [None])[0]
                if file_name:
                    content_length = int(next((line.split(":")[1].strip() for line in lines if line.startswith("Content-Length")), 0))
                    body = request[-content_length:]
                    file_path = os.path.join('./data', file_name)
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(body)
                    self.backend_log_message(f"(Generate Response): File {file_name} updated successfully.")
                    return self.build_response(200, f"PUT data updated in {file_path}")
                self.backend_log_message("(Generate Response): Missing file name. Returning 400 Bad Request.")
                return self.build_response(400, "Bad Request")

            # Handle DELETE requests
            elif method == "DELETE":
                file_name = query_params.get('file', [None])[0]
                if file_name:
                    file_path = os.path.join('./data', file_name)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        self.backend_log_message(f"(Generate Response): File {file_name} deleted successfully.")
                        return self.build_response(200, "DELETE request successful")
                    self.backend_log_message("(Generate Response): File not found. Returning 404 Not Found.")
                    return self.build_response(404, "Not Found")

            # Handle OPTIONS requests
            elif method == "OPTIONS":
                self.backend_log_message("(Generate Response): Returning allowed methods for OPTIONS request.")
                return self.build_response(200, "Allowed Methods: GET, POST, PUT, DELETE")

            # Method not allowed
            self.backend_log_message(f"(Generate Response): Method {method} not allowed. Returning 405 Method Not Allowed.")
            return self.build_response(405, "Method Not Allowed")

        except Exception as e:
            self.backend_log_message(f"(Generate Response): Error occurred: {e}")
            return self.build_response(500, "Internal Server Error")

    # Helper function to build HTTP responses
    def build_response(self, status_code, body, content_type="text/html"):
        status_messages = {
            200: "OK",
            400: "Bad Request",
            404: "Not Found",
            405: "Method Not Allowed",
            401: "Unauthorized",
            403: "Forbidden",
            500: "Internal Server Error"
        }
        status_message = status_messages.get(status_code, "Error")
        body = body.encode('utf-8')
        return f"HTTP/1.1 {status_code} {status_message}\r\n" \
            f"Content-Type: {content_type}\r\n" \
            f"Content-Length: {len(body)}\r\n\r\n".encode('utf-8') + body



if __name__ == "__main__":
    root = tk.Tk()
    app = ModernHTTPServerGUI(root)
    root.mainloop()
