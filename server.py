import socket
import scapy.all as scapy
import mimetypes
import os
import threading
import urllib

# Helper function to serve static files
def serve_static_file(filepath):
    if not os.path.exists(filepath):
        return "HTTP/1.1 404 Not Found\r\n" \
               "Content-Type: text/html\r\n" \
               "Content-Length: 0\r\n\r\n".encode('utf-8')  # Ensure 404 response is in bytes

    with open(filepath, 'rb') as file:
        body = file.read()
        content_type, _ = mimetypes.guess_type(filepath)
        if content_type is None:
            content_type = 'application/octet-stream'

        response = "HTTP/1.1 200 OK\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "\r\n"
        return response.encode('utf-8') + body  # Return both headers and body as bytes

# Log the packet information at each layer dynamically
def log_packet_info(packet):
    print("\n--- Dynamic Packet Analysis ---")

    # Layer 7: Application Layer (HTTP Request and Response)
    if packet.haslayer(scapy.Raw):
        # Layer 7: HTTP Request/Response (Based on Raw Payload)
        raw_data = packet[scapy.Raw].load.decode(errors="ignore")
        print(f"\n[Application Layer] HTTP Data:")
        print(raw_data)  # Printing the raw HTTP request or response content

    # Layer 4: Transport Layer (TCP Details)
    if packet.haslayer(scapy.TCP):
        print(f"\n[Transport Layer] TCP Connection Info:")
        print(f"Source Port: {packet[scapy.TCP].sport}")
        print(f"Destination Port: {packet[scapy.TCP].dport}")
        print(f"Sequence Number: {packet[scapy.TCP].seq}")
        print(f"Acknowledgment Number: {packet[scapy.TCP].ack}")
        print(f"Flags: {packet[scapy.TCP].flags}")
        print(f"Window Size: {packet[scapy.TCP].window}")
        print(f"Checksum: {packet[scapy.TCP].chksum}")

    # Layer 3: Network Layer (IP Information)
    if packet.haslayer(scapy.IP):
        print(f"\n[Network Layer] IP Information:")
        print(f"Source IP: {packet[scapy.IP].src}")
        print(f"Destination IP: {packet[scapy.IP].dst}")
        print(f"Protocol: {packet[scapy.IP].proto}")
        print(f"Total Length: {len(packet)} bytes")

    # Layer 2: Data Link Layer (Ethernet Info)
    if packet.haslayer(scapy.Ether):
        print(f"\n[Data Link Layer] Ethernet Frame Info:")
        print(f"Source MAC: {packet[scapy.Ether].src}")
        print(f"Destination MAC: {packet[scapy.Ether].dst}")
        print(f"Ethernet Type: {hex(packet[scapy.Ether].type)}")

    # Additional Physical Layer Information (Wi-Fi related)
    if packet.haslayer(scapy.Dot11):
        print(f"\n[Physical Layer] Wi-Fi Info:")
        # Get signal strength (RSSI)
        if packet.haslayer(scapy.Dot11Radiotap):
            rssi = packet[scapy.Dot11Radiotap].dBm_AntSignal
            print(f"Signal Strength (RSSI): {rssi} dBm")
        
        # Get channel frequency
        if packet.haslayer(scapy.Dot11):
            channel = packet[scapy.Dot11].channel
            print(f"Channel Frequency: {channel} MHz")

    print("\n--- End of Packet Analysis ---\n")

def parse_multipart_form_data(body, boundary):
    # Check if body is bytes, and decode it if necessary
    if isinstance(body, bytes):
        body = body.decode('utf-8', errors="ignore")  # Decode bytes to string if it's in bytes format

    # Boundary needs to be in correct format (including "--")
    boundary = '--' + boundary  # boundary remains as string

    # Split body into parts based on the boundary
    parts = body.split(boundary)

    files = {}

    for part in parts:
        if "Content-Disposition" in part:
            # Split content-disposition and extract filename if available
            disposition = part.split("Content-Disposition: ")[1].split("\r\n")[0]
            filename = None
            if 'filename' in disposition:
                filename = disposition.split('filename="')[1].split('"')[0]  # extract the filename
                
            if filename:
                # The file data is after "\r\n\r\n", and before the next boundary
                file_data = part.split("\r\n\r\n", 1)[1].split("\r\n--")[0]  # Extract file content
                files["file"] = (filename, file_data.encode('utf-8'))  # Save file data as bytes

    return files



def serve_file(file_name):
    file_path = os.path.join('uploads', file_name)
    if not os.path.exists(file_path):
        return "HTTP/1.1 404 Not Found\r\n" \
               "Content-Type: text/html\r\n" \
               "Content-Length: 0\r\n\r\n".encode('utf-8')

    with open(file_path, 'rb') as file:
        body = file.read()
        content_type, _ = mimetypes.guess_type(file_path)
        if content_type is None:
            content_type = 'application/octet-stream'

        response = "HTTP/1.1 200 OK\r\n"
        response += f"Content-Type: {content_type}\r\n"
        response += f"Content-Length: {len(body)}\r\n"
        response += "\r\n"
        return response.encode('utf-8') + body
def receive_request(client_socket):
    request = ""
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        request += data.decode("utf-8", errors="ignore")
        # If the request contains a blank line (indicating the end of headers), break out
        if "\r\n\r\n" in request:
            break
    return request


# Function to handle HTTP request (serve static files)
def generate_response(request):
    # Parse request method and path
    lines = request.split('\r\n')
    request_line = lines[0]
    
    parts = request_line.split(' ', 2)
    if len(parts) != 3:
        print(f"Invalid request line: {request_line}")
        return "HTTP/1.1 400 Bad Request\r\n" \
               "Content-Type: text/html\r\n" \
               "Content-Length: 0\r\n\r\n".encode('utf-8')
    
    method, path, _ = parts
    response = ""
    if path == '/':
        return serve_static_file('./index.html')
    if os.path.isfile('.' + path):
        return serve_static_file('.' + path)
    
    if path.startswith("/files"):
            file_path = '.' + path
            return serve_static_file(file_path)

    # Parse the query parameters (if any)
    url_parts = urllib.parse.urlparse(path)
    query_params = urllib.parse.parse_qs(url_parts.query)


    if method == "GET":
        if path.startswith('/download'):
            query_string = path.split('?', 1)[-1]
            params = urllib.parse.parse_qs(query_string)  
            file_name = params.get('file', [None])[0]
            if file_name:
                return serve_file(file_name)
        # Handle GET with query params to retrieve a file
        file_name = query_params.get("file", [None])[0]
        if file_name:
            file_path = os.path.join('./data', file_name)
            if os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_data = f.read()
                response = f"HTTP/1.1 200 OK\r\n" \
                           f"Content-Type: text/html\r\n" \
                           f"Content-Length: {len(file_data)}\r\n\r\n" \
                           f"{file_data.decode('utf-8', 'ignore')}".encode('utf-8')
            else:
                response = "HTTP/1.1 404 Not Found\r\n" \
                           "Content-Type: text/html\r\n" \
                           "Content-Length: 0\r\n\r\n".encode('utf-8')
        else:
            response = "HTTP/1.1 400 Bad Request\r\n" \
                       "Content-Type: text/html\r\n" \
                       "Content-Length: 0\r\n\r\n".encode('utf-8')

    elif method == "POST":
        if path == '/upload':
            content_type = None
            for line in lines:
                if line.lower().startswith("content-type"):
                    content_type = line.split(":")[1].strip()
                    break
            if content_type and "multipart/form-data" in content_type:
                # Process the file upload
                boundary = content_type.split('boundary=')[1]
                body = request.split("\r\n\r\n", 1)[1]  # Get the body of the request after headers
                print('body',body)
                files = parse_multipart_form_data(body, boundary)
                print('files',files)
                if files:
                    file_name, file_data = files.get("file", (None, None))
                    if file_name:
                        with open(f'./uploads/{file_name}', 'wb') as f:
                            f.write(file_data)
                        return "HTTP/1.1 200 OK\r\n" \
                                   "Content-Type: text/html\r\n" \
                                   "Content-Length: 0\r\n\r\n".encode('utf-8')
                    else:
                        return "HTTP/1.1 400 Bad Request\r\n" \
                                   "Content-Type: text/html\r\n" \
                                   "Content-Length: 0\r\n\r\n".encode('utf-8')
                else:
                    return "HTTP/1.1 400 Bad Request\r\n" \
                               "Content-Type: text/html\r\n" \
                               "Content-Length: 0\r\n\r\n".encode('utf-8')
                
            else:
                return "HTTP/1.1 400 Bad Request\r\n" \
                       "Content-Type: text/html\r\n" \
                       "Content-Length: 0\r\n\r\n".encode('utf-8')

        # Handle POST to create a new file in the data folder
        content_length = int(next((line for line in lines if line.startswith("Content-Length")), 0).split(":")[1].strip())
        body = request[-content_length:]
        
        file_name = query_params.get("file", [None])[0] # This line will 
        if file_name and body:
            # Save the POST data to the specified file in 'data' folder
            file_path = os.path.join('./data', file_name)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(body)
            
            response = f"HTTP/1.1 200 OK\r\n" \
                       f"Content-Type: text/html\r\n" \
                       f"Content-Length: {len(body)}\r\n\r\n" \
                       f"POST data saved to {file_path}".encode('utf-8')

        else:
            response = "HTTP/1.1 400 Bad Request\r\n" \
                       "Content-Type: text/html\r\n" \
                       "Content-Length: 0\r\n\r\n".encode('utf-8')

    elif method == "PUT":
        # Handle PUT to update an existing file in the data folder
        file_name = query_params.get("file", [None])[0]
        if file_name:
            content_length = int(next((line for line in lines if line.startswith("Content-Length")), 0).split(":")[1].strip())
            body = request[-content_length:]
            
            # Update the file with the new content
            file_path = os.path.join('./data', file_name)
            if os.path.exists(file_path):
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(body)
                response = f"HTTP/1.1 200 OK\r\n" \
                           f"Content-Type: text/html\r\n" \
                           f"Content-Length: {len(body)}\r\n\r\n" \
                           f"PUT data updated in {file_path}".encode('utf-8')
            else:
                response = "HTTP/1.1 404 Not Found\r\n" \
                           "Content-Type: text/html\r\n" \
                           "Content-Length: 0\r\n\r\n".encode('utf-8')

        else:
            response = "HTTP/1.1 400 Bad Request\r\n" \
                       "Content-Type: text/html\r\n" \
                       "Content-Length: 0\r\n\r\n".encode('utf-8')

    elif method == "DELETE":
        # Handle DELETE to remove a file in the data folder
        file_name = query_params.get("file", [None])[0] # 
        if file_name:
            file_path = os.path.join('./data', file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
                response = "HTTP/1.1 200 OK\r\n" \
                           "Content-Type: text/html\r\n" \
                           "Content-Length: 19\r\n\r\n" \
                           "DELETE request successful".encode('utf-8')
            else:
                response = "HTTP/1.1 404 Not Found\r\n" \
                           "Content-Type: text/html\r\n" \
                           "Content-Length: 0\r\n\r\n".encode('utf-8')
        else:
            response = "HTTP/1.1 400 Bad Request\r\n" \
                       "Content-Type: text/html\r\n" \
                       "Content-Length: 0\r\n\r\n".encode('utf-8')

    elif method == "OPTIONS":
        # Handle OPTIONS request to inform about allowed methods
        response = "HTTP/1.1 200 OK\r\n" \
                   "Content-Type: text/html\r\n" \
                   "Content-Length: 35\r\n\r\n" \
                   "Allowed Methods: GET, POST, PUT, DELETE".encode('utf-8')

    else:
        response = "HTTP/1.1 405 Method Not Allowed\r\n" \
                   "Content-Type: text/html\r\n" \
                   "Content-Length: 0\r\n\r\n".encode('utf-8')
        
    return response

# Function to handle sniffing of network packets
def sniff_packets():
    def packet_callback(packet):
        if packet.haslayer(scapy.Raw):
            return
            log_packet_info(packet)
    
    # Sniff network packets in a separate thread
    scapy.sniff(prn=packet_callback, store=0, filter='tcp port 8080', iface="Software Loopback Interface 1")

def handle_client(client_socket):
    request = receive_request(client_socket)
    if request:
        response = generate_response(request)
        client_socket.send(response)
    client_socket.close()


# Main function to run the HTTP server and capture packets
def run_server(host='127.0.0.1', port=8080):
    # Create the server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Listening on {host}:{port}...")

    # Start sniffing in a separate thread
    sniff_thread = threading.Thread(target=sniff_packets)
    sniff_thread.daemon = True  # This will ensure the thread terminates when the main program exits
    sniff_thread.start()

    while True: 
        # Accept an incoming connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address} established.")
        
        # Receive the HTTP request from the client
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()

if __name__ == "__main__":
    run_server()
