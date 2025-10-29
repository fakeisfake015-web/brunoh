"""
CTF Challenge: SQL Injection to RCE
Category: Web Exploitation
Difficulty: Advanced

Description:
Advanced SQL injection challenge with multiple layers of filters.
Players must bypass WAF, exploit second-order SQLi, and achieve RCE.

Flag: JCOECTF{adv4nc3d_sql1_t0_rc3_ch41n_pwn3d}
"""

from flask import Flask, request, render_template_string, session, redirect, url_for
import sqlite3
import hashlib
import os
import re
import subprocess

app = Flask(__name__)
app.secret_key = os.urandom(32)

# WAF - Web Application Firewall (intentionally bypassable)
class SimpleWAF:
    BLACKLIST = [
        'union', 'select', 'insert', 'delete', 'update', 'drop', 'create',
        'alter', 'exec', 'execute', 'script', 'javascript', 'onerror',
        'onload', '--', '/*', '*/', '||', '&&', 'concat', 'char', 'load_file'
    ]
    
    @staticmethod
    def check(input_string):
        """Check if input contains blacklisted keywords"""
        input_lower = input_string.lower()
        for blocked in SimpleWAF.BLACKLIST:
            if blocked in input_lower:
                return False, f"WAF: Blocked keyword detected: {blocked}"
        return True, "OK"

# Database initialization
def init_db():
    conn = sqlite3.connect('challenge.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, 
                  password TEXT, role TEXT, api_key TEXT)''')
    
    # Logs table (for second-order SQLi)
    c.execute('''CREATE TABLE IF NOT EXISTS logs
                 (id INTEGER PRIMARY KEY, username TEXT, action TEXT, 
                  timestamp TEXT, ip_address TEXT)''')
    
    # Admin command execution table
    c.execute('''CREATE TABLE IF NOT EXISTS commands
                 (id INTEGER PRIMARY KEY, command TEXT, result TEXT, 
                  executed_by TEXT, timestamp TEXT)''')
    
    # Insert default users
    admin_pass = hashlib.md5(b"sup3r_s3cr3t_p4ssw0rd").hexdigest()
    c.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', ?, 'admin', 'ADM1N-K3Y-2024')",
              (admin_pass,))
    
    guest_pass = hashlib.md5(b"guest").hexdigest()
    c.execute("INSERT OR IGNORE INTO users VALUES (2, 'guest', ?, 'user', 'GUEST-K3Y-2024')",
              (guest_pass,))
    
    # Insert flag in a special location
    flag_pass = hashlib.md5(b"impossible_to_guess_12345").hexdigest()
    c.execute("INSERT OR IGNORE INTO users VALUES (999, 'flag_keeper', ?, 'secret', 'JCOECTF{adv4nc3d_sql1_t0_rc3_ch41n_pwn3d}')",
              (flag_pass,))
    
    conn.commit()
    conn.close()

# Home page
@app.route('/')
def index():
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Secure Login Portal</title>
        <style>
            body { font-family: Arial; background: #f0f0f0; padding: 50px; }
            .container { max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
            h1 { color: #333; }
            input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 5px; }
            button { width: 100%; padding: 10px; background: #4CAF50; color: white; border: none; border-radius: 5px; cursor: pointer; }
            button:hover { background: #45a049; }
            .info { background: #e7f3fe; padding: 15px; margin-top: 20px; border-left: 4px solid #2196F3; }
            .error { background: #ffebee; padding: 15px; margin-top: 20px; border-left: 4px solid #f44336; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 Secure Login Portal v2.0</h1>
            <form method="POST" action="/login">
                <input type="text" name="username" placeholder="Username" required>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
            </form>
            
            <div class="info">
                <strong>🛡️ Security Features:</strong><br>
                ✅ Advanced WAF Protection<br>
                ✅ MD5 Password Hashing<br>
                ✅ SQL Injection Prevention<br>
                ✅ XSS Filtering<br>
                <br>
                <em>Try to hack me! 😏</em><br>
                <small>Hint: Sometimes the second try is the charm...</small>
            </div>
            
            {% if error %}
            <div class="error">{{ error }}</div>
            {% endif %}
        </div>
    </body>
    </html>
    '''
    return render_template_string(template, error=request.args.get('error'))

# Login endpoint (vulnerable to SQLi but protected by WAF)
@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # WAF Check
    waf_check, waf_msg = SimpleWAF.check(username + password)
    if not waf_check:
        return redirect(url_for('index', error=waf_msg))
    
    # Hash password
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    # Log the login attempt (Second-order SQLi vulnerability!)
    conn = sqlite3.connect('challenge.db')
    c = conn.cursor()
    
    # This is vulnerable but username is logged as-is
    log_query = f"INSERT INTO logs (username, action, timestamp, ip_address) VALUES ('{username}', 'login_attempt', datetime('now'), '{request.remote_addr}')"
    try:
        c.execute(log_query)
        conn.commit()
    except:
        pass
    
    # Vulnerable SQL query (but protected by WAF on first attempt)
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password_hash}'"
    
    try:
        result = c.execute(query).fetchone()
        conn.close()
        
        if result:
            session['username'] = result[1]
            session['role'] = result[3]
            session['api_key'] = result[4]
            return redirect(url_for('dashboard'))
        else:
            return redirect(url_for('index', error='Invalid credentials'))
    except Exception as e:
        conn.close()
        return redirect(url_for('index', error=f'Database error: {str(e)}'))

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Dashboard</title>
        <style>
            body { font-family: Arial; background: #f0f0f0; padding: 50px; }
            .container { max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 10px; }
            .welcome { background: #4CAF50; color: white; padding: 20px; border-radius: 5px; }
            .section { margin: 20px 0; padding: 20px; background: #f9f9f9; border-radius: 5px; }
            button { padding: 10px 20px; background: #2196F3; color: white; border: none; border-radius: 5px; cursor: pointer; margin: 5px; }
            a { text-decoration: none; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="welcome">
                <h1>Welcome, {{ username }}!</h1>
                <p>Role: {{ role }}</p>
                <p>API Key: {{ api_key }}</p>
            </div>
            
            <div class="section">
                <h2>Available Actions:</h2>
                <a href="/logs"><button>View Login Logs</button></a>
                {% if role == 'admin' %}
                <a href="/admin"><button>Admin Panel</button></a>
                {% endif %}
                <a href="/logout"><button>Logout</button></a>
            </div>
            
            <div class="section">
                <h3>📊 System Statistics</h3>
                <p>Total Users: {{ user_count }}</p>
                <p>Your Login Attempts: {{ login_attempts }}</p>
            </div>
        </div>
    </body>
    </html>
    '''
    
    conn = sqlite3.connect('challenge.db')
    c = conn.cursor()
    user_count = c.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    login_attempts = c.execute(f"SELECT COUNT(*) FROM logs WHERE username='{session['username']}'").fetchone()[0]
    conn.close()
    
    return render_template_string(template, 
                                   username=session['username'],
                                   role=session['role'],
                                   api_key=session['api_key'],
                                   user_count=user_count,
                                   login_attempts=login_attempts)

# View logs (Second-order SQLi exploitation point)
@app.route('/logs')
def view_logs():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    conn = sqlite3.connect('challenge.db')
    c = conn.cursor()
    
    # Second-order SQLi: The malicious payload stored in logs is now executed!
    search = request.args.get('search', '')
    if search:
        # This query uses data from the logs table which may contain SQLi payload
        query = f"SELECT * FROM logs WHERE username LIKE '%{search}%' OR action LIKE '%{search}%'"
    else:
        query = "SELECT * FROM logs ORDER BY id DESC LIMIT 50"
    
    try:
        logs = c.execute(query).fetchall()
        conn.close()
        
        template = '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Login Logs</title>
            <style>
                body { font-family: Arial; background: #f0f0f0; padding: 50px; }
                table { width: 100%; border-collapse: collapse; background: white; }
                th, td { padding: 12px; text-align: left; border: 1px solid #ddd; }
                th { background: #4CAF50; color: white; }
                .search { margin: 20px 0; }
                input { padding: 10px; width: 300px; }
                button { padding: 10px 20px; background: #2196F3; color: white; border: none; cursor: pointer; }
            </style>
        </head>
        <body>
            <h1>Login Logs</h1>
            <div class="search">
                <form method="GET">
                    <input type="text" name="search" placeholder="Search logs..." value="{{ search }}">
                    <button type="submit">Search</button>
                </form>
            </div>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Username</th>
                    <th>Action</th>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                </tr>
                {% for log in logs %}
                <tr>
                    <td>{{ log[0] }}</td>
                    <td>{{ log[1] }}</td>
                    <td>{{ log[2] }}</td>
                    <td>{{ log[3] }}</td>
                    <td>{{ log[4] }}</td>
                </tr>
                {% endfor %}
            </table>
            <br>
            <a href="/dashboard"><button>Back to Dashboard</button></a>
        </body>
        </html>
        '''
        return render_template_string(template, logs=logs, search=search)
    except Exception as e:
        conn.close()
        return f"<h1>Error</h1><p>{str(e)}</p><a href='/dashboard'>Back</a>"

# Admin panel (requires admin role)
@app.route('/admin')
def admin():
    if 'username' not in session or session.get('role') != 'admin':
        return "<h1>Access Denied</h1><p>Admin only!</p>"
    
    template = '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Admin Panel</title>
        <style>
            body { font-family: Arial; background: #f0f0f0; padding: 50px; }
            .container { max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 10px; }
            .danger { background: #ff9800; color: white; padding: 20px; border-radius: 5px; margin: 20px 0; }
            input { padding: 10px; width: 100%; margin: 10px 0; }
            button { padding: 10px 20px; background: #f44336; color: white; border: none; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⚠️ Admin Panel</h1>
            <div class="danger">
                <h2>System Command Execution</h2>
                <p>Execute system commands (use with caution!)</p>
                <form method="POST" action="/admin/execute">
                    <input type="text" name="command" placeholder="Enter command..." required>
                    <button type="submit">Execute</button>
                </form>
            </div>
            <a href="/dashboard"><button style="background: #2196F3;">Back to Dashboard</button></a>
        </div>
    </body>
    </html>
    '''
    return render_template_string(template)

# Command execution (RCE endpoint - admin only)
@app.route('/admin/execute', methods=['POST'])
def execute_command():
    if 'username' not in session or session.get('role') != 'admin':
        return "<h1>Access Denied</h1>"
    
    command = request.form.get('command', '')
    
    # Simple command whitelist (bypassable)
    allowed_commands = ['ls', 'pwd', 'whoami', 'date', 'cat /tmp/flag.txt']
    
    if any(cmd in command for cmd in allowed_commands):
        try:
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=5)
            output = result.decode()
        except Exception as e:
            output = str(e)
    else:
        output = "Command not in whitelist!"
    
    return f'''
    <html>
    <head>
        <style>
            body {{ font-family: monospace; background: #000; color: #0f0; padding: 50px; }}
            pre {{ background: #1a1a1a; padding: 20px; border: 1px solid #0f0; }}
        </style>
    </head>
    <body>
        <h1>Command Output:</h1>
        <pre>{output}</pre>
        <a href="/admin" style="color: #0f0;">Back</a>
    </body>
    </html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    
    # Create flag file
    with open('/tmp/flag.txt', 'w') as f:
        f.write('JCOECTF{adv4nc3d_sql1_t0_rc3_ch41n_pwn3d}')
    
    print("="*50)
    print("SQL Injection to RCE Challenge")
    print("="*50)
    print("\nChallenge is running on http://localhost:5000")
    print("\nDefault credentials:")
    print("  Username: guest")
    print("  Password: guest")
    print("\nObjective: Get the flag from /tmp/flag.txt")
    print("="*50)
    
    app.run(host='0.0.0.0', port=5000, debug=False)
