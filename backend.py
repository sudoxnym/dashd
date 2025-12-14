#!/usr/bin/env python3
"""
dashd backend - user auth + settings persistence
"""

import os
import json
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import jwt

DB_PATH = os.environ.get('DASHD_DB', '/data/dashd.db')
JWT_SECRET = os.environ.get('DASHD_SECRET', secrets.token_hex(32))
JWT_EXPIRY_DAYS = 30

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            user_id INTEGER PRIMARY KEY,
            services TEXT DEFAULT '[]',
            card_positions TEXT DEFAULT '{}',
            card_sizes TEXT DEFAULT '{}',
            grid_size TEXT DEFAULT '{}',
            machines TEXT DEFAULT '[]',
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + ':' + hashed.hex()

def verify_password(password, stored):
    salt, hashed = stored.split(':')
    check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return check.hex() == hashed

def create_token(user_id, username):
    payload = {
        'user_id': user_id,
        'username': username,
        'exp': datetime.utcnow() + timedelta(days=JWT_EXPIRY_DAYS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm='HS256')

def verify_token(token):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        return payload
    except:
        return None

class APIHandler(BaseHTTPRequestHandler):
    def send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.end_headers()

    def get_user(self):
        auth = self.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            return verify_token(token)
        return None

    def read_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length:
            return json.loads(self.rfile.read(length).decode())
        return {}

    def do_POST(self):
        path = urlparse(self.path).path
        
        if path == '/api/auth/register':
            data = self.read_body()
            username = data.get('username', '').strip().lower()
            password = data.get('password', '')
            
            if not username or not password:
                return self.send_json({'error': 'username and password required'}, 400)
            if len(username) < 3:
                return self.send_json({'error': 'username too short'}, 400)
            if len(password) < 6:
                return self.send_json({'error': 'password too short'}, 400)
            
            conn = get_db()
            try:
                cur = conn.execute(
                    'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                    (username, hash_password(password))
                )
                user_id = cur.lastrowid
                conn.execute('INSERT INTO settings (user_id) VALUES (?)', (user_id,))
                conn.commit()
                token = create_token(user_id, username)
                self.send_json({'token': token, 'username': username})
            except sqlite3.IntegrityError:
                self.send_json({'error': 'username taken'}, 400)
            finally:
                conn.close()
        
        elif path == '/api/auth/login':
            data = self.read_body()
            username = data.get('username', '').strip().lower()
            password = data.get('password', '')
            
            conn = get_db()
            user = conn.execute(
                'SELECT id, password_hash FROM users WHERE username = ?', (username,)
            ).fetchone()
            conn.close()
            
            if user and verify_password(password, user['password_hash']):
                token = create_token(user['id'], username)
                self.send_json({'token': token, 'username': username})
            else:
                self.send_json({'error': 'invalid credentials'}, 401)
        
        elif path == '/api/settings/save':
            user = self.get_user()
            if not user:
                return self.send_json({'error': 'unauthorized'}, 401)
            
            data = self.read_body()
            conn = get_db()
            conn.execute('''
                UPDATE settings SET
                    services = ?,
                    card_positions = ?,
                    card_sizes = ?,
                    grid_size = ?,
                    machines = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = ?
            ''', (
                json.dumps(data.get('services', [])),
                json.dumps(data.get('cardPositions', {})),
                json.dumps(data.get('cardSizes', {})),
                json.dumps(data.get('gridSize', {})),
                json.dumps(data.get('machines', [])),
                user['user_id']
            ))
            conn.commit()
            conn.close()
            self.send_json({'success': True})
        
        else:
            self.send_json({'error': 'not found'}, 404)

    def do_GET(self):
        path = urlparse(self.path).path
        
        if path == '/api/settings/load':
            user = self.get_user()
            if not user:
                return self.send_json({'error': 'unauthorized'}, 401)
            
            conn = get_db()
            settings = conn.execute(
                'SELECT * FROM settings WHERE user_id = ?', (user['user_id'],)
            ).fetchone()
            conn.close()
            
            if settings:
                self.send_json({
                    'services': json.loads(settings['services']),
                    'cardPositions': json.loads(settings['card_positions']),
                    'cardSizes': json.loads(settings['card_sizes']),
                    'gridSize': json.loads(settings['grid_size']),
                    'machines': json.loads(settings['machines'])
                })
            else:
                self.send_json({})
        
        elif path == '/api/auth/verify':
            user = self.get_user()
            if user:
                self.send_json({'valid': True, 'username': user['username']})
            else:
                self.send_json({'valid': False}, 401)
        
        elif path == '/health':
            self.send_json({'status': 'ok'})
        
        else:
            self.send_json({'error': 'not found'}, 404)

    def log_message(self, format, *args):
        pass  # silent logging

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 8086))
    server = HTTPServer(('0.0.0.0', port), APIHandler)
    print(f'dashd backend running on port {port}')
    server.serve_forever()
