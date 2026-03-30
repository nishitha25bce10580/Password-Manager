from flask import Flask, request, jsonify, send_from_directory, session
import sqlite3
import hashlib
import secrets
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

app = Flask(__name__, static_folder='static')
app.secret_key = secrets.token_hex(32)

DB_PATH = 'rakshan.db'

# ── Database setup ──────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            username  TEXT    UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt      TEXT NOT NULL,
            enc_key_salt TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS passwords (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            site_name   TEXT NOT NULL,
            site_url    TEXT,
            username    TEXT,
            encrypted_password TEXT NOT NULL,
            notes       TEXT,
            category    TEXT DEFAULT 'General',
            strength    INTEGER DEFAULT 0,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            action     TEXT,
            details    TEXT,
            timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    conn.commit()
    conn.close()

# ── Crypto helpers ───────────────────────────────────────────────────────────

def derive_key(master_password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 390000).hex()

def encrypt_password(plaintext: str, key: bytes) -> str:
    f = Fernet(key)
    return f.encrypt(plaintext.encode()).decode()

def decrypt_password(ciphertext: str, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(ciphertext.encode()).decode()

def password_strength(password: str) -> int:
    score = 0
    if len(password) >= 8:  score += 1
    if len(password) >= 16: score += 1
    if any(c.isupper() for c in password): score += 1
    if any(c.islower() for c in password): score += 1
    if any(c.isdigit() for c in password): score += 1
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password): score += 1
    return min(score, 5)

def log_action(user_id, action, details=''):
    conn = get_db()
    conn.execute('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)',
                 (user_id, action, details))
    conn.commit()
    conn.close()

# ── Auth routes ──────────────────────────────────────────────────────────────

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Master password must be at least 8 characters'}), 400

    salt = secrets.token_hex(32)
    enc_salt = secrets.token_bytes(32)
    pw_hash = hash_password(password, salt)

    conn = get_db()
    try:
        conn.execute(
            'INSERT INTO users (username, password_hash, salt, enc_key_salt) VALUES (?, ?, ?, ?)',
            (username, pw_hash, salt, base64.b64encode(enc_salt).decode())
        )
        conn.commit()
        log_action(None, 'REGISTER', f'User {username} registered')
        return jsonify({'message': 'Account created successfully'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username', '').strip()
    password = data.get('password', '')

    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()

    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401

    pw_hash = hash_password(password, user['salt'])
    if pw_hash != user['password_hash']:
        return jsonify({'error': 'Invalid credentials'}), 401

    enc_salt = base64.b64decode(user['enc_key_salt'])
    enc_key = derive_key(password, enc_salt)

    session['user_id'] = user['id']
    session['username'] = user['username']
    session['enc_key'] = enc_key.decode()

    log_action(user['id'], 'LOGIN', f'User {username} logged in')
    return jsonify({'message': 'Login successful', 'username': username})

@app.route('/api/logout', methods=['POST'])
def logout():
    uid = session.get('user_id')
    session.clear()
    log_action(uid, 'LOGOUT')
    return jsonify({'message': 'Logged out'})

@app.route('/api/me', methods=['GET'])
def me():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({'username': session['username'], 'user_id': session['user_id']})

# ── Password CRUD ────────────────────────────────────────────────────────────

def require_auth(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Not authenticated'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/passwords', methods=['GET'])
@require_auth
def list_passwords():
    user_id = session['user_id']
    enc_key = session['enc_key'].encode()
    search = request.args.get('q', '').lower()
    category = request.args.get('category', '')

    conn = get_db()
    query = 'SELECT * FROM passwords WHERE user_id = ?'
    params = [user_id]
    if category:
        query += ' AND category = ?'
        params.append(category)
    query += ' ORDER BY site_name ASC'
    rows = conn.execute(query, params).fetchall()
    conn.close()

    results = []
    for r in rows:
        if search and search not in r['site_name'].lower() and search not in (r['site_url'] or '').lower():
            continue
        try:
            decrypted = decrypt_password(r['encrypted_password'], enc_key)
        except Exception:
            decrypted = '(decryption error)'
        results.append({
            'id': r['id'],
            'site_name': r['site_name'],
            'site_url': r['site_url'],
            'username': r['username'],
            'password': decrypted,
            'notes': r['notes'],
            'category': r['category'],
            'strength': r['strength'],
            'created_at': r['created_at'],
            'updated_at': r['updated_at'],
        })
    return jsonify(results)

@app.route('/api/passwords', methods=['POST'])
@require_auth
def add_password():
    user_id = session['user_id']
    enc_key = session['enc_key'].encode()
    data = request.json

    site_name = data.get('site_name', '').strip()
    plain_pw = data.get('password', '')
    if not site_name or not plain_pw:
        return jsonify({'error': 'Site name and password required'}), 400

    encrypted = encrypt_password(plain_pw, enc_key)
    strength = password_strength(plain_pw)

    conn = get_db()
    cur = conn.execute(
        '''INSERT INTO passwords (user_id, site_name, site_url, username, encrypted_password, notes, category, strength)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (user_id, site_name, data.get('site_url'), data.get('username'),
         encrypted, data.get('notes'), data.get('category', 'General'), strength)
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    log_action(user_id, 'ADD_PASSWORD', f'Added entry for {site_name}')
    return jsonify({'message': 'Password saved', 'id': new_id, 'strength': strength})

@app.route('/api/passwords/<int:pw_id>', methods=['PUT'])
@require_auth
def update_password(pw_id):
    user_id = session['user_id']
    enc_key = session['enc_key'].encode()
    data = request.json

    conn = get_db()
    row = conn.execute('SELECT * FROM passwords WHERE id = ? AND user_id = ?', (pw_id, user_id)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Not found'}), 404

    plain_pw = data.get('password', '')
    encrypted = encrypt_password(plain_pw, enc_key) if plain_pw else row['encrypted_password']
    strength = password_strength(plain_pw) if plain_pw else row['strength']

    conn.execute(
        '''UPDATE passwords SET site_name=?, site_url=?, username=?, encrypted_password=?,
           notes=?, category=?, strength=?, updated_at=CURRENT_TIMESTAMP WHERE id=?''',
        (data.get('site_name', row['site_name']), data.get('site_url', row['site_url']),
         data.get('username', row['username']), encrypted, data.get('notes', row['notes']),
         data.get('category', row['category']), strength, pw_id)
    )
    conn.commit()
    conn.close()
    log_action(user_id, 'UPDATE_PASSWORD', f'Updated entry id={pw_id}')
    return jsonify({'message': 'Updated', 'strength': strength})

@app.route('/api/passwords/<int:pw_id>', methods=['DELETE'])
@require_auth
def delete_password(pw_id):
    user_id = session['user_id']
    conn = get_db()
    conn.execute('DELETE FROM passwords WHERE id = ? AND user_id = ?', (pw_id, user_id))
    conn.commit()
    conn.close()
    log_action(user_id, 'DELETE_PASSWORD', f'Deleted entry id={pw_id}')
    return jsonify({'message': 'Deleted'})

@app.route('/api/stats', methods=['GET'])
@require_auth
def stats():
    user_id = session['user_id']
    enc_key = session['enc_key'].encode()
    conn = get_db()
    rows = conn.execute('SELECT * FROM passwords WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()

    total = len(rows)
    weak = sum(1 for r in rows if r['strength'] <= 2)
    strong = sum(1 for r in rows if r['strength'] >= 4)
    cats = {}
    for r in rows:
        cats[r['category']] = cats.get(r['category'], 0) + 1

    return jsonify({'total': total, 'weak': weak, 'strong': strong, 'categories': cats})

@app.route('/api/generate', methods=['GET'])
@require_auth
def generate_password():
    import string, random
    length = int(request.args.get('length', 16))
    chars = string.ascii_letters + string.digits + '!@#$%^&*'
    pw = ''.join(secrets.choice(chars) for _ in range(length))
    return jsonify({'password': pw, 'strength': password_strength(pw)})

# ── Static files ─────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

if __name__ == '__main__':
    init_db()
    print("\n🔐 Rakshan Password Manager")
    print("=" * 40)
    print("▶  Open http://127.0.0.1:5000 in your browser")
    print("   Database: rakshan.db (auto-created)")
    print("=" * 40 + "\n")
    app.run(debug=True, port=5000)
