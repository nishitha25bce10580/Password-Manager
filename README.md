# Suraksha

A **local, encrypted password manager** built with Python (Flask) + HTML/CSS.  
All passwords are encrypted with AES-256 (Fernet) before being stored in SQLite.

---

## ⚡ Quick Start (3 steps)

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
python app.py
```

### 3. Open in browser
```
http://127.0.0.1:5000
```

---

## 🗄 Database

Rakshan auto-creates **`rakshan.db`** (SQLite) the first time you run the app.  
No setup needed — it just works.

**Tables created automatically:**

| Table | Purpose |
|-------|---------|
| `users` | Accounts with hashed master passwords |
| `passwords` | AES-256 encrypted vault entries |
| `audit_log` | Login/action history |

---

## 🔒 Security Features

- **PBKDF2-HMAC-SHA256** (390,000 iterations) for master password hashing
- **Fernet (AES-128-CBC + HMAC-SHA256)** for vault encryption
- Encryption key derived from master password — **never stored on disk**
- Each user has a unique random salt
- Passwords are only decrypted in memory, on demand
- Session-based auth with server-side key storage

---

## 🗂 Project Structure

```
rakshan/
├── app.py              ← Flask backend + all API routes
├── requirements.txt    ← Python dependencies
├── rakshan.db          ← SQLite database (auto-created)
├── README.md
└── static/
    └── index.html      ← Full frontend (HTML + CSS + JS)
```

---

## 🛠 API Endpoints

| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/register` | Create account |
| POST | `/api/login` | Sign in |
| POST | `/api/logout` | Sign out |
| GET | `/api/me` | Current session |
| GET | `/api/passwords` | List all entries |
| POST | `/api/passwords` | Add password |
| PUT | `/api/passwords/:id` | Update entry |
| DELETE | `/api/passwords/:id` | Delete entry |
| GET | `/api/stats` | Vault statistics |
| GET | `/api/generate` | Generate strong password |

---

## 📋 Requirements

- Python 3.8+
- pip
- A modern browser (Chrome, Firefox, Edge, Safari)
