from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3, os
from argon2 import PasswordHasher

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": ["http://localhost:3000","https://eco-shield-green.web.app"]}})

ph = PasswordHasher()
DB_PATH = os.path.join(os.path.dirname(__file__), "eco.db")

def get_db():
    return sqlite3.connect(DB_PATH)

def init_db():
    eco = get_db()
    cursor = eco.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS User(
            user_id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            contact TEXT,
            email TEXT UNIQUE,
            password TEXT,
            dob TEXT,
            is_active BOOLEAN DEFAULT 1
        )
    """)
    eco.commit()
    eco.close()
init_db()

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name, contact, email, dob, password = data['name'], data['contact'], data['email'], data['dob'], data['password']

    hashed_password = ph.hash(password)
    eco = get_db()
    cursor = eco.cursor()
    try:
        cursor.execute("INSERT INTO User(name, contact, email, password, dob) VALUES (?, ?, ?, ?, ?)",
                       (name, contact, email, hashed_password, dob))
        eco.commit()
        return jsonify({"message": "Signup successful"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Email already registered"}), 409
    finally:
        eco.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email, password = data['email'], data['password']

    eco = get_db()
    cursor = eco.cursor()
    cursor.execute("SELECT user_id, password FROM User WHERE email = ? AND is_active = 1", (email,))
    row = cursor.fetchone()
    eco.close()

    if not row:
        return jsonify({"error": "Email not found"}), 404

    user_id, stored_hash = row
    try:
        if ph.verify(stored_hash, password):
            return jsonify({"message": "Login successful", "user_id": user_id}), 200
    except:
        return jsonify({"error": "Password incorrect"}), 401

@app.route('/dashboard', methods=['GET'])
def dashboard():
    eco = get_db()
    cursor = eco.cursor()
    cursor.execute("SELECT name, email, contact FROM User")
    rows = cursor.fetchall()
    eco.close()

    users = [{"name": r[0], "email": r[1], "contact": r[2]} for r in rows]
    return jsonify(users), 200

if __name__ == "__main__":
    app.run(debug=True)
