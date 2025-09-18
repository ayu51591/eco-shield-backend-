from flask import request, Flask, jsonify
import sqlite3, os
from argon2 import PasswordHasher 
from flask import Flask
from flask_cors import CORS
app = Flask(__name__)



# Allow multiple origins (e.g., localhost for development and production domain
CORS(app, resources={
    r"/*": {
        "origins": [
            "http://localhost:3000",
            "https://eco-shield-green.web.app"
        ]
    }
})

SCAM_FOLDER = "eco/scam/"
app.config["SCAM_FOLDER"] = SCAM_FOLDER

global login_id
global hashed
ph = PasswordHasher()

@app.route('/signup', methods=['POST'])#useke hisb se 
def singup():
    data = request.get_json()
    name = data['name']
    contact = data['contact']
    email = data['email']
    password = ph.hash(data['password'])
    dob = data['dob']
    
    eco = sqlite3.connect("eco.db")
    cursor = eco.cursor()
     
    cursor.execute("CREATE TABLE IF NOT EXISTS User(user_id INTEGER PRIMARY KEY AUTOINCREMENT, name VARCHAR(15), contact VARCHAR(15), email VARCHAR(50), password VARCHAR(255), dob VARCHAR(20))")
    
    cursor.execute("INSERT INTO User(name, contact, email, password, dob) VALUES (?, ?, ?, ?, ?)",(name, contact, email, password, dob)) 
    
    eco.commit() 
    eco.close()

    return jsonify({"message": "Signup successful"}), 201

    
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password']

    eco = sqlite3.connect("eco.db")
    cursor = eco.cursor()
    cursor.execute("SELECT password FROM User WHERE email = ?", (email,))
    row = cursor.fetchone()
    eco.close()

    if not row:
        return jsonify({"error": "Email not found"}), 404

    try:
        if ph.verify(row[0], password):
            return jsonify({"message": "Password correct"}), 200
        else:
            return jsonify({"error": "Password incorrect"}), 401
    except:
        return jsonify({"error": "Password incorrect"}), 401

@app.route('/Scam_Report',methods=['POST'])
def scam():
    data = request.get_json()
    file = request.files["image"]
    file_path = os.path.join(app.config["SCAM_FOLDER"], file.filename)#when u local host path is to be set then 
    file.save(file_path)
    title = data["title"]
    discription = data["detail"]
    
    eco = sqlite3.connect("eco.db")
    cursor = eco.cursor()
     
    cursor.execute("CREATE TABLE IF NOT EXISTS Scam_reports (report_id INTEGER PRIMARY KEY AUTOENCREMENT,  victim INTEGER, title TEXT, discription TEXT, image TEXT, FOREIGN KEY (user_id) RFREFENCES User(user_id)  ")
    
