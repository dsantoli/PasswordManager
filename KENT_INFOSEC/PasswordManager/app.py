from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify,  get_flashed_messages
from flask_bcrypt import Bcrypt
from flask_session import Session
from config import db  
import sqlite3
import re
import logging

import secrets
import string

from crypto_utils import derive_key, encrypt_data, decrypt_data
import os


# Set up basic configuration for logging
logging.basicConfig(level=logging.INFO, filename='app.log', filemode='a',
                    format='%(name)s - %(levelname)s - %(message)s')

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///../santoliDB.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)  # Initialize db with the app
bcrypt = Bcrypt(app)
app.config["SECRET_KEY"] = "e3c0a82e15339c1a3e05d3df115d80aaaf91e7928e5343ee6d3ea5e5b63703b5"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

Session(app)

DATABASE = '../santoliDB.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def check_password_strength(password):
    # Check for the length of the password
    if len(password) < 8:
        return "Weak", "Password too short (minimum 8 characters)."
    
    # Check for the presence of lowercase and uppercase letters
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return "Weak", "Password must contain both lowercase and uppercase letters."
    
    # Check for the presence of digits
    if not re.search(r"[0-9]", password):
        return "Weak", "Password must contain numbers."
    
    # Check for the presence of special characters
    # Include the '[' character in the character class
    if not re.search(r"[!@#$%^&*()_+{}\[\]:;\"'|<>,.?/~`-]", password):
        return "Medium", "Add special characters for a stronger password."
    
    if len(password) >= 12:
        return "Strong", "Strong password."
    else:
        return "Medium", "Password should be at least 12 characters long for extra strength."

def enhanced_generate_password(length=20):
    if length < 8:
        raise ValueError("Password length should be at least 8 characters for security reasons.")

    # Character pools
    uppercase = string.ascii_uppercase
    lowercase = string.ascii_lowercase
    digits = string.digits
    symbols = string.punctuation

    # Ensure the password includes required character types for bonus
    password = [
        secrets.choice(uppercase),
        secrets.choice(symbols),
        secrets.choice(digits),
    ]

    # Fill the rest of the password length ensuring required entropy distribution
    while len(password) < length:
        if len(password) < 8:
            # Next 7 characters (2 bits of entropy each, choose from a larger pool)
            pool = lowercase + digits
        elif len(password) < 20:
            # Next 12 characters (1.5 bits of entropy each, include some symbols)
            pool = lowercase + digits + symbols
        else:
            # Remaining characters (1 bit of entropy each, mostly lowercases)
            pool = lowercase
        
        password.append(secrets.choice(pool))

    # Shuffle to avoid predictable character placement
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)

@app.route('/', methods=['GET', 'POST'])
def auth():
    # Check if the request method is POST, which indicates form submission
    if request.method == 'POST':
        # Retrieve 'username' and 'password' from the submitted form
        username = request.form['username']
        password = request.form['password']
        session['master'] = password
        logging.info(username)
        logging.info(password)

        # Check if the registration button was clicked in the form
        if 'register' in request.form:
            # Check the strength of the provided password
            strength, message = check_password_strength(password)
            # If password is weak or medium, flash a message and reload the auth page
            if strength in ["Weak", "Medium"]:
                flash(message,'auth')
                return render_template('auth.html', username=username)

            # Hash the password using bcrypt for secure storage
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

            # Establish a database connection
            conn = get_db_connection()
            try:
                # Attempt to insert the new user into the database
                conn.execute('INSERT INTO User (Username, Password) VALUES (?, ?)', (username, hashed_password))
                conn.commit()  # Commit the transaction to save the data
                flash('Registration successful! Please login.','auth')  # Flash success message
            except sqlite3.IntegrityError as e:
                # Handle exceptions for duplicate usernames
                flash('Username already exists.','auth')
                logging.error(f'Registration failed for {username}. Reason: {str(e)}')  # Log the error
            finally:
                # Close the database connection
                conn.close()

            # After handling registration, load the authentication page again
            return render_template('auth.html')
        elif 'login' in request.form:
            logging.info("LOGIN BUTTON HIT")
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Retrieve the hashed password for the given username
            cursor.execute('SELECT Password FROM User WHERE Username = ?', (username,))
            user = cursor.fetchone()
            
            if user:
                # Check if the hashed password matches the one provided
                hashed_password = user['Password']
                if bcrypt.check_password_hash(hashed_password, password):
                    session['username'] = username
                    flash('Login successful.', 'dashboard')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid password. Please try again.', 'auth')
            else:
                flash('Username does not exist.', 'auth')

            conn.close()

    # If not a POST request, or no form action matched, load the authentication page
    return render_template('auth.html')

@app.route('/generate-password', methods=['GET'])
def generate_password_api():
    try:
        length = int(request.args.get('length', 12))
        if length < 8 or length > 128:
            raise ValueError("Invalid password length")
        password = enhanced_generate_password(length)
        logging.info(f"Generated password: {password}")  # Log the password to the console
        return jsonify({'password': password})
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    

@app.route('/add-password', methods=['POST'])
def add_password():
    website = request.form['website']
    entry_username = request.form['username']
    password = request.form['password']
    master_password = session.get('master')
    salt = os.urandom(16)
    key = derive_key(master_password, salt)
    logging.info(print("Derived key length:", len(key)))  # Should output 32
    encrypted_password = encrypt_data(key, password)
    login_username = session.get('username')

    conn = get_db_connection()
    cursor = conn.cursor()

    # First, retrieve the user ID based on the username
    try:
        cursor.execute('SELECT ID FROM User WHERE Username = ?', (login_username,))
        user_record = cursor.fetchone()
        if user_record:
            user_id = user_record['ID']
            logging.info(user_id)
            
            # Encrypting the password and storing it with the salt
            cursor.execute('INSERT INTO PasswordEntry (UserID, Website, Username, EncryptedPassword, Salt) VALUES (?, ?, ?, ?, ?)',
               (user_id, website, entry_username, encrypted_password, salt.hex()))
            conn.commit()
            flash('New password entry added successfully!','dashboard')
        else:
            flash('No user found with that username.','dashboard')
    except sqlite3.IntegrityError as e:
        conn.rollback()
        flash('Error adding password entry. Please try again.','dashboard')
        print(e)  # For debugging
    except Exception as e:
        conn.rollback()
        flash('An error occurred. Please try again.','dashboard')
        print(e)  # For debugging
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    username = session.get('username')
    if not username:
        flash('Please log in to view this page.', 'auth')
        return redirect(url_for('auth'))

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the user is ADMIN
    if username == "ADMIN":
        # Fetch all entries with encrypted passwords
        cursor.execute('SELECT ID, UserID, Website, Username, EncryptedPassword FROM PasswordEntry')
        entries = cursor.fetchall()
        entries = [{
            'id': entry['ID'],
            'UserID': entry['UserID'],
            'website': entry['Website'],
            'username': entry['Username'],
            'password': entry['EncryptedPassword']  # Keep encrypted
        } for entry in entries]
    else:
        # Fetch only this user's entries and decrypt them
        cursor.execute('SELECT ID FROM User WHERE Username = ?', (username,))
        user_record = cursor.fetchone()
        if not user_record:
            flash('User not found.', 'dashboard')
            return render_template('dashboard.html', username=username, password_entries=[])

        user_id = user_record['ID']
        cursor.execute('SELECT Website, Username, EncryptedPassword, Salt FROM PasswordEntry WHERE UserID = ?', (user_id,))
        entries = cursor.fetchall()
        decrypted_entries = []
        master_password = session.get('master')  # Assume this is stored securely
        for entry in entries:
            salt = bytes.fromhex(entry['Salt'])
            key = derive_key(master_password, salt)
            decrypted_password = decrypt_data(key, entry['EncryptedPassword'])
            decrypted_entries.append({
                'website': entry['Website'],
                'username': entry['Username'],
                'password': decrypted_password
            })
        entries = decrypted_entries

    return render_template('dashboard.html', username=username, password_entries=entries)

@app.route('/logout')
def logout():
    # Clear the user session
    session.pop('username', None)  # More targeted session data clearance
    session.pop('master', None)
    flash('You have been logged out.', 'auth')
    return redirect(url_for('auth'))


if __name__ == '__main__':
    app.run(debug=True), 
