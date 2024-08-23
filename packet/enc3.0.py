import serial
import datetime
import sqlite3
import os
import base64
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Configure logging
logging.basicConfig(filename="encryption_tool.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Pre-set password and key file path
PRESET_PASSWORD = "your_secure_password"
KEY_FILE_PATH = "encryption_key.key"

def initialize_db(db_name='nfc_uids.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            uid TEXT UNIQUE,
            name TEXT
        )
    ''')
    conn.commit()
    conn.close()

def check_uid_in_db(uid, db_name='nfc_uids.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT name FROM users WHERE uid = ?
    ''', (uid,))
    result = cursor.fetchone()
    conn.close()
    return result

def generate_key(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key, salt

def save_key(file_path, key, salt):
    with open(file_path, 'wb') as key_file:
        key_file.write(salt + key)

def load_key(file_path, password):
    with open(file_path, 'rb') as key_file:
        salt = key_file.read(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def encrypt_file(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, 'rb') as file:
            data = file.read()
        encrypted_data = fernet.encrypt(data)
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(encrypted_data)
        os.remove(file_path)  # Remove the original file after encryption
        logging.info(f"File encrypted: {file_path}")
        print("File encrypted successfully")
    except Exception as e:
        print(f"Failed to encrypt file: {e}")
        logging.error(f"Failed to encrypt file {file_path}: {e}")

def read_nfc_uid(port='COM5', baudrate=115200, filename='nfc_uids.txt', db_name='nfc_uids.db'):
    ser = serial.Serial(port, baudrate, timeout=1)
    initialize_db(db_name)  # Ensure the database is initialized

    if not os.path.exists(KEY_FILE_PATH):
        print("Generating new encryption key...")
        key, salt = generate_key(PRESET_PASSWORD)
        save_key(KEY_FILE_PATH, key, salt)
        print("Encryption key saved to", KEY_FILE_PATH)
    
    key = load_key(KEY_FILE_PATH, PRESET_PASSWORD)
    
    try:
        while True:
            if ser.in_waiting > 0:
                line = ser.readline().decode('utf-8').strip()
                if "UID Value:" in line:
                    uid = line.split(":")[1].strip()
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    user_info = check_uid_in_db(uid, db_name)
                    if user_info:
                        log_message = f"{timestamp} - UID: {uid} - {user_info[0]} - Access Granted"
                    else:
                        log_message = f"{timestamp} - UID: {uid} - UNAUTHORIZED ACCESS"
                    
                    with open(filename, 'a') as file:  # Open the file in append mode
                        file.write(log_message + "\n")
                        file.flush()
                    
                    print(log_message)
                    
                    # Encrypt the file immediately after writing the log entry
                    encrypt_file(filename, key)
                    
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ser.close()

if __name__ == "__main__":
    read_nfc_uid()
