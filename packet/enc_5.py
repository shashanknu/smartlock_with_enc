import serial
import datetime
import sqlite3
from cryptography.fernet import Fernet
import os

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename='key.key'):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

def load_key(filename='key.key'):
    if not os.path.exists(filename):
        raise FileNotFoundError(f"Key file '{filename}' not found. Please generate it using the key generation script.")
    with open(filename, 'rb') as key_file:
        return key_file.read()

def initialize_db(db_name='nfc_uids.db', key_filename='key.key'):
    key = load_key(key_filename)
    fernet = Fernet(key)
    
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

def encrypt_string(string, key_filename='key.key'):
    key = load_key(key_filename)
    fernet = Fernet(key)
    encrypted = fernet.encrypt(string.encode())
    return encrypted

def decrypt_string(encrypted_string, key_filename='key.key'):
    key = load_key(key_filename)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_string).decode()
    return decrypted

def check_uid_in_db(uid, db_name='nfc_uids.db', key_filename='key.key'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT name FROM users WHERE uid = ?
    ''', (encrypt_string(uid, key_filename),))
    result = cursor.fetchone()
    conn.close()
    return result

def read_nfc_uid(port='COM5', baudrate=115200, filename='nfc_uids.txt', db_name='nfc_uids.db', key_filename='key.key'):
    ser = serial.Serial(port, baudrate, timeout=1)
    initialize_db(db_name, key_filename)  # Ensure the database is initialized
    try:
        with open(filename, 'a') as file:  # Open the file in append mode
            while True:
                if ser.in_waiting > 0:
                    line = ser.readline().decode('utf-8').strip()
                    if "UID Value:" in line:
                        uid = line.split(":")[1].strip()
                        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        user_info = check_uid_in_db(uid, db_name, key_filename)
                        if user_info:
                            log_message = f"{timestamp} - UID: {uid} - {user_info[0]} logged-in"
                        else:
                            log_message = f"{timestamp} - UID: {uid} - UNAUTHORISED ACCESS"
                        file.write(log_message + "\n")
                        file.flush()
                        print(log_message)
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        ser.close()

if __name__ == "__main__":
    read_nfc_uid()
