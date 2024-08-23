import serial
import datetime
import sqlite3
import os
import logging
import threading
import time
from cryptography.fernet import Fernet

# Configure logging
logging.basicConfig(filename="encryption_tool.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Key file path
KEY_FILE_PATH = "encryption_key.key"
DATA_FILE_PATH = "nfc_uids.txt"

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

def generate_key():
    return Fernet.generate_key()

def save_key(file_path, key):
    with open(file_path, 'wb') as key_file:
        key_file.write(key)
    logging.info(f"Key saved to {file_path}")

def load_key(file_path):
    with open(file_path, 'rb') as key_file:
        key = key_file.read()
    logging.info(f"Key loaded: {key}")
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

def periodic_encryption(file_path, key, interval=10):
    while True:
        time.sleep(interval)
        encrypt_file(file_path, key)

def read_nfc_uid(port='COM5', baudrate=115200, db_name='nfc_uids.db'):
    ser = serial.Serial(port, baudrate, timeout=1)
    initialize_db(db_name)  # Ensure the database is initialized

    if not os.path.exists(KEY_FILE_PATH):
        print("Generating new encryption key...")
        key = generate_key()
        save_key(KEY_FILE_PATH, key)
        print("Encryption key saved to", KEY_FILE_PATH)
    else:
        key = load_key(KEY_FILE_PATH)
        if len(key) != 44:
            print("Key is not valid. Generating a new one.")
            key = generate_key()
            save_key(KEY_FILE_PATH, key)
            print("New encryption key saved to", KEY_FILE_PATH)

    # Start the periodic encryption in a separate thread
    encryption_thread = threading.Thread(target=periodic_encryption, args=(DATA_FILE_PATH, key))
    encryption_thread.daemon = True
    encryption_thread.start()

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
                    
                    with open(DATA_FILE_PATH, 'a') as file:  # Open the file in append mode
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
