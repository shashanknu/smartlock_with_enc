import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os
import logging
import threading
import re
# Configure logging
logging.basicConfig(filename="encryption_tool.log", level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
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

def encrypt_file(file_path, key, progress_callback=None):
    try:
        fernet = Fernet(key)
        with open(file_path, 'rb') as file:
            data = file.read()
        encrypted_data = fernet.encrypt(data)
        with open(file_path + '.enc', 'wb') as enc_file:
            enc_file.write(encrypted_data)
        if progress_callback:
            progress_callback(100)
        messagebox.showinfo("Success", "File encrypted successfully")
        logging.info(f"File encrypted: {file_path}")
    except Exception as e:
        if progress_callback:
            progress_callback(100)
        messagebox.showerror("Error", f"Failed to encrypt file: {e}")
        logging.error(f"Failed to encrypt file {file_path}: {e}")

def decrypt_file(file_path, key, progress_callback=None):
    try:
        fernet = Fernet(key)
        with open(file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        
        if len(encrypted_data) % 4 != 0:
            encrypted_data += b'=' * (4 - len(encrypted_data) % 4)
        
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path.replace('.enc', ''), 'wb') as dec_file:
            dec_file.write(decrypted_data)-63
            
        if progress_callback:
            progress_callback(100)
        messagebox.showinfo("Success", "File decrypted successfully")
        logging.info(f"File decrypted: {file_path}")
    except base64.binascii.Error as b64e:
        if progress_callback:
            progress_callback(100)
        messagebox.showerror("Error", f"Base64 error: {b64e}")
        logging.error(f"Base64 error while decrypting file {file_path}: {b64e}")
    except Exception as e:
        if progress_callback:
            progress_callback(100)
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")
        logging.error(f"Failed to decrypt file {file_path}: {e}")

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def browse_key_file():
    key_file_path = filedialog.askopenfilename()
    if key_file_path:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key_file_path)

def password_strength(password):
    if len(password) < 8:
        return "Weak"
    if not re.search("[a-z]", password):
        return "Weak"
    if not re.search("[A-Z]", password):
        return "Weak"
    if not re.search("[0-9]", password):
        return "Weak"
    if not re.search("[^a-zA-Z0-9]", password):
        return "Medium"
    if len(password) >= 8:
        return "Strong"
    return "Medium"

def generate_new_key():
    key_file_path = filedialog.asksaveasfilename(defaultextension=".key")
    if key_file_path:
        while True:
            password = simpledialog.askstring("Password", "Enter a password for the key:", show='*')
            strength = password_strength(password)
            messagebox.showinfo("Password Strength", f"Password strength: {strength}")
            if strength == "Weak":
                retry = messagebox.askyesno("Weak Password", "The password is weak. Do you want to try again?")
                if not retry:
                    break
            else:
                break
        if password:
            key, salt = generate_key(password)
            save_key(key_file_path, key, salt)
            messagebox.showinfo("Success", "Key generated and saved successfully")
            logging.info(f"Key generated and saved: {key_file_path}")
            key_entry.delete(0, tk.END)
            key_entry.insert(0, key_file_path)

def start_progress():
    progress_window = tk.Toplevel(root)
    progress_window.title("Progress")
    progress_label = tk.Label(progress_window, text="Processing...")
    progress_label.pack(pady=10)
    progress_bar = ttk.Progressbar(progress_window, length=200, mode='determinate')
    progress_bar.pack(pady=10)
    return progress_window, progress_bar

def update_progress(progress_bar, value):
    progress_bar['value'] = value
    root.update_idletasks()

def encrypt():
    file_path = file_entry.get()
    key_file_path = key_entry.get()
    if file_path and key_file_path:
        password = simpledialog.askstring("Password", "Enter the password for the key:", show='*')
        key = load_key(key_file_path, password)
        progress_window, progress_bar = start_progress()
        threading.Thread(target=encrypt_file, args=(file_path, key, lambda v: update_progress(progress_bar, v))).start()
        root.after(1000, lambda: progress_window.destroy())
    else:
        messagebox.showerror("Error", "Please select a file and key file")

def decrypt():
    file_path = file_entry.get()
    key_file_path = key_entry.get()
    if file_path and key_file_path:
        password = simpledialog.askstring("Password", "Enter the password for the key:", show='*')
        key = load_key(key_file_path, password)
        progress_window, progress_bar = start_progress()
        threading.Thread(target=decrypt_file, args=(file_path, key, lambda v: update_progress(progress_bar, v))).start()
        root.after(1000, lambda: progress_window.destroy())
    else:
        messagebox.showerror("Error", "Please select a file and key file")

# Create the main application window
root = tk.Tk()
root.title("File Encryption Tool")

# Create and place the widgets
tk.Label(root, text="File:").grid(row=0, column=0, padx=10, pady=10)
file_entry = tk.Entry(root, width=50)
file_entry.grid(row=0, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_file).grid(row=0, column=2, padx=10, pady=10)

tk.Label(root, text="Key File:").grid(row=1, column=0, padx=10, pady=10)
key_entry = tk.Entry(root, width=50)
key_entry.grid(row=1, column=1, padx=10, pady=10)
tk.Button(root, text="Browse", command=browse_key_file).grid(row=1, column=2, padx=10, pady=10)

tk.Button(root, text="Generate Key", command=generate_new_key).grid(row=2, column=1, padx=10, pady=10)

tk.Button(root, text="Encrypt", command=encrypt).grid(row=3, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt", command=decrypt).grid(row=3, column=1, padx=10, pady=10)

# Start the main event loop
root.mainloop()