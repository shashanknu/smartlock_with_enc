import tkinter as tk
from tkinter import filedialog, simpledialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os

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
    fernet = Fernet(key)
    with open(file_path, 'rb') as file:
        data = file.read()
    encrypted_data = fernet.encrypt(data)
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_data)
    messagebox.showinfo("Success", "File encrypted successfully")

def decrypt_file(file_path, key):
    try:
        fernet = Fernet(key)
        with open(file_path, 'rb') as enc_file:
            encrypted_data = enc_file.read()
        
        # Ensure the base64 string is correctly padded
        if len(encrypted_data) % 4 != 0:
            encrypted_data += b'=' * (4 - len(encrypted_data) % 4)
        
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(file_path.replace('.enc', ''), 'wb') as dec_file:
            dec_file.write(decrypted_data)
        messagebox.showinfo("Success", "File decrypted successfully")
    except base64.binascii.Error as b64e:
        messagebox.showerror("Error", f"Base64 error: {b64e}")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to decrypt file: {e}")

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

def generate_new_key():
    key_file_path = filedialog.asksaveasfilename(defaultextension=".key")
    if key_file_path:
        password = simpledialog.askstring("Password", "Enter a password for the key:", show='*')
        key, salt = generate_key(password)
        save_key(key_file_path, key, salt)
        messagebox.showinfo("Success", "Key generated and saved successfully")
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key_file_path)

def encrypt():
    file_path = file_entry.get()
    key_file_path = key_entry.get()
    if file_path and key_file_path:
        password = simpledialog.askstring("Password", "Enter the password for the key:", show='*')
        key = load_key(key_file_path, password)
        encrypt_file(file_path, key)
    else:
        messagebox.showerror("Error", "Please select a file and key file")

def decrypt():
    file_path = file_entry.get()
    key_file_path = key_entry.get()
    if file_path and key_file_path:
        password = simpledialog.askstring("Password", "Enter the password for the key:", show='*')
        key = load_key(key_file_path, password)
        decrypt_file(file_path, key)
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
