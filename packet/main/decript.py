import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet

# Function to generate a key and write it to a file
def generate_key(file_path):
    key = Fernet.generate_key()
    with open(file_path, 'wb') as key_file:
        key_file.write(key)

# Function to load a key from a file
def load_key(file_path):
    with open(file_path, 'rb') as key_file:
        key = key_file.read()
    return key

# Function to encrypt a file
def encrypt_file(file_path, key_path):
    key = load_key(key_path)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as file:
        data = file.read()
        
    encrypted_data = fernet.encrypt(data)
    
    with open(file_path + '.enc', 'wb') as enc_file:
        enc_file.write(encrypted_data)
    
    messagebox.showinfo("Success", "File encrypted successfully")

# Function to decrypt a file
def decrypt_file(file_path, key_path):
    key = load_key(key_path)
    fernet = Fernet(key)
    
    with open(file_path, 'rb') as enc_file:
        encrypted_data = enc_file.read()
        
    decrypted_data = fernet.decrypt(encrypted_data)
    
    with open(file_path.replace('.enc', ''), 'wb') as dec_file:
        dec_file.write(decrypted_data)
    
    messagebox.showinfo("Success", "File decrypted successfully")

# Function to browse for a file
def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

# Function to browse for a key file
def browse_key_file():
    key_file_path = filedialog.askopenfilename()
    if key_file_path:
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key_file_path)

# Function to generate a new key
def generate_new_key():
    key_file_path = filedialog.asksaveasfilename(defaultextension=".key")
    if key_file_path:
        generate_key(key_file_path)
        messagebox.showinfo("Success", "Key generated and saved successfully")
        key_entry.delete(0, tk.END)
        key_entry.insert(0, key_file_path)

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

tk.Button(root, text="Encrypt", command=lambda: encrypt_file(file_entry.get(), key_entry.get())).grid(row=3, column=0, padx=10, pady=10)
tk.Button(root, text="Decrypt", command=lambda: decrypt_file(file_entry.get(), key_entry.get())).grid(row=3, column=1, padx=10, pady=10)

# Start the main event loop
root.mainloop()
