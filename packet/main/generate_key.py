from cryptography.fernet import Fernet

def generate_key():
    return Fernet.generate_key()

def save_key(key, filename='key.key'):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

if __name__ == "__main__":
    key = generate_key()
    save_key(key)
    print("Encryption key generated and saved as 'key.key'.")
