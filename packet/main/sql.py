import sqlite3

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

def add_user(uid, name, db_name='nfc_uids.db'):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR IGNORE INTO users (uid, name) VALUES (?, ?)
    ''', (uid, name))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    initialize_db()
    # Add some test users
    add_user('0xC9 0xAF 0x76 0xC2', 'vismaya s r')
    add_user('0x19 0xE2 0x74 0xC2', 'shashank n u')
    