import mysql.connector
import pyaes
from werkzeug.security import generate_password_hash, check_password_hash

# Function to encrypt data using AES
def encrypt_data(data, key):
    aes = pyaes.AESModeOfOperationCTR(key)
    return aes.encrypt(data.encode('utf-8'))

# Function to decrypt data using AES
def decrypt_data(data, key):
    aes = pyaes.AESModeOfOperationCTR(key)
    decrypted_data = aes.decrypt(data)
    return decrypted_data.decode('utf-8', errors='ignore')

# Modify create_conn to use your PythonAnywhere MySQL credentials
def create_conn():
    return mysql.connector.connect(
        host='Esat.mysql.pythonanywhere-services.com',  # Your PythonAnywhere database host
        user='Esat',  # Your PythonAnywhere username
        passwd='C>3Gmt-4_2h3Fp)/',  # Your MySQL password
        database='Esat$utilisateurs'  # Your database name
    )
    
def generate_unique_login(nom, prenom):
    base_login = f"{prenom[0].lower()}{nom.lower()}"
    login = base_login
    counter = 1
    while True:
        conn = create_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE login = %s", (login,))
        if cursor.fetchone() is None:
            return login
        login = f"{base_login}{counter}"
        counter += 1


def register(nom, prenom, password):
    login = generate_unique_login(nom, prenom)  # Ensure this function generates a unique login
    hashed_password = generate_password_hash(password)
    try:
        conn = create_conn()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (login, nom, prenom, mtp) VALUES (%s, %s, %s, %s)", (login, nom, prenom, hashed_password))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Failed to insert user: {err}")
        return False
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def login(username, password):
    conn = create_conn()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE login = %s", (username,))
    user = cursor.fetchone()
    if user and check_password_hash(user['mtp'], password):
        return user  # For simplicity, returning the user dictionary
    return None

def get_user(login):
    conn = create_conn()
    cursor = conn.cursor(dictionary=True)  # Fetch results as dictionaries
    try:
        cursor.execute("SELECT * FROM users WHERE login = %s", (login,))
        user = cursor.fetchone()
        return user  # Return the user dictionary
    except mysql.connector.Error as err:
        print(f"Error fetching user: {err}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_decrypted_text(user):
    if user and 'encrypted_text' in user and 'encryption_key' in user:
        encrypted_text = user['encrypted_text']
        encryption_key = user['encryption_key']
        try:
            # Assuming encryption_key and encrypted_text need processing to be used here
            decrypted_text = decrypt_data(encrypted_text, encryption_key)
            return decrypted_text
        except Exception as e:
            print(f"Error decrypting text: {e}")
            return None
    return None
