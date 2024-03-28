import mysql.connector
import pyaes
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os
from cryptography.fernet import Fernet

# Correct approach to load the master key from an environment variable
MASTER_KEY = os.getenv('MASTER_KEY')
if MASTER_KEY is None:
    raise ValueError("Master key not found in environment variables")
fernet = Fernet(MASTER_KEY.encode())

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
        
        
def encode_for_storage(data):
    """Encode binary data using Base64 for database storage.
    
    Args:
        data (bytes): The binary data to encode.
    
    Returns:
        str: The Base64-encoded string representation of the data.
    """
    if data is None:
        return None
    return base64.b64encode(data).decode('utf-8')

def decode_for_usage(encoded_data):
    """Decode Base64-encoded data back into binary form for usage.
    
    Args:
        encoded_data (str): The Base64-encoded string representation of the data.
    
    Returns:
        bytes: The original binary data.
    """
    if encoded_data is None:
        return None
    return base64.b64decode(encoded_data.encode('utf-8'))



def generate_new_encryption_key(key_length=32):
    return os.urandom(key_length)

def encrypt_key_for_storage(encryption_key):
    return fernet.encrypt(encryption_key)

def decrypt_key_for_usage(encrypted_key):
    return fernet.decrypt(encrypted_key)

def secure_store_key(user_login, encryption_key):
    encrypted_key_for_storage = encrypt_key_for_storage(encryption_key)
    conn = create_conn()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET encryption_key = %s WHERE login = %s", 
                   (encrypted_key_for_storage, user_login))
    conn.commit()
    cursor.close()
    conn.close()

def retrieve_and_decrypt_key(user_login):
    conn = create_conn()
    cursor = conn.cursor()
    cursor.execute("SELECT encryption_key FROM users WHERE login = %s", (user_login,))
    encrypted_key = cursor.fetchone()[0]
    decrypted_key = decrypt_key_for_usage(encrypted_key)
    cursor.close()
    conn.close()
    return decrypted_key

def save_encrypted_text(user_login, text_to_encrypt):
    conn = create_conn()
    cursor = conn.cursor(dictionary=True)
    
    # Generate or retrieve the user's AES encryption key
    cursor.execute("SELECT encryption_key FROM users WHERE login = %s", (user_login,))
    result = cursor.fetchone()
    
    if result and result['encryption_key']:
        encrypted_aes_key = result['encryption_key']
        aes_key = decrypt_key_for_usage(encrypted_aes_key)
    else:
        aes_key = generate_new_encryption_key()
        encrypted_aes_key = encrypt_key_for_storage(aes_key)
    
    # Encrypt the user's text with the AES key
    encrypted_text = encrypt_data(text_to_encrypt, aes_key)
    encrypted_text_encoded = encode_for_storage(encrypted_text)
    
    # Update the user record with the encrypted text and AES key (encrypted with the master key)
    try:
        cursor.execute("UPDATE users SET encrypted_text = %s, encryption_key = %s WHERE login = %s", 
                       (encrypted_text_encoded, encrypted_aes_key, user_login))
        conn.commit()
    except mysql.connector.Error as err:
        print(f"Failed to save encrypted text: {err}")
        return False
    finally:
        cursor.close()
        conn.close()
    
    return True





def get_decrypted_text(user_login):
    conn = create_conn()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT encrypted_text, encryption_key FROM users WHERE login = %s", (user_login,))
    result = cursor.fetchone()
    
    if not result or 'encrypted_text' not in result or 'encryption_key' not in result:
        print("Encrypted text or encryption key is missing.")
        return None
    
    encrypted_text_encoded = result['encrypted_text']
    encrypted_aes_key = result['encryption_key']
    
    if encrypted_text_encoded and encrypted_aes_key:
        # Decrypt the AES key with the master key
        aes_key = decrypt_key_for_usage(encrypted_aes_key)
        # Decode the encrypted text from storage format
        encrypted_text = decode_for_usage(encrypted_text_encoded)
        # Decrypt the text with the AES key
        decrypted_text = decrypt_data(encrypted_text, aes_key)
        return decrypted_text
    
    return None
