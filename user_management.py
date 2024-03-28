import mysql.connector
import pyaes
from werkzeug.security import generate_password_hash, check_password_hash
import base64
import os

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


def generate_new_encryption_key(key_length=32):
    """Generate a new AES encryption key."""
    return os.urandom(key_length)

def encode_for_storage(data):
    """Encode binary data using Base64 for database storage."""
    return base64.b64encode(data).decode('utf-8')

def decode_for_usage(encoded_data):
    """Decode Base64-encoded data back into binary form for usage."""
    return base64.b64decode(encoded_data.encode('utf-8'))

def secure_store_key(user_login, encryption_key):
    """Securely store the encryption key.
    
    Implement according to your security requirements. This could involve encrypting
    the key itself with a master key, using a dedicated key management service, etc.
    """
    # Placeholder for secure encryption key storage logic
    pass

def save_encrypted_text(user, text_to_encrypt):
    if user and 'login' in user:
        login = user['login']
        # Generate a new encryption key if necessary and securely store it
        encryption_key = user.get('encryption_key')
        if encryption_key is None:
            encryption_key = generate_new_encryption_key()
            secure_store_key(login, encryption_key)  # Securely store the new key
            user['encryption_key'] = encode_for_storage(encryption_key)  # Store encoded key for session usage
        
        # Encrypt the text and encode both the encrypted text and key for database storage
        encrypted_text = encrypt_data(text_to_encrypt, decode_for_usage(user['encryption_key']))
        encrypted_text_encoded = encode_for_storage(encrypted_text)
        
        try:
            conn = create_conn()
            cursor = conn.cursor()
            # Update the database with the encoded encrypted text (and potentially the encoded key)
            cursor.execute("UPDATE users SET encrypted_text = %s WHERE login = %s", 
                           (encrypted_text_encoded, login))
            conn.commit()
            return True
        except mysql.connector.Error as err:
            print(f"Failed to save encrypted text: {err}")
            return False
        finally:
            cursor.close()
            conn.close()
    return False




def get_decrypted_text(user):
    encrypted_text = user.get('encrypted_text')
    encryption_key = user.get('encryption_key')
    
    # Check if either the encrypted text or the encryption key is None
    if encrypted_text is None or encryption_key is None:
        print("Encrypted text or encryption key is missing.")
        return None

    try:
        decrypted_text = decrypt_data(encrypted_text, encryption_key)
        return decrypted_text
    except Exception as e:
        print(f"Error decrypting text: {e}")
        return None
