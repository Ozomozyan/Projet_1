import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

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
