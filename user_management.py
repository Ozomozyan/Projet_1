import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash

# Modify create_conn to use your PythonAnywhere MySQL credentials
def create_conn():
    return mysql.connector.connect(
        host='Esat.mysql.pythonanywhere-services.com',  # Your PythonAnywhere database host
        user='Esat',  # Your PythonAnywhere username
        passwd='C>3Gmt-4_2h3Fp)/',  # Your MySQL password
        database='utilisateurs'  # Your database name
    )

def register(nom, prenom, password):
    conn = None  # Initialize conn to None outside of the try block
    try:
        conn = mysql.connector.connect(
            host='Esat.mysql.pythonanywhere-services.com',
            user='Esat',
            passwd='C>3Gmt-4_2h3Fp)/',
            database='utilisateurs'
        )
        cursor = conn.cursor()
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (nom, prenom, mtp) VALUES (%s, %s, %s)", (nom, prenom, hashed_password))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return False
    finally:
        if conn and conn.is_connected():  # Check if conn is not None and connected before trying to close
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
