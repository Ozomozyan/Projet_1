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

def register(nom, prenom, password):
    try:
        conn = create_conn()
        cursor = conn.cursor()
        hashed_password = generate_password_hash(password)
        cursor.execute("INSERT INTO users (nom, prenom, mtp) VALUES (%s, %s, %s)", (nom, prenom, hashed_password))
        conn.commit()
        return True
    except mysql.connector.Error as err:
        print("Failed to insert user: {}".format(err))
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
