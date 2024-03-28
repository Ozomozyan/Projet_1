from flask import Flask, render_template, request, redirect, url_for, session, flash
import user_management

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for sessions

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_management.login(username, password)
        if user:
            session['user_id'] = user['login']  # Ensure the login attribute is correctly named in your user dictionary
            session['role'] = user['role']  # Ensure the role attribute is correctly named in your user dictionary
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        password = request.form['password']
        success = user_management.register(nom, prenom, password)
        if success:
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/save_text', methods=['POST'])
def save_text():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_login = session['user_id']
    user = user_management.get_user(user_login)
    
    if user is None:
        return "User not found", 404

    if 'encrypted_text' in request.form:
        text_to_encrypt = request.form['encrypted_text']
        # Assume save_encrypted_text function exists and correctly handles the encryption and saving
        success = user_management.save_encrypted_text(user, text_to_encrypt)
        if success:
            flash("Text encrypted and saved successfully.", "success")
        else:
            flash("Failed to save encrypted text.", "error")
    else:
        flash("No text provided.", "error")

    return redirect(url_for('dashboard'))


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_login = session['user_id']
    user = user_management.get_user(user_login)
    
    if user is None:
        return "User not found", 404
    
    decrypted_text = None
    if 'encrypted_text' in request.form:
        # Logic for handling encrypted text submission
        text_to_encrypt = request.form['encrypted_text']
        user_management.save_encrypted_text(user, text_to_encrypt)
        return redirect(url_for('dashboard'))
    else:
        decrypted_text = user_management.get_decrypted_text(user)
    
    return render_template('user_dashboard.html', decrypted_text=decrypted_text)

@app.route('/remove_text', methods=['POST'])
def remove_text():
    if 'user_id' in session:
        user_login = session['user_id']
        user = user_management.get_user(user_login)
        user_management.remove_encrypted_text(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
