from flask import Flask, render_template, request, redirect, url_for, session
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
            session['user_id'] = user['login']  # Changed from get_login() to ['login']
            session['role'] = user['role']  # Changed from get_role() to ['role']
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password'
    return render_template('login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract registration form data
        nom = request.form['nom']
        prenom = request.form['prenom']
        password = request.form['password']
        # Call your user management system to register user
        success = user_management.register(nom, prenom, password)
        if success:
            return redirect(url_for('login'))
        else:
            # Handle registration error
            pass
    return render_template('register.html')

@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    decrypted_text = None
    user = user_management.get_user(session['user_id'])

    if request.method == 'POST':
        if 'encrypted_text' in request.form:
            # Save or modify the encrypted text
            text_to_encrypt = request.form['encrypted_text']
            user_management.save_encrypted_text(user, text_to_encrypt)
            return redirect(url_for('dashboard'))

    decrypted_text = user_management.get_decrypted_text(user)

    return render_template('user_dashboard.html', decrypted_text=decrypted_text)

@app.route('/remove_text', methods=['POST'])
def remove_text():
    if 'user_id' in session:
        user = user_management.get_user(session['user_id'])
        user_management.remove_encrypted_text(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
