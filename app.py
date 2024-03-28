from flask import Flask, render_template, request, redirect, url_for, session, flash
import user_management

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key for production

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = user_management.login(username, password)
        if user:
            session['user_id'] = user['login']  # Ensure correct attribute names
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        password = request.form['password']
        if user_management.register(nom, prenom, password):
            flash('Registration successful. Please login.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed.', 'error')
    return render_template('register.html')

@app.route('/save_text', methods=['POST'])
def save_text():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    text_to_encrypt = request.form.get('encrypted_text')
    if text_to_encrypt:
        user_login = session['user_id']
        if user_management.save_encrypted_text(user_login, text_to_encrypt):
            flash("Text encrypted and saved successfully.", "success")
        else:
            flash("Failed to save encrypted text.", "error")
    else:
        flash("No text provided.", "error")
    return redirect(url_for('dashboard'))

@app.route('/dashboard', methods=['GET'])
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_login = session['user_id']
    decrypted_text = user_management.get_decrypted_text(user_login)
    return render_template('user_dashboard.html', decrypted_text=decrypted_text)

@app.route('/remove_text', methods=['POST'])
def web_remove_text():
    if 'user_id' not in session:
        # Redirect the user to login page if not logged in
        return redirect(url_for('login'))

    user_login = session['user_id']
    success = user_management.remove_encrypted_text(user_login)
    if success:
        flash("Encrypted text removed successfully.", "success")
    else:
        flash("Failed to remove encrypted text.", "error")
    
    return redirect(url_for('dashboard'))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
