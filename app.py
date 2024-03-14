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
            session['user_id'] = user.get_login()
            session['role'] = user.get_role()
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

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # Display different dashboard based on role
    if session['role'] == 'admin':
        return render_template('admin_dashboard.html')
    else:
        # Assume a simple user dashboard for demonstration
        return 'User Dashboard - <a href="/logout">Logout</a>'

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
