from flask import Flask, render_template, request, redirect, url_for, session, flash
import user_management
from flask import jsonify
from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField
from wtforms.validators import DataRequired
from werkzeug.security import check_password_hash
import user_management  # Ensure this module is correctly implemented and imported


app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a real secret key for production
from flask_wtf.csrf import CSRFProtect
csrf = CSRFProtect(app)
csrf.init_app(app)  # This initializes CSRF protection for your app

class DeleteAccountForm(FlaskForm):
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Delete My Account')

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

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        flash("You need to login to update your profile.", "error")
        return redirect(url_for('login'))

    nom = request.form['nom']
    prenom = request.form['prenom']
    password = request.form['password']  # Can be empty if the user doesn't want to change the password

    success = user_management.update_user_profile(session['user_id'], nom, prenom, password)
    if success:
        flash("Your profile was updated successfully.", "success")
    else:
        flash("Failed to update your profile.", "error")

    return redirect(url_for('dashboard'))

@app.route('/admin/update_user_role', methods=['POST'])
def update_user_role():
    if 'user_id' in session and session['role'] == 'admin':
        data = request.get_json()
        login = data.get('login')
        new_role = data.get('role')
        
        if user_management.admin_update_user_info(login=login, role=new_role):
            return jsonify({"success": "Role updated successfully", "login": login, "new_role": new_role}), 200
        else:
            return jsonify({"error": "Failed to update user role."}), 500
    else:
        return jsonify({"error": "Unauthorized."}), 403

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    form = DeleteAccountForm()
    if form.validate_on_submit():
        user_login = session['user_id']
        user = user_management.get_user(user_login)
        if user and check_password_hash(user['mtp'], form.password.data):
            success = user_management.delete_user_account(user_login)
            if success:
                session.clear()  # Clear the session after account deletion
                flash('Your account has been successfully deleted.', 'success')
                return redirect(url_for('home'))
            else:
                flash('Failed to delete your account.', 'error')
        else:
            flash('Incorrect password.', 'error')
    return render_template('delete_account.html', form=form)


@app.route('/admin_dashboard', methods=['GET'])
def admin_dashboard():
    if 'user_id' in session and session['role'] == 'admin':
        users = user_management.fetch_all_users()  # Implement this if not already done
        return render_template('admin_dashboard.html', users=users)
    else:
        flash("Unauthorized access.", "error")
        return redirect(url_for('dashboard'))



@app.route('/admin/update_user_info', methods=['POST'])
def admin_update_user_info():
    # Ensure the request has JSON content
    if not request.is_json:
        return jsonify({'error': 'Request must be JSON'}), 400

    data = request.get_json()

    # Use .get() to avoid KeyError and provide a default value
    login = data.get('login')
    if not login:
        return jsonify({'error': 'Missing login'}), 400

    # Process other fieldss
    nom = data.get('nom')
    prenom = data.get('prenom')

    # Call your function to update user info in the database
    success = user_management.admin_update_user_info(login=login, nom=nom, prenom=prenom)

    if success:
        return jsonify({'success': 'User info updated successfully'}), 200
    else:
        return jsonify({'error': 'Failed to update user info'}), 500
    
@app.route('/api/users')
def get_users():
    if 'user_id' in session and session['role'] == 'admin':
        users = user_management.fetch_all_users()
        return jsonify(users)
    else:
        return jsonify({"error": "Unauthorized access"}), 403



@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)