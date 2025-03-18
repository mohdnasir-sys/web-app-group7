from flask import Flask, render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import logging, re, os, time

# Initialize Flask app
app = Flask(__name__)
# Set a secret key for session security
app.secret_key = 'securekey'
# Configure logging to store security events
logging.basicConfig(filename='logs/security.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Make sure the logs directory exists
if not os.path.exists('logs'):
    os.makedirs('logs')

# Used to track failed login attempts
failed_attempts = {}
LOCKOUT_THRESHOLD = 3  # Block login after 3 times failed attempts

# Function to check password strength
def is_strong_password(password):
    return bool(re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&_])[A-Za-z\d@$!%*#?&_]{8,}$', password))
# Users dictionary with admin credentials
users = {'admin': {'password': generate_password_hash('SecurePass123!'), 'role': 'admin'}}

# Function to log user activities
def log_activity(user, action):
    logging.info(f'User: {user}, Action: {action}')

# Function to check if current time is outside working hours
def is_off_hours():
    current_hour = time.localtime().tm_hour
    return current_hour < 9 or current_hour > 18  # Assume work hours are 9 AM - 6 PM

# Route for home page
@app.route('/')
def home():
    return render_template('index.html')

# Route for login functionality
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check for exceeded failed attempts
        if username in failed_attempts and failed_attempts[username] >= LOCKOUT_THRESHOLD:
            flash('Too many failed login attempts. Please try again later.', 'danger')
            return redirect('/login')
        
        # Verify user credentials
        if username in users and check_password_hash(users[username]['password'], password):
            session['user'] = username
            session['role'] = users[username]['role']
            failed_attempts.pop(username, None)  # Reset failed attempts
            log_activity(username, 'Login Successful')
            
            # Log suspicious login outside work hours
            if is_off_hours():
                log_activity(username, 'Suspicious login outside working hours!')
            
            return redirect('/dashboard')
        else:
            # Increment failed login attempts
            failed_attempts[username] = failed_attempts.get(username, 0) + 1
            log_activity(username, 'Failed Login Attempt')
            flash('Invalid login credentials!', 'danger')
    return render_template('login.html')

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Validate password strength
        if not is_strong_password(password):
            flash('Weak password! Must include letters, numbers, minimum 8 characters & special characters.', 'danger')
            return redirect('/register')
        # Store user credentials
        users[username] = {'password': generate_password_hash(password), 'role': 'user'}
        log_activity(username, 'Registered Successfully')
        flash('Account created! Please login.', 'success')
        return redirect('/login')
    return render_template('register.html')

# Route for user dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template('dashboard.html', username=session['user'])

# Route for admin panel access
@app.route('/admin')
def admin_panel():
    if 'user' not in session or session.get('role') != 'admin':
        log_activity(session.get('user', 'Unknown'), 'Unauthorized Admin Access Attempt')
        flash('Access Denied!', 'danger')
        return redirect('/dashboard')
    return "Welcome to Admin Panel!"

# Route for user logout
@app.route('/logout')
def logout():
    user = session.pop('user', None)
    session.pop('role', None)
    log_activity(user, 'Logged Out')
    return redirect('/')

# Input validation to prevent script injection
@app.route('/validate_input', methods=['POST'])
def validate_input():
    user_input = request.form['input']
    if re.search(r'<script.*?>', user_input, re.IGNORECASE):
        flash('Input validation prevents script injection!', 'danger')
        return redirect('/')
    return "Valid Input"

if __name__ == '__main__':
    app.run(debug=True)

