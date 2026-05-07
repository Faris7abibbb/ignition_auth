from flask import Flask, render_template, request, redirect, url_for
from extensions import db, bcrypt
from models import User
from security_logger import log_security_event

# 1. Initialize the Application
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ignition-super-secret-dev-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ignition.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# 2. Bind Extensions to the App
db.init_app(app)
bcrypt.init_app(app)

# --- ROUTES ---

@app.route('/')
def home():
    return "<h1>Ignition Auth Engine is Online.</h1><p>Awaiting telemetry integration...</p>"

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')

        # SECURITY CHECK 1: Does this email already exist?
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            log_security_event(
                event_type="REGISTRATION_FAILED", 
                message="Attempt to register with existing email", 
                source_ip=request.remote_addr, 
                target_user=email
            )
            return "Error: Identity already exists."

        # CRYPTOGRAPHY: Hash the password
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        # DATABASE: Create the new user
        new_user = User(username=username, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        # FIRE TELEMETRY
        log_security_event(
            event_type="USER_REGISTERED", 
            message="New identity initialized", 
            source_ip=request.remote_addr, 
            target_user=email
        )
        
        return redirect(url_for('home'))

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)