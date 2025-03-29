import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import secrets
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv()  # Load .env file



app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# SMTP2GO Configuration (replace with your details)
SMTP2GO_SERVER = "mail.smtp2go.com"
SMTP2GO_PORT = 2525  # Alternatives: 8025, 587, or 25
SMTP2GO_USERNAME = "roommonito"  # Usually your email
SMTP2GO_PASSWORD =os.getenv("SMTP2GO_PASSWORD")  # Securely input API key
FROM_EMAIL = "lnietourret@alumni.unav.es"  # Must match SMTP2GO verified sender

app.config['MAIL_SERVER'] = SMTP2GO_SERVER  # Replace with your SMTP server
app.config['MAIL_PORT'] = SMTP2GO_PORT
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = SMTP2GO_USERNAME 
app.config['MAIL_PASSWORD'] = SMTP2GO_PASSWORD
app.config['MAIL_DEFAULT_SENDER'] = FROM_EMAIL
app.config['VERIFICATION_EXPIRE_DAYS'] = 1
app.config['RESET_TOKEN_EXPIRE_HOURS'] = 1




db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

    # Add this new route
@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    # Get all users from database
    users = User.query.all()
    return render_template('admin_dashboard.html', users=users)

def send_email(to, subject, body):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = to
    
    with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.send_message(msg)

# User model
# Update the User model in main.py
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token = db.Column(db.String(100), unique=True, nullable=True)
    reset_token_expires = db.Column(db.DateTime, nullable=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=app.config['RESET_TOKEN_EXPIRE_HOURS'])
            db.session.commit()
            
            # Send email
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(
                user.email,
                'Password Reset Request',
                f'Click this link to reset your password: {reset_url}\n\n'
                f'This link will expire in {app.config["RESET_TOKEN_EXPIRE_HOURS"]} hours.'
            )
        
        flash('If an account exists with that email, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or user.reset_token_expires < datetime.utcnow():
        flash('Invalid or expired password reset link', 'danger')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user.set_password(password)
        user.reset_token = None
        user.reset_token_expires = None
        db.session.commit()
        
        flash('Your password has been reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)


@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if not user:
        flash('Invalid or expired verification link', 'danger')
        return redirect(url_for('login'))
    
    user.is_verified = True
    user.verification_token = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
@login_required
def index():
    return render_template('index.html', user=current_user)



@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

        # Create new user
        verification_token = secrets.token_urlsafe(32)
        new_user = User(
            username=username, 
            email=email, 
            is_admin=False,
            verification_token=verification_token
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send verification email
        verification_url = url_for('verify_email', token=verification_token, _external=True)
        send_email(
            email,
            'Verify Your Email',
            f'Thank you for registering! Please click this link to verify your email: {verification_url}\n\n'
            f'This link will expire in {app.config["VERIFICATION_EXPIRE_DAYS"]} day(s).'
        )

        flash('Registration successful! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if not user.is_verified:
                flash('Please verify your email before logging in. Check your email for the verification link.', 'danger')
                return redirect(url_for('login'))
            
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Initialize database
def create_tables():
    with app.app_context():
        db.create_all()
        # Create admin user if not exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                is_verified=True  # Admin is automatically verified
            )
            admin.set_password('admin123')  # Change to a secure password
            db.session.add(admin)
            db.session.commit()


    # Add admin user management routes
@app.route('/admin/delete-user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash('You cannot delete your own account', 'danger')
        return redirect(url_for('admin_dashboard'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/edit-user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        is_admin = 'is_admin' in request.form
        
        # Check if username or email already exists (excluding current user)
        if User.query.filter(User.username == username, User.id != user.id).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        
        if User.query.filter(User.email == email, User.id != user.id).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('edit_user', user_id=user_id))
        
        user.username = username
        user.email = email
        user.is_admin = is_admin
        db.session.commit()
        
        flash('User updated successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('edit_user.html', user=user)

if __name__ == '__main__':
    create_tables()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)

