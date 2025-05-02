import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///studyrooms.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = "mail.smtp2go.com"
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "roommonito"
app.config['MAIL_PASSWORD'] = os.getenv("SMTP2GO_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = "lnietourret@alumni.unav.es"
app.config['VERIFICATION_EXPIRE_DAYS'] = 1
app.config['RESET_TOKEN_EXPIRE_HOURS'] = 1

# Time slots configuration
TIME_SLOTS = [
    {'start': '09:00', 'end': '10:30', 'label': '9:00-10:30'},
    {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
    {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
    {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
    {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
    {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
    {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
]

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ========== MODELS ==========

class User(UserMixin, db.Model):
    __tablename__ = 'users'

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

    reservations = db.relationship('Reservation', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Classroom(db.Model):
    __tablename__ = 'classrooms'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    color = db.Column(db.String(20), default='#ff0404')
    description = db.Column(db.Text)

    reservations = db.relationship('Reservation', backref='classroom', lazy=True)

    def is_occupied(self):
        now = datetime.now()
        return db.session.query(
            Reservation.query.filter(
                Reservation.classroom_id == self.id,
                Reservation.start_time <= now,
                Reservation.end_time >= now
            ).exists()
        ).scalar()

    def get_noise_level(self):
        base = 30  # dB minimum
        if self.is_occupied():
            return min(90, base + secrets.randbelow(40))
        return base + secrets.randbelow(10)

    def reservations_today_count(self):
        today = datetime.today().date()
        return Reservation.query.filter(
            db.func.date(Reservation.start_time) == today,
            Reservation.classroom_id == self.id
        ).count()

    def occupancy_rate(self):
        total_slots = len(TIME_SLOTS) * 7
        reserved_slots = Reservation.query.filter(
            Reservation.classroom_id == self.id,
            Reservation.start_time >= datetime.now() - timedelta(days=7)
        ).count()
        return round((reserved_slots / total_slots) * 100) if total_slots > 0 else 0

class Reservation(db.Model):
    __tablename__ = 'reservations'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classrooms.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Add this new property
    @property
    def is_active(self):
        """Checks if the reservation's end time is in the future or present."""
        return self.end_time >= datetime.now()

    # reservations = db.relationship('Reservation', backref='user', lazy=True) # This line might exist already
    # user = db.relationship('User', backref='reservations') # This line might exist already
    # classroom = db.relationship('Classroom', backref='reservations') # This line might exist already

# ... rest of your main.py

# ========== HELPER FUNCTIONS ==========

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def send_email(to, subject, body):
    try:
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_DEFAULT_SENDER']
        msg['To'] = to

        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email sending failed: {str(e)}")
        return False

def send_reservation_confirmation(user, classroom, reservation):
    subject = f"Reservation Confirmation for {classroom.name}"
    body = f"""
Dear {user.username},

Your reservation has been confirmed:

Room: {classroom.name}
Date: {reservation.start_time.strftime('%A, %d %B %Y')}
Time: {reservation.start_time.strftime('%H:%M')} - {reservation.end_time.strftime('%H:%M')}

Thank you for using the Study Room Monitor system.
"""
    send_email(user.email, subject, body)

# ========== AUTH ROUTES ==========

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
                flash('Please verify your email before logging in', 'danger')
                return redirect(url_for('login'))

            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))

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

        verification_url = url_for('verify_email', token=verification_token, _external=True)
        send_email(
            email,
            'Verify Your Email',
            f'Click this link to verify your email: {verification_url}\n\n'
            f'This link expires in {app.config["VERIFICATION_EXPIRE_DAYS"]} day(s).'
        )

        flash('Registration successful! Please check your email.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()

    if not user:
        flash('Invalid verification link', 'danger')
        return redirect(url_for('login'))

    user.is_verified = True
    user.verification_token = None
    db.session.commit()

    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()

        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expires = datetime.utcnow() + timedelta(hours=app.config['RESET_TOKEN_EXPIRE_HOURS'])
            db.session.commit()

            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(
                email,
                'Password Reset Request',
                f'Click this link to reset your password: {reset_url}\n\n'
                f'This link expires in {app.config["RESET_TOKEN_EXPIRE_HOURS"]} hours.'
            )

        flash('If an account exists with this email, a reset link has been sent', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()

    if not user or user.reset_token_expires < datetime.utcnow():
        flash('Invalid or expired reset link', 'danger')
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

        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)

# ========== MAIN APPLICATION ROUTES ==========

@app.route('/')
@login_required
def index():
    classrooms = Classroom.query.all()
    return render_template('index.html', classrooms=classrooms, datetime=datetime)

# --- MODIFIED RESERVE ROUTE FOR AJAX ---
@app.route('/reserve/<int:classroom_id>', methods=['GET', 'POST'])
@login_required
def reserve(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)

    # Handle the GET request (might be used for direct page access or errors)
    if request.method == 'GET':
        date_str = request.args.get('date', datetime.today().strftime('%Y-%m-%d'))

        try:
            selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            selected_date = datetime.today().date()
            # Flash messages won't typically appear for AJAX POST responses,
            # but kept here for the GET case.
            flash('Invalid date format', 'warning')

        # Get available slots for selected date for rendering the template
        reserved_slots = [
            r.start_time.strftime('%H:%M')
            for r in classroom.reservations
            if r.start_time.date() == selected_date
        ]
        available_slots = [
            slot for slot in TIME_SLOTS
            if slot['start'] not in reserved_slots
        ]

        # You might need a dedicated 'reserve.html' template,
        # or ensure index.html can handle displaying the correct info
        # if accessed directly via this GET route.
        return render_template(
            'reserve.html', # Adjust template name if necessary
            classroom=classroom,
            available_slots=available_slots,
            selected_date=selected_date.strftime('%Y-%m-%d'),
            today=datetime.today().strftime('%Y-%m-%d')
        )

    # Handle the POST request (from the AJAX call in the modal)
    elif request.method == 'POST':
        date_str = request.form.get('date')
        time_slot_label = request.form.get('time_slot')

        # Basic validation for required data
        if not date_str or not time_slot_label:
            # Return JSON error response with status code
            return jsonify({'status': 'error', 'message': 'Missing date or time slot'}), 400 # Bad Request

        try:
            # Find the corresponding time slot configuration
            slot = next((s for s in TIME_SLOTS if s['label'] == time_slot_label), None)

            if not slot:
                # Return JSON error if the provided time slot label is not found
                return jsonify({'status': 'error', 'message': 'Invalid time slot selected'}), 400 # Bad Request

            # Construct datetime objects for the reservation start and end times
            start_time = datetime.strptime(f"{date_str} {slot['start']}", '%Y-%m-%d %H:%M')
            end_time = datetime.strptime(f"{date_str} {slot['end']}", '%Y-%m-%d %H:%M')

            # Ensure reservation is not in the past
            if start_time < datetime.now():
                 return jsonify({'status': 'error', 'message': 'Cannot reserve past time slots'}), 400

            # Check if the time slot is already reserved for this classroom
            existing = Reservation.query.filter(
                Reservation.classroom_id == classroom_id,
                Reservation.start_time == start_time
            ).first()

            if existing:
                # Return JSON error if the slot is already taken (Conflict)
                return jsonify({'status': 'error', 'message': 'This time slot is already reserved'}), 409 # Conflict
            else:
                # Create a new reservation object
                reservation = Reservation(
                    user_id=current_user.id,
                    classroom_id=classroom_id,
                    start_time=start_time,
                    end_time=end_time
                )
                db.session.add(reservation) # Add to the database session
                db.session.commit()        # Commit the transaction

                # Send the reservation confirmation email
                send_reservation_confirmation(current_user, classroom, reservation)

                # Return JSON success response
                return jsonify({'status': 'success', 'message': 'Reservation successful!'})

        except Exception as e:
            # Log the error for debugging
            app.logger.error(f"Reservation processing error: {str(e)}")
            # Return a generic JSON error response for unexpected issues
            return jsonify({'status': 'error', 'message': 'An internal error occurred during reservation.'}), 500 # Internal Server Error

    # Return Method Not Allowed for any other HTTP methods
    return jsonify({'status': 'error', 'message': 'Method not allowed'}), 405 # Method Not Allowed


@app.route('/my-reservations')
@login_required
def my_reservations():
    # Upcoming reservations
    upcoming = Reservation.query.filter(
        Reservation.user_id == current_user.id,
        Reservation.end_time >= datetime.now()
    ).order_by(Reservation.start_time.asc()).all()

    # Past reservations (last 30 days)
    past = Reservation.query.filter(
        Reservation.user_id == current_user.id,
        Reservation.end_time < datetime.now(),
        Reservation.start_time > datetime.now() - timedelta(days=30)
    ).order_by(Reservation.start_time.desc()).all()

    return render_template('my_reservations.html', reservations=upcoming + past)

@app.route('/cancel-reservation/<int:reservation_id>', methods=['POST'])
@login_required
def cancel_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)

    # Verify user owns the reservation or is an admin
    if reservation.user_id != current_user.id and not current_user.is_admin:
        abort(403) # Forbidden

    # Don't allow canceling past reservations
    if reservation.end_time < datetime.now():
        flash("Cannot cancel past reservations", "warning")
    else:
        db.session.delete(reservation)
        db.session.commit()
        flash("Reservation canceled", "success")

    return redirect(url_for('my_reservations'))

# ========== ADMIN ROUTES ==========

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = User.query.all()
    classrooms = Classroom.query.all()
    return render_template('admin_dashboard.html', users=users, classrooms=classrooms)

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        # Use request.form.get to safely check checkbox presence
        is_admin = request.form.get('is_admin') == 'on'

        # Check for conflicts
        if User.query.filter(User.username == username, User.id != user.id).first():
            flash('Username already taken', 'danger')
        elif User.query.filter(User.email == email, User.id != user.id).first():
            flash('Email already registered', 'danger')
        else:
            user.username = username
            user.email = email
            user.is_admin = is_admin
            db.session.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('manage_users'))

    return render_template('admin_edit_user.html', user=user)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    # Prevent admin from deleting their own account
    if current_user.id == user_id:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/classrooms')
@login_required
@admin_required
def manage_classrooms():
    classrooms = Classroom.query.order_by(Classroom.name).all()
    return render_template('admin_classrooms.html', classrooms=classrooms)

@app.route('/admin/classrooms/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_classroom():
    if request.method == 'POST':
        name = request.form['name']
        # Use a try-except block for type conversion
        try:
            capacity = int(request.form['capacity'])
        except ValueError:
            flash('Capacity must be an integer', 'danger')
            return render_template('admin_add_classroom.html', form_data=request.form) # Preserve form data

        color = request.form.get('color', '#ff0404')
        description = request.form.get('description', '')

        if Classroom.query.filter_by(name=name).first():
            flash('Classroom name already exists', 'danger')
            return render_template('admin_add_classroom.html', form_data=request.form)

        classroom = Classroom(
            name=name,
            capacity=capacity,
            color=color,
            description=description
        )
        db.session.add(classroom)
        db.session.commit()
        flash('Classroom added successfully', 'success')
        return redirect(url_for('manage_classrooms'))

    return render_template('admin_add_classroom.html')

@app.route('/admin/classrooms/edit/<int:classroom_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)

    if request.method == 'POST':
        classroom.name = request.form['name']
        # Use try-except for capacity conversion
        try:
            classroom.capacity = int(request.form['capacity'])
        except ValueError:
            flash('Capacity must be an integer', 'danger')
            return render_template('admin_edit_classroom.html', classroom=classroom) # Render with existing data

        classroom.color = request.form.get('color', classroom.color)
        classroom.description = request.form.get('description', classroom.description)

        # Optional: Check for name conflict if name is changed
        existing = Classroom.query.filter(Classroom.name == classroom.name, Classroom.id != classroom_id).first()
        if existing:
             flash('Classroom name already exists', 'danger')
             return render_template('admin_edit_classroom.html', classroom=classroom)

        db.session.commit()
        flash('Classroom updated successfully', 'success')
        return redirect(url_for('manage_classrooms'))

    return render_template('admin_edit_classroom.html', classroom=classroom)

@app.route('/admin/classrooms/delete/<int:classroom_id>', methods=['POST'])
@login_required
@admin_required
def delete_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)

    # Delete all reservations associated with this classroom
    Reservation.query.filter_by(classroom_id=classroom_id).delete()
    db.session.delete(classroom)
    db.session.commit()

    flash('Classroom deleted successfully', 'success')
    return redirect(url_for('manage_classrooms'))

# ========== API ROUTES ==========

@app.route('/api/rooms/status')
def rooms_status():
    classrooms = Classroom.query.all()

    total_rooms = len(classrooms)
    occupied_rooms = sum(1 for c in classrooms if c.is_occupied())
    # Avoid division by zero
    avg_occupancy = round((occupied_rooms / total_rooms) * 100) if total_rooms > 0 else 0

    noise_levels = [c.get_noise_level() for c in classrooms]
     # Avoid division by zero
    avg_sound_level = round(sum(noise_levels) / len(noise_levels)) if noise_levels else 0

    # Calculate peak hours (simplified)
    now = datetime.now().hour
    # Example logic: Consider peak during morning/afternoon
    peak_hours = 18 if (9 <= now <= 11 or 15 <= now <= 17) else 12


    return jsonify({
        'avg_occupancy': avg_occupancy,
        'avg_sound_level': avg_sound_level,
        'peak_hours': peak_hours,
        'rooms': [
            {
                'id': c.id,
                'name': c.name,
                'is_occupied': c.is_occupied(),
                'noise_level': c.get_noise_level()
            }
            for c in classrooms
        ]
    })

@app.route('/api/room/<int:room_id>/availability')
@login_required
def room_availability(room_id):
    # Use request.args.get with a default to avoid errors if date is missing
    date_str = request.args.get('date', datetime.today().strftime('%Y-%m-%d'))
    try:
        date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        # Return error if date format is invalid
        return jsonify({'error': 'Invalid date format'}), 400

    classroom = Classroom.query.get_or_404(room_id)

    # Get reservations for the specific date and classroom
    reservations = Reservation.query.filter(
        db.func.date(Reservation.start_time) == date,
        Reservation.classroom_id == room_id
    ).all()

    # Extract start times of reserved slots
    reserved_starts = [r.start_time.strftime('%H:%M') for r in reservations]

    # Determine available slots by comparing with all time slots
    available_slots = [slot for slot in TIME_SLOTS if slot['start'] not in reserved_starts]

    return jsonify({
        'is_occupied': classroom.is_occupied(), # Note: This checks current occupancy, not occupancy for the selected date
        'available_slots': available_slots,
        'capacity': classroom.capacity,
        'description': classroom.description,
        'name': classroom.name # Added classroom name for potential use in modal
    })

# ========== INITIALIZATION ==========

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_tables():
    with app.app_context():
        db.create_all()

        # Create admin user if none exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                is_verified=True # Auto-verify admin
            )
            admin.set_password('admin123') # IMPORTANT: Change this default password!
            db.session.add(admin)

        # Create default classrooms if none exist
        if not Classroom.query.first():
            classrooms_data = [
                {'name': 'Edison', 'capacity': 15, 'color': '#ff0404'},
                {'name': 'Galileo', 'capacity': 20, 'color': '#000000'},
                {'name': 'Gutenberg', 'capacity': 12, 'color': '#4CAF50'},
                {'name': 'Marconi', 'capacity': 18, 'color': '#2196F3'},
                {'name': 'Nobel', 'capacity': 10, 'color': '#9C27B0'},
                {'name': 'Elhuyar', 'capacity': 15, 'color': '#FF9800'},
                {'name': 'Gauss', 'capacity': 12, 'color': '#607D8B'},
                {'name': 'Joule', 'capacity': 10, 'color': '#795548'},
                {'name': 'Marie Curie', 'capacity': 15, 'color': '#E91E63'},
                {'name': 'Newton', 'capacity': 20, 'color': '#3F51B5'}
            ]

            for room_data in classrooms_data:
                classroom = Classroom(
                    name=room_data['name'],
                    capacity=room_data['capacity'],
                    color=room_data['color'],
                    description=f"The {room_data['name']} Room is equipped for optimal study conditions."
                )
                db.session.add(classroom)

        db.session.commit()

if __name__ == '__main__':
    create_tables() # Ensure tables and initial data exist
    # Debug=True should only be used during development
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)