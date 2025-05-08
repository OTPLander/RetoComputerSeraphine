import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify, current_app
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import random # Import random for code generation
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv
import pandas as pd # Import pandas to read Excel files
import sqlalchemy # Import sqlalchemy for inspecting tables
import matplotlib.pyplot as plt

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__, instance_relative_config=True)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
# Configure the database URI. Ensure this matches your main app's config.
# This example uses a SQLite database in the instance folder.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///studyrooms.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False # Recommended to disable this

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
class MiotyData(db.Model):
    __tablename__ = 'mioty_data'

    # Fields directly mapping to the file columns
    # Using String for date and hour as they appear as text in the file
    # Using them as a composite primary key as there is no unique ID in the file
    sample_date = db.Column(db.String, primary_key=True)
    sample_hour = db.Column(db.String, primary_key=True)
    student_id = db.Column(db.Integer, nullable=True) # Student ID can be null
    temperature = db.Column(db.Float, nullable=False) # Temperature has decimal values
    luminosity = db.Column(db.Float, nullable=False) # Luminosity has decimal values
    noise = db.Column(db.Float, nullable=False) # Noise has decimal values

    def __repr__(self):
        return f'<MiotyData {self.sample_date} {self.sample_hour}>'

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
    # Add relationship to ReservationCodes. Creates 'user_rel' on ReservationCodes
    reservation_codes = db.relationship('ReservationCodes', backref='user_rel', lazy=True)

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
    description = db.Column(db.Text) # Corrected typo here

    reservations = db.relationship('Reservation', backref='classroom', lazy=True)
    # Add relationship to ReservationCodes. Creates 'classroom_rel' on ReservationCodes
    reservation_codes = db.relationship('ReservationCodes', backref='classroom_rel', lazy=True)


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


    @property
    def is_active(self):
        """Checks if the reservation's end time is in the future or present."""
        return self.end_time >= datetime.now()

    # ADDED: Explicit relationship to AccessCode. Creates 'access_code_rel' on Reservation
    access_code_rel = db.relationship(
        'ReservationCodes',
        backref='reservation', # This creates a 'reservation' attribute on ReservationCodes instances
        uselist=False,         # One Reservation has one AccessCode
        lazy=True              # Default loading, can be overridden by joinedload
    )


class ReservationCodes(db.Model):
    __tablename__ = 'acces_codes'

    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(2), nullable=False) # The code itself (e.g., "05", "99")

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    reservation_id = db.Column(db.Integer, db.ForeignKey('reservations.id'), unique=True, nullable=False) # Link back to Reservation
    classroom_id = db.Column(db.Integer, db.ForeignKey('classrooms.id'), nullable=False) # Keep this as discussed
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # REMOVED: Explicit relationship definitions for user_rel and classroom_rel
    # These attributes are created automatically by the backref arguments
    # in the relationships defined on the User and Classroom models.
    # user_rel = db.relationship('User')         # REMOVED
    # classroom_rel = db.relationship('Classroom') # REMOVED


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

# MODIFIED: Accept access_code as an argument
def send_reservation_confirmation(user, classroom, reservation, access_code):
    subject = f"Reservation Confirmation for {classroom.name}"
    # MODIFIED: Include the access code in the email body
    body = f"""
Dear {user.username},

Your reservation has been confirmed:

Room: {classroom.name}
Date: {reservation.start_time.strftime('%A, %d %B %Y')}
Time: {reservation.start_time.strftime('%H:%M')} - {reservation.end_time.strftime('%H:%M')}

Your access code for this reservation is: {access_code}

Please use this code to access the room during your reserved time.

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
    # Pass datetime to the template for the date picker min attribute
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
            flash('Invalid date format', 'warning')

        # Query reservations specifically for the selected date and classroom
        reservations_for_date = Reservation.query.filter(
            db.func.date(Reservation.start_time) == selected_date,
            Reservation.classroom_id == classroom_id
        ).all()


        reserved_starts = [
            r.start_time.strftime('%H:%M') for r in reservations_for_date
        ]

        now = datetime.now()
        available_slots = []
        for slot in TIME_SLOTS:
            if slot['start'] not in reserved_starts:
                slot_end_datetime = datetime.strptime(f"{date_str} {slot['end']}", '%Y-%m-%d %H:%M')

                if selected_date == now.date() and slot_end_datetime < now:
                    continue # Skip slots in the past for today
                else:
                    available_slots.append(slot)

        return render_template(
            'reserve.html', # Adjust template name if necessary
            classroom=classroom,
            available_slots=available_slots,
            selected_date=selected_date.strftime('%Y-%m-%d'),
            today=datetime.today().strftime('%Y-%m-%d'),
            datetime=datetime # Pass datetime for potential use in template
        )

    # Handle the POST request (from the AJAX call in the modal)
    elif request.method == 'POST':
        date_str = request.form.get('date')
        time_slot_label = request.form.get('time_slot')

        if not date_str or not time_slot_label:
            return jsonify({'status': 'error', 'message': 'Missing date or time slot'}), 400

        try:
            slot = next((s for s in TIME_SLOTS if s['label'] == time_slot_label), None)

            if not slot:
                return jsonify({'status': 'error', 'message': 'Invalid time slot selected'}), 400

            # Corrected datetime parsing format
            start_time = datetime.strptime(f"{date_str} {slot['start']}", '%Y-%m-%d %H:%M')
            end_time = datetime.strptime(f"{date_str} {slot['end']}", '%Y-%m-%d %H:%M')


            if start_time < datetime.now():
                 return jsonify({'status': 'error', 'message': 'Cannot reserve past time slots'}), 400

            existing = Reservation.query.filter(
                Reservation.classroom_id == classroom_id,
                Reservation.start_time == start_time
            ).first()

            if existing:
                return jsonify({'status': 'error', 'message': 'This time slot is already reserved'}), 409
            else:
                # Create the reservation first
                reservation = Reservation(
                    user_id=current_user.id,
                    classroom_id=classroom_id,
                    start_time=start_time,
                    end_time=end_time
                )
                db.session.add(reservation)
                db.session.commit() # Commit the reservation to get its ID

                # --- NEW: Generate and Store Access Code using ReservationCodes model ---
                # Generate a random two-digit code (00 to 99)
                access_code_value = f"{random.randint(0, 99):02d}"

                # Create a new ReservationCodes record based on the model with user_id and reservation_id
                reservation_code = ReservationCodes( # Use the class name ReservationCodes
                    code=access_code_value,
                    user_id=current_user.id,       # Link to the user making the reservation
                    reservation_id=reservation.id,  # Link to the specific reservation
                    classroom_id=classroom_id, # Linked to classroom
                    created_at=datetime.utcnow() # Added created_at timestamp
                )
                db.session.add(reservation_code) # Add the reservation code to the session
                db.session.commit()        # Commit the reservation code record

                # --- MODIFIED: Call send_reservation_confirmation with the code ---
                send_reservation_confirmation(current_user, classroom, reservation, access_code_value)

                return jsonify({'status': 'success', 'message': 'Reservation successful! Your access code has been sent via email.'})

        except Exception as e:
            app.logger.error(f"Reservation processing error: {str(e)}")
            db.session.rollback() # Rollback changes if an error occurred after any commit
            return jsonify({'status': 'error', 'message': 'An internal error occurred during reservation.'}), 500

    return jsonify({'status': 'error', 'message': 'Method not allowed'}), 405


@app.route('/my-reservations')
@login_required
def my_reservations():
    # Upcoming reservations only
    # Fetch reservations and eagerly load the associated access code to avoid N+1 queries
    # Ensure the relationship name 'access_code_rel' matches the one defined in the Reservation model
    upcoming = Reservation.query.options(db.joinedload(Reservation.access_code_rel)).filter(
        Reservation.user_id == current_user.id,
        Reservation.end_time >= datetime.now()
    ).order_by(Reservation.start_time.asc()).all()

    # Pass datetime to the template for potential use (like copyright year)
    return render_template('my_reservations.html', reservations=upcoming, datetime=datetime)

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
        try:
            # Delete the associated access code directly by query without loading the object.
            # This might bypass the error caused by the missing 'classroom_id' column in the old table schema.
            # Filter by reservation_id, which is in ReservationCodes
            deleted_count = ReservationCodes.query.filter_by(reservation_id=reservation.id).delete()

            # Now delete the reservation itself
            db.session.delete(reservation)

            # Commit both deletions in one transaction
            db.session.commit()

            if deleted_count > 0:
                 app.logger.info(f"Deleted {deleted_count} access code(s) for reservation ID {reservation.id}")

            flash("Reservation canceled", "success")

        except Exception as e:
            # If an error occurs during deletion (including the 'no such column' error
            # if the workaround wasn't successful for some reason), rollback the changes.
            db.session.rollback()
            app.logger.error(f"Error canceling reservation or deleting code: {str(e)}")
            flash("Error canceling reservation", "danger")


    return redirect(url_for('my_reservations'))



# ========== GRAPH GENERATING FUNCTION ==========

# --- Graph Generation Function (Reading from Excel) ---
def generate_and_save_graphs():
    """Generates graphs from Mioty data read directly from an Excel file
       and saves them as static files."""
    global global_graph_urls # Declare that we are using the global variable

    print("Generating and saving graphs from Excel...")

    # Define the path to the Excel file
    # Ensure this path is correct relative to your Flask app's root directory
    excel_file_path = os.path.join(app.root_path, 'datos_inventados_V5.xlsx')

    # Ensure the static/graphs directory exists
    graph_dir = os.path.join(app.static_folder, 'graphs')
    if not os.path.exists(graph_dir):
        os.makedirs(graph_dir)

    graph_urls = {} # Dictionary to store graph URLs for this generation cycle (LOCAL variable)

    try:
        # Read the Excel file into a pandas DataFrame
        print(f"Attempting to read data from {excel_file_path}...")
        df_mioty = pd.read_excel(excel_file_path)
        print("Data read from Excel.")

        # Assuming your Excel columns are named 'Sample Date', 'Sample Hour', 'Student ID', 'Temperature', 'Luminosity', 'Noise'
        # Adjust these names if your Excel columns are different
        required_columns = ['Sample_Date', 'Sample_Hour', 'Student_ID', 'Temp(ºc)   ', 'Light_Level(Lux)', 'Noise_Level(dB)']
        if not all(col in df_mioty.columns for col in required_columns):
            print(f"Error: Excel file must contain the following columns: {required_columns}")
            global_graph_urls = {} # Assign empty dict if columns are missing
            print("Graph generation complete (missing columns).")
            return # Exit if required columns are missing

        if df_mioty.empty:
            print("Excel file is empty or contains no valid data rows.")
            global_graph_urls = {} # Assign empty dict if no data
            print("Graph generation complete (empty file).")
            return # Exit if no data

        # --- Data Cleaning and Preparation (Adjust column names to match Excel) ---
        # Ensure 'Sample Date' is datetime type
        df_mioty['Sample Date'] = pd.to_datetime(df_mioty['Sample Date'], errors='coerce')

        # Ensure 'Sample Hour' is treated as a string before converting to time
        # Handle potential datetime values in Excel by taking the time part
        df_mioty['Sample Hour'] = df_mioty['Sample Hour'].apply(lambda x: str(x).split(' ')[-1] if pd.notna(x) else None)

        # Combine date and hour into a single datetime column for time-based plotting
        # Convert time strings to datetime.time objects first for combining
        # Handle potential errors during time parsing
        df_mioty['Sample Hour_time'] = df_mioty['Sample Hour'].apply(
            lambda x: datetime.strptime(x, '%H:%M:%S').time() if isinstance(x, str) and ':' in x else (
                      datetime.strptime(x, '%H:%M').time() if isinstance(x, str) and ':' in x else None)
            if x is not None else None # Handle None values explicitly
        )

        # Combine date (from Sample Date) and time (from Sample Hour_time) into a single datetime object
        # Use a helper function to combine date and time objects
        def combine_date_time(row):
            if pd.notna(row['Sample Date']) and pd.notna(row['Sample Hour_time']):
                # Ensure row['Sample Hour_time'] is a time object
                if isinstance(row['Sample Hour_time'], time):
                     return datetime.combine(row['Sample Date'], row['Sample Hour_time'])
            return pd.NaT # Return Not a Time if either is missing or time object is invalid

        df_mioty['datetime'] = df_mioty.apply(combine_date_time, axis=1)


        # Drop rows where datetime conversion failed or key columns are missing
        # Include 'Temperature', 'Luminosity', 'Noise' as they are needed for plots
        df_mioty.dropna(subset=['datetime', 'Temperature', 'Luminosity', 'Noise', 'Sample Date', 'Sample Hour', 'StudentID'], inplace=True)


        if df_mioty.empty:
             print("DataFrame is empty after cleaning and creating datetime column.")
             global_graph_urls = {} # Assign an empty dict if data became empty
             print("Graph generation complete (data cleaned to empty).")
             return # Exit if dataframe is empty after cleaning

        # Sort by datetime for time-series plots
        df_mioty.sort_values('datetime', inplace=True)


        # --- Graph 1: Occupancy by Period ---
        try:
            print("Generating Occupancy by Period graph...")
            # Use HH:MM format for period assignment (from Sample Hour)
            df_mioty['Hour_HH_MM'] = df_mioty['Sample Hour'].astype(str).str[:5]

            # Define the periods with a specific order (Ensure these match your requirements)
            periods = [
                {'start': '09:00', 'end': '10:30', 'label': '9:00-10:30'},
                {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
                {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
                {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
                {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
                {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
                {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
            ]
            period_labels = [p['label'] for p in periods]

            # Function to assign a period to each hour string (HH:MM)
            def assign_period(hour_hh_mm_str):
                if not isinstance(hour_hh_mm_str, str):
                    return None # Handle non-string inputs
                # Check if hour_hh_mm_str falls within the period start and end times
                for period in periods:
                    if period['start'] <= hour_hh_mm_str <= period['end']:
                         return period['label']
                return None

            # Create a new column 'Period'
            df_mioty['Period'] = df_mioty['Hour_HH_MM'].apply(assign_period)

            # Convert 'Period' column to a categorical type with the specified order
            df_mioty['Period'] = pd.Categorical(df_mioty['Period'], categories=period_labels, ordered=True)

            # Function to check if a value is numeric for StudentID
            def is_numeric(value):
                try:
                    # Convert to string before trying to float, handles potential None or other types
                    float(str(value))
                    return True
                except (ValueError, TypeError):
                    return False

            # Apply the function to the 'StudentID' column and count the True values (numeric IDs) per period
            # Group by 'Period' and sum the boolean results of is_numeric
            # Use .loc to avoid SettingWithCopyWarning if filtering was done before
            occupancy_by_period_df = df_mioty.loc[df_mioty['Period'].notna()].groupby('Period', observed=False)['StudentID'].apply(lambda x: x.apply(is_numeric).sum()).reset_index(name='numeric_student_id_count')


            # Create a plot
            plt.figure(figsize=(12, 6))
            plt.bar(occupancy_by_period_df['Period'], occupancy_by_period_df['numeric_student_id_count'], color='skyblue') # Added color
            plt.xlabel('Period')
            plt.ylabel('Number of Numeric Student IDs')
            plt.title('Number of Numeric Student IDs by Period')
            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()
            graph_path = os.path.join(graph_dir, 'occupancy_by_period.png')
            plt.savefig(graph_path)
            plt.close()
            graph_urls['occupancy_by_period'] = url_for('static', filename='graphs/occupancy_by_period.png')
            print("Occupancy by Period graph generated.")
        except Exception as e:
            print(f"Error generating Occupancy by Period graph: {e}")
            graph_urls['occupancy_by_period'] = None # Indicate that graph generation failed


        # --- Graph 2: Temperature on 1-May-2025 by Time Frame ---
        try:
            print("Generating Temperature on 1-May-2025 graph...")
            target_date_str = '2025-05-01'
            # Filter DataFrame for the target date
            # Ensure comparison is between date objects
            target_date_obj = datetime.strptime(target_date_str, '%Y-%m-%d').date()
            # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
            filtered_df_temp1 = df_mioty.loc[df_mioty['Sample Date'].apply(lambda x: x == target_date_obj if pd.notna(x) else False)].copy()


            if not filtered_df_temp1.empty:
                # Use the existing 'datetime' column for plotting
                filtered_df_temp1.dropna(subset=['datetime', 'Temperature'], inplace=True) # Drop rows with missing datetime or temperature

                if not filtered_df_temp1.empty:
                     # Sort by datetime again after filtering
                    filtered_df_temp1.sort_values('datetime', inplace=True)

                    # Define time frames (can reuse or redefine if needed)
                    time_frames = [
                        {'start': '09:00', 'end': '10:30', 'label': '09:00-10:30'},
                        {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
                        {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
                        {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
                        {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
                        {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
                        {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
                    ]

                    plt.figure(figsize=(12, 6))

                    previous_end_temp = None
                    previous_end_time = None
                    previous_color = None

                    for i, frame in enumerate(time_frames):
                        # Create time objects from start/end strings for comparison
                        start_time_obj = datetime.strptime(frame['start'], '%H:%M').time()
                        end_time_obj = datetime.strptime(frame['end'], '%H:%M').time()

                        # Filter DataFrame based on the time part of the 'datetime' column
                        # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
                        frame_df = filtered_df_temp1.loc[
                            (filtered_df_temp1['datetime'].dt.time >= start_time_obj) &
                            (filtered_df_temp1['datetime'].dt.time < end_time_obj)
                        ].copy()


                        if not frame_df.empty:
                            color = f'C{i}' # Use default matplotlib colors
                            plt.plot(frame_df['datetime'], frame_df['Temperature'], marker='o', linestyle='-', color=color, label=frame['label'])

                            # Connect the last point of the previous time frame with the first point of the current time frame
                            if previous_end_time is not None and not frame_df.empty:
                                # Ensure the connection point exists in the previous and current frames
                                plt.plot([previous_end_time, frame_df['datetime'].iloc[0]],
                                         [previous_end_temp, frame_df['Temperature'].iloc[0]],
                                         linestyle='-', color=previous_color, alpha=0.7) # Added alpha for visibility


                            # Update previous end points for the next iteration
                            previous_end_temp = frame_df['Temperature'].iloc[-1]
                            previous_end_time = frame_df['datetime'].iloc[-1]
                            previous_color = color
                        else:
                             # If a frame is empty, reset previous end points so no line is drawn to/from it
                             previous_end_temp = None
                             previous_end_time = None
                             previous_color = None


                    plt.title(f'Temperature on {target_date_str} by Time Frame')
                    plt.xlabel('Time of Day')
                    plt.ylabel('Temperature (°C)')
                    plt.grid(True)
                    plt.legend()
                    plt.tight_layout()
                    graph_path = os.path.join(graph_dir, 'temperature_may1_2025.png')
                    plt.savefig(graph_path)
                    plt.close()
                    graph_urls['temperature_may1_2025'] = url_for('static', filename='graphs/temperature_may1_2025.png')
                    print("Temperature on 1-May-2025 graph generated.")

                else:
                    print(f"No valid data for {target_date_str} after dropping missing values.")
                    graph_urls['temperature_may1_2025'] = None

            else:
                 graph_urls['temperature_may1_2025'] = None # Indicate no data for this graph
                 print(f"No data for {target_date_str} to generate temperature graph.")

        except Exception as e:
            print(f"Error generating Temperature on 1-May-2025 graph: {e}")
            graph_urls['temperature_may1_2025'] = None


        # --- Graph 3: Temperature on 5-May-2025 by Time Frame ---
        try:
            print("Generating Temperature on 5-May-2025 graph...")
            target_date_str = '2025-05-05'
            target_date_obj = datetime.strptime(target_date_str, '%Y-%m-%d').date()
            # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
            filtered_df_temp5 = df_mioty.loc[df_mioty['Sample Date'].apply(lambda x: x == target_date_obj if pd.notna(x) else False)].copy()

            if not filtered_df_temp5.empty:
                filtered_df_temp5.dropna(subset=['datetime', 'Temperature'], inplace=True)

                if not filtered_df_temp5.empty:
                    filtered_df_temp5.sort_values('datetime', inplace=True)

                    time_frames = [
                        {'start': '09:00', 'end': '10:30', 'label': '09:00-10:30'},
                        {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
                        {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
                        {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
                        {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
                        {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
                        {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
                    ]

                    plt.figure(figsize=(12, 6))

                    previous_end_temp = None
                    previous_end_time = None
                    previous_color = None

                    for i, frame in enumerate(time_frames):
                        start_time_obj = datetime.strptime(frame['start'], '%H:%M').time()
                        end_time_obj = datetime.strptime(frame['end'], '%H:%M').time()

                        # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
                        frame_df = filtered_df_temp5.loc[
                            (filtered_df_temp5['datetime'].dt.time >= start_time_obj) &
                            (filtered_df_temp5['datetime'].dt.time < end_time_obj)
                        ].copy()

                        if not frame_df.empty:
                            color = f'C{i}'
                            plt.plot(frame_df['datetime'], frame_df['Temperature'], marker='o', linestyle='-', color=color, label=frame['label'])

                            if previous_end_time is not None and not frame_df.empty:
                                plt.plot([previous_end_time, frame_df['datetime'].iloc[0]],
                                         [previous_end_temp, frame_df['Temperature'].iloc[0]],
                                         linestyle='-', color=previous_color, alpha=0.7)

                            previous_end_temp = frame_df['Temperature'].iloc[-1]
                            previous_end_time = frame_df['datetime'].iloc[-1]
                            previous_color = color
                        else:
                             previous_end_temp = None
                             previous_end_time = None
                             previous_color = None


                    plt.title(f'Temperature on {target_date_str} by Time Frame')
                    plt.xlabel('Time of Day')
                    plt.ylabel('Temperature (°C)')
                    plt.grid(True)
                    plt.legend()
                    plt.tight_layout()
                    graph_path = os.path.join(graph_dir, 'temperature_may5_2025.png')
                    plt.savefig(graph_path)
                    plt.close()
                    graph_urls['temperature_may5_2025'] = url_for('static', filename='graphs/temperature_may5_2025.png')
                    print("Temperature on 5-May-2025 graph generated.")
                else:
                    print(f"No valid data for {target_date_str} after dropping missing values.")
                    graph_urls['temperature_may5_2025'] = None

            else:
                graph_urls['temperature_may5_2025'] = None
                print(f"No data for {target_date_str} to generate temperature graph.")

        except Exception as e:
            print(f"Error generating Temperature on 5-May-2025 graph: {e}")
            graph_urls['temperature_may5_2025'] = None


        # --- Graph 4: Luminosity on 9-May-2025 by Time Frame (On/Off) ---
        try:
            print("Generating Luminosity on 9-May-2025 graph...")
            target_date_str = '2025-05-09'
            target_date_obj = datetime.strptime(target_date_str, '%Y-%m-%d').date()
            # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
            filtered_df_lumi = df_mioty.loc[df_mioty['Sample Date'].apply(lambda x: x == target_date_obj if pd.notna(x) else False)].copy()


            if not filtered_df_lumi.empty:
                filtered_df_lumi.dropna(subset=['datetime', 'Luminosity'], inplace=True)

                if not filtered_df_lumi.empty:
                    filtered_df_lumi.sort_values('datetime', inplace=True)

                    time_frames = [
                        {'start': '09:00', 'end': '10:30', 'label': '09:00-10:30'},
                        {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
                        {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
                        {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
                        {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
                        {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
                        {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
                    ]

                    plt.figure(figsize=(12, 6))

                    previous_end_luminosity = None
                    previous_end_time = None
                    previous_color = None


                    for i, frame in enumerate(time_frames):
                        start_time_obj = datetime.strptime(frame['start'], '%H:%M').time()
                        end_time_obj = datetime.strptime(frame['end'], '%H:%M').time()

                        # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
                        frame_df = filtered_df_lumi.loc[
                            (filtered_df_lumi['datetime'].dt.time >= start_time_obj) &
                            (filtered_df_lumi['datetime'].dt.time < end_time_obj)
                        ].copy()


                        if not frame_df.empty:
                             # Apply the 0/1 conversion to 'Luminosity'
                             # Ensure 'Luminosity' is numeric and handle None before comparison
                             frame_df.loc[:, 'Luminosity_Binary'] = frame_df['Luminosity'].apply(lambda x: 1 if pd.notna(x) and x > 100 else 0) # Use 1/0 for plotting

                             color = f'C{i}'
                             plt.plot(frame_df['datetime'], frame_df['Luminosity_Binary'], linestyle='-', color=color, label=frame['label']) # Removed marker='o'

                             if previous_end_time is not None and not frame_df.empty:
                                 plt.plot([previous_end_time, frame_df['datetime'].iloc[0]],
                                          [previous_end_luminosity, frame_df['Luminosity_Binary'].iloc[0]],
                                           linestyle='-', color=previous_color, alpha=0.7)


                             previous_end_luminosity = frame_df['Luminosity_Binary'].iloc[-1]
                             previous_end_time = frame_df['datetime'].iloc[-1]
                             previous_color = color
                        else:
                             previous_end_luminosity = None
                             previous_end_time = None
                             previous_color = None


                    plt.title(f'Luminosity on {target_date_str} by Time Frame (On/Off)')
                    plt.xlabel('Time of Day')
                    plt.ylabel('Luminosity (1=On, 0=Off)') # Updated label
                    plt.yticks([0, 1], ['Off', 'On']) # Set y-ticks for On/Off
                    plt.grid(axis='y', linestyle='--', alpha=0.7)
                    plt.legend()
                    plt.tight_layout()
                    graph_path = os.path.join(graph_dir, 'luminosity_may9_2025.png')
                    plt.savefig(graph_path)
                    plt.close()
                    graph_urls['luminosity_may9_2025'] = url_for('static', filename='graphs/luminosity_may9_2025.png')
                    print("Luminosity on 9-May-2025 graph generated.")
                else:
                    print(f"No valid data for {target_date_str} after dropping missing values.")
                    graph_urls['luminosity_may9_2025'] = None


            else:
                graph_urls['luminosity_may9_2025'] = None # Indicate no data for this graph
                print(f"No data for {target_date_str} to generate luminosity graph.")

        except Exception as e:
            print(f"Error generating Luminosity on 9-May-2025 graph: {e}")
            graph_urls['luminosity_may9_2025'] = None


        # --- Graph 5: Noise on 1-May-2025 by Time Frame ---
        try:
            print("Generating Noise on 1-May-2025 graph...")
            target_date_str = '2025-05-01'
            target_date_obj = datetime.strptime(target_date_str, '%Y-%m-%d').date()
            # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
            filtered_df_noise = df_mioty.loc[df_mioty['Sample Date'].apply(lambda x: x == target_date_obj if pd.notna(x) else False)].copy()


            if not filtered_df_noise.empty:
                filtered_df_noise.dropna(subset=['datetime', 'Noise'], inplace=True)

                if not filtered_df_noise.empty:
                    filtered_df_noise.sort_values('datetime', inplace=True)

                    time_frames = [
                        {'start': '09:00', 'end': '10:30', 'label': '09:00-10:30'},
                        {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
                        {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
                        {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
                        {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
                        {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
                        {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
                    ]

                    plt.figure(figsize=(12, 6))

                    previous_end_noise = None
                    previous_end_time = None
                    previous_color = None


                    for i, frame in enumerate(time_frames):
                        start_time_obj = datetime.strptime(frame['start'], '%H:%M').time()
                        end_time_obj = datetime.strptime(frame['end'], '%H:%M').time()

                        # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
                        frame_df = filtered_df_noise.loc[
                            (filtered_df_noise['datetime'].dt.time >= start_time_obj) &
                            (filtered_df_noise['datetime'].dt.time < end_time_obj)
                        ].copy()

                        if not frame_df.empty:
                            color = f'C{i}'
                            plt.plot(frame_df['datetime'], frame_df['Noise'], marker='o', linestyle='-', color=color, label=frame['label'])

                            if previous_end_time is not None and not frame_df.empty:
                                plt.plot([previous_end_time, frame_df['datetime'].iloc[0]],
                                         [previous_end_noise, frame_df['Noise'].iloc[0]],
                                         linestyle='-', color=previous_color, alpha=0.7)

                            previous_end_noise = frame_df['Noise'].iloc[-1]
                            previous_end_time = frame_df['datetime'].iloc[-1]
                            previous_color = color
                        else:
                             previous_end_noise = None
                             previous_end_time = None
                             previous_color = None


                    plt.title(f'Noise on {target_date_str} by Time Frame')
                    plt.xlabel('Time of Day')
                    plt.ylabel('Noise (dB)') # Assuming Noise is in dB
                    plt.grid(True)
                    plt.legend()
                    plt.tight_layout()
                    graph_path = os.path.join(graph_dir, 'noise_may1_2025.png')
                    plt.savefig(graph_path)
                    plt.close()
                    graph_urls['noise_may1_2025'] = url_for('static', filename='graphs/noise_may1_2025.png')
                    print("Noise on 1-May-2025 graph generated.")
                else:
                    print(f"No valid data for {target_date_str} after dropping missing values.")
                    graph_urls['noise_may1_2025'] = None

            else:
                graph_urls['noise_may1_2025'] = None # Indicate no data for this graph
                print(f"No data for {target_date_str} to generate noise graph.")

        except Exception as e:
            print(f"Error generating Noise on 1-May-2025 graph: {e}")
            graph_urls['noise_may1_2025'] = None


        # --- Graph 6: Average Environmental Factors on 1-May-2025 by Hour ---
        # Note: The notebook code provided only had 5 graphs, but the description mentioned 6.
        # I will implement the 5th graph from the notebook code which is Average Environmental Factors.
        try:
            print("Generating Average Environmental Factors graph...")
            target_date_str = '2025-05-01'
            target_date_obj = datetime.strptime(target_date_str, '%Y-%m-%d').date()
            # Use .loc for label-based indexing and .copy() to avoid SettingWithCopyWarning
            filtered_df_avg = df_mioty.loc[df_mioty['Sample Date'].apply(lambda x: x == target_date_obj if pd.notna(x) else False)].copy()

            if not filtered_df_avg.empty:
                filtered_df_avg.dropna(subset=['datetime', 'Temperature', 'Noise'], inplace=True)

                if not filtered_df_avg.empty:
                    filtered_df_avg['Sample Hour_hour'] = filtered_df_avg['datetime'].dt.hour

                    # Group by 'Sample Hour_hour' and calculate the mean for 'Temperature' and 'Noise'
                    average_df = filtered_df_avg.groupby('Sample Hour_hour')[['Temperature', 'Noise']].mean().reset_index()

                    plt.figure(figsize=(12, 6))

                    # Plot average temperature
                    plt.plot(average_df['Sample Hour_hour'], average_df['Temperature'], marker='o', linestyle='-', color='r', label='Temperature')

                    # Plot average noise
                    plt.plot(average_df['Sample Hour_hour'], average_df['Noise'], marker='o', linestyle='-', color='b', label='Noise')

                    plt.title(f'Average Environmental Factors on {target_date_str} by Hour')
                    plt.xlabel('Hour of Day')
                    plt.ylabel('Average Value')
                    plt.grid(True)
                    plt.legend()
                    plt.xticks(average_df['Sample Hour_hour']) # Ensure all hours are displayed
                    plt.tight_layout()
                    graph_path = os.path.join(graph_dir, 'average_environmental_factors.png')
                    plt.savefig(graph_path)
                    plt.close()
                    graph_urls['average_environmental_factors'] = url_for('static', filename='graphs/average_environmental_factors.png')
                    print("Average Environmental Factors graph generated.")
                else:
                    print(f"No valid data for {target_date_str} after dropping missing values.")
                    graph_urls['average_environmental_factors'] = None

            else:
                 graph_urls['average_environmental_factors'] = None # Indicate no data for this graph
                 print(f"No data for {target_date_str} to generate average environmental factors graph.")

        except Exception as e:
            print(f"Error generating Average Environmental Factors graph: {e}")
            graph_urls['average_environmental_factors'] = None


    except FileNotFoundError:
        print(f"Error: The file {excel_file_path} was not found. Cannot generate graphs.")
        global_graph_urls = {} # Assign empty dict if file not found
    except pd.errors.EmptyDataError:
        print(f"Error: The file {excel_file_path} is empty. Cannot generate graphs.")
        global_graph_urls = {} # Assign empty dict if file is empty
    except Exception as e:
        # Catch any other exceptions during the overall loading/processing
        print(f"An unexpected error occurred during graph generation: {e}")
        global_graph_urls = {} # Assign empty dict on unexpected error


    # Update the global variable with the new URLs
    global_graph_urls = graph_urls
    print("Graph generation complete.")

    # The function does not return graph_urls anymore, it updates the global variable


# ========== ADMIN ROUTES ==========
@app.route('/admin/refresh_graphs', methods=['POST']) # Use POST for actions
@login_required
@admin_required
def refresh_graphs():
    """Regenerates graphs and redirects back to the admin dashboard."""
    generate_and_save_graphs()
    flash('Graphs refreshed successfully!', 'success') # Optional: add a flash message
    return redirect(url_for('admin_dashboard'))



@app.route('/admin/dashboard')
@login_required # Asumiendo que necesitas estar logueado
@admin_required # Asumiendo que solo los administradores pueden acceder
def admin_dashboard():
    """Renderiza el panel de administración con datos de usuarios, aulas, reservas y mensajes Mioty."""
    # Obtiene todos los usuarios de la base de datos
    users = User.query.all()

    # Obtiene todas las aulas de la base de datos
    classrooms = Classroom.query.all()

    # Obtiene todas las reservas, cargando eagermente las relaciones de usuario y aula
    # para evitar consultas adicionales en el template, ordenado por fecha descendente
    reservations = Reservation.query.options(
        db.joinedload(Reservation.user),
        db.joinedload(Reservation.classroom)
    ).order_by(Reservation.start_time.desc()).all()

    # Obtiene todos los datos de la tabla mioty_data, que se rellena con el archivo Excel
    # Ordena los mensajes por sample_date y sample_hour de forma descendente
    page = request.args.get('mioty_page', 1, type=int) # Use a distinct query parameter for Mioty pagination
    per_page = 15 # Define how many Mioty items per page (you can adjust this)

    # Obtiene los datos de la tabla mioty_data con paginación
    # Ordena los mensajes por sample_date y sample_hour de forma descendente
    mioty_data_pagination = MiotyData.query.order_by(
        MiotyData.sample_date.desc(),
        MiotyData.sample_hour.desc()
    ).paginate(page=page, per_page=per_page, error_out=False) # Added error_out=False

    mioty_data_list = mioty_data_pagination.items # Get the items for the current page

    # --- Use the global graph URLs ---
    # Ensure global_graph_urls is populated (it should be called on startup and refresh)
    # Add a check in case it's somehow None (e.g., startup failed)
    current_graph_urls = global_graph_urls 
    # --- End Use Global Graph URLs ---


    # Renderiza la plantilla HTML del panel de administración
    # Pasa los datos obtenidos de las consultas a la plantilla
    return render_template(
        'admin_dashboard.html',
        users=users,         # Lista de objetos User
        classrooms=classrooms, # Lista de objetos Classroom
        reservations=reservations, # Lista de objetos Reservation con user y classroom cargados
        messages=mioty_data_list, # <-- Pass the paginated list of MiotyData objects
        mioty_data_pagination=mioty_data_pagination, # <-- Pass the pagination object for Mioty data
        datetime=datetime,    # Pasa el objeto datetime (opcional si no lo usas mucho en el template)
        graph_urls=current_graph_urls
    )

@app.route('/admin/users')
@login_required
@admin_required
def manage_users():
    users = User.query.order_by(User.username).all()
    return render_template('admin_users.html', users=users, datetime=datetime)

@app.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        is_admin = request.form.get('is_admin') == 'on'

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

    return render_template('edit_user.html', user=user, datetime=datetime)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    if current_user.id == user_id:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('manage_users'))

    user = User.query.get_or_404(user_id)
    try:
        # Delete associated access codes and reservations before deleting the user
        # Filter by user_id in ReservationCodes
        ReservationCodes.query.filter_by(user_id=user.id).delete()
        Reservation.query.filter_by(user_id=user.id).delete()
        db.session.delete(user)
        db.session.commit()
        flash('User and associated data deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting user {user_id}: {str(e)}")
        flash('Error deleting user', 'danger')

    return redirect(url_for('manage_users'))

@app.route('/admin/classrooms')
@login_required
@admin_required
def manage_classrooms():
    classrooms = Classroom.query.order_by(Classroom.name).all()
    return render_template('admin_classrooms.html', classrooms=classrooms, datetime=datetime)

@app.route('/admin/classrooms/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_classroom():
    if request.method == 'POST':
        name = request.form['name']
        try:
            capacity = int(request.form['capacity'])
        except ValueError:
            flash('Capacity must be an integer', 'danger')
            return render_template('admin_add_classroom.html', form_data=request.form, datetime=datetime)

        color = request.form.get('color', '#ff0404')
        description = request.form.get('description', '')

        if Classroom.query.filter_by(name=name).first():
            flash('Classroom name already exists', 'danger')
            return render_template('admin_add_classroom.html', form_data=request.form, datetime=datetime)

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

    return render_template('admin_add_classroom.html', datetime=datetime)

@app.route('/admin/classrooms/edit/<int:classroom_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)

    if request.method == 'POST':
        classroom.name = request.form['name']
        try:
            classroom.capacity = int(request.form['capacity'])
        except ValueError:
            flash('Capacity must be an integer', 'danger')
            return render_template('admin_edit_classroom.html', classroom=classroom, datetime=datetime)

        classroom.color = request.form.get('color', classroom.color)
        classroom.description = request.form.get('description', classroom.description)

        existing = Classroom.query.filter(Classroom.name == classroom.name, Classroom.id != classroom_id).first()
        if existing:
             flash('Classroom name already exists', 'danger')
             return render_template('admin_edit_classroom.html', classroom=classroom, datetime=datetime)

        db.session.commit()
        flash('Classroom updated successfully', 'success')
        return redirect(url_for('manage_classrooms'))

    return render_template('admin_edit_classroom.html', classroom=classroom, datetime=datetime)

@app.route('/admin/classrooms/delete/<int:classroom_id>', methods=['POST'])
@login_required
@admin_required
def delete_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)

    try:
        # Delete all associated access codes before deleting reservations and classroom
        # Filter by classroom_id in ReservationCodes
        # This filter requires classroom_id to be a column in ReservationCodes
        ReservationCodes.query.filter_by(classroom_id=classroom_id).delete()
        Reservation.query.filter_by(classroom_id=classroom_id).delete()
        db.session.delete(classroom)
        db.session.commit()
        flash('Classroom and associated data deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting classroom {classroom_id}: {str(e)}")
        flash('Error deleting classroom', 'danger')

    return redirect(url_for('manage_classrooms'))

# ========== API ROUTES ==========

@app.route('/api/rooms/status')
def rooms_status():
    classrooms = Classroom.query.all()

    total_rooms = len(classrooms)
    occupied_rooms = sum(1 for c in classrooms if c.is_occupied())
    avg_occupancy = round((occupied_rooms / total_rooms) * 100) if total_rooms > 0 else 0

    noise_levels = [c.get_noise_level() for c in classrooms]
    avg_sound_level = round(sum(noise_levels) / len(noise_levels)) if noise_levels else 0

    now = datetime.now().hour
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
    date_str = request.args.get('date', datetime.today().strftime('%Y-%m-%d'))
    try:
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
    except ValueError:
        return jsonify({'error': 'Invalid date format'}), 400

    classroom = Classroom.query.get_or_404(room_id)

    reservations = Reservation.query.filter(
        db.func.date(Reservation.start_time) == selected_date,
        Reservation.classroom_id == room_id
    ).all()

    reserved_starts = [r.start_time.strftime('%H:%M') for r in reservations]

    now = datetime.now()
    available_slots = []
    for slot in TIME_SLOTS:
        if slot['start'] not in reserved_starts:
            slot_end_datetime = datetime.strptime(f"{date_str} {slot['end']}", '%Y-%m-%d %H:%M')

            if selected_date == now.date() and slot_end_datetime < now:
                continue # Skip slots in the past for today
            else:
                available_slots.append(slot)

    return jsonify({
        'is_occupied': classroom.is_occupied(),
        'available_slots': available_slots,
        'capacity': classroom.capacity,
        'description': classroom.description,
        'name': classroom.name
    })

# ========== INITIALIZATION ==========

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_tables():
    """Creates all database tables, dropping mioty_data if it exists."""
    with app.app_context():
        # Use inspector to check if the mioty_data table exists
        inspector = sqlalchemy.inspect(db.engine)
        if 'mioty_data' in inspector.get_table_names():
            print("Dropping existing 'mioty_data' table...")
            # Drop the table
            MiotyData.__table__.drop(db.engine)
            print("'mioty_data' table dropped.")

        # This will create all tables defined in your models,
        # including the newly dropped and recreated mioty_data table
        db.create_all()
        print("Database tables created (or recreated for mioty_data).")

        # Create admin user if none exists
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                is_verified=True
            )
            admin.set_password('admin123')
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
                {'name': 'Joule', 'capacity': 10, 'color': '#795548'}, # Corrected typo 'Joule'
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


# --- Function to load data from Excel ---
def load_data_from_excel():
    """Loads data from datos_inventados_V5.xlsx and populates the MiotyData table."""
    # Construct the path to the Excel file in the instance folder
    excel_file_path = os.path.join(app.instance_path, 'datos_inventados_V5.xlsx')
    print(f"Attempting to load data from: {excel_file_path}")

    # Check if the Excel file exists
    if not os.path.exists(excel_file_path):
        print(f"Error: File not found at {excel_file_path}")
        print("Please ensure 'datos_inventados_V5.xlsx' is in the 'instance' folder.")
        return

    try:
        # Read the Excel file into a pandas DataFrame
        # Assuming the first sheet contains the data.
        # Use 'decimal=',' to handle comma decimal separators if present in the file
        df = pd.read_excel(excel_file_path, decimal=',')

        # Clean column names: remove leading/trailing spaces and special characters if any
        # This makes column access more reliable
        df.columns = df.columns.str.strip().str.replace('[^A-Za-z0-9_]+', '', regex=True)

        # --- DEBUGGING: Print the column names after cleaning ---
        # This output is crucial for verifying the column names pandas is using
        print("DataFrame columns after cleaning:", df.columns.tolist())
        # ---------------------------------------------------------

        # Prepare data for bulk insertion
        data_to_add = []
        # Iterate through DataFrame rows
        for index, row in df.iterrows():
            try:
                # --- Handle 'Student ID' column specifically ---
                # Get the value from the 'StudentID' column after cleaning
                student_id_value = row.get('Student_ID', None)

                # Explicitly check if the value is the string '---' or pandas NaN
                if isinstance(student_id_value, str) and student_id_value.strip() == '---':
                    processed_student_id = None # Treat "---" as None
                elif pd.isna(student_id_value):
                    processed_student_id = None # Treat pandas NaN as None
                else:
                    # Attempt to convert to integer, handle potential errors
                    try:
                        processed_student_id = int(student_id_value)
                        print(f"{processed_student_id}")
                    except (ValueError, TypeError):
                        # If conversion fails (e.g., unexpected non-numeric string), treat as None
                        print(f"Warning: Could not convert StudentID value '{student_id_value}' to integer in row {index}. Setting to None.")
                        processed_student_id = None
                # -----------------------------------------------

                if str(row.get('Sample_Date', '')).endswith(' 00:00:00'):
                    date_str = str(row.get('Sample_Date', '')).replace(' 00:00:00', '')
                


                # Create MiotyData object for each row
                # Use .get() with a default value (like None) for other columns
                # to handle potential missing columns more gracefully.
                data_entry = MiotyData(
                    # Ensure string format and strip whitespace for date and hour
                    sample_date=date_str,
                    sample_hour=str(row.get('Sample_Hour', '')).strip(),
                    student_id=processed_student_id, # Use the processed student_id
                    temperature=row.get('Tempc', None),
                    luminosity=row.get('Light_LevelLux', None),
                    noise=row.get('Noise_LeveldB', None)
                )
                data_to_add.append(data_entry)
            except KeyError as e:
                # This catch block helps identify exactly which column is missing if .get() wasn't used or failed
                print(f"Error processing row {index}: Missing expected column {e}. Row data: {row.to_dict()}")
                # Decide how to handle rows with missing data: skip, log, etc.
                continue # Skip this row if a required column is missing
            except Exception as e:
                # Catch any other unexpected errors during object creation
                print(f"Error creating MiotyData object for row {index}: {e}. Row data: {row.to_dict()}")
                continue # Skip row on other errors

        # Use app.app_context() to perform database operations
        with app.app_context():
            # Check if the table is already populated before adding data
            # This check is less critical now that the table is dropped on each run,
            # but it's a good practice if you remove the drop table logic later.
            if MiotyData.query.first() is None:
                print(f"Adding {len(data_to_add)} records to the database.")
                # Use bulk_save_objects for efficient insertion of multiple records
                db.session.bulk_save_objects(data_to_add)
                db.session.commit() # Commit the transaction to save data
                print("Data successfully loaded into the database.")
            else:
                print("Database table 'mioty_data' is already populated. Skipping data load.")


    except FileNotFoundError:
        print(f"Error: The file {excel_file_path} was not found.")
    except pd.errors.EmptyDataError:
        print(f"Error: The file {excel_file_path} is empty.")
    except Exception as e:
        # Catch any other exceptions during the overall loading process
        print(f"An error occurred during data loading: {e}")


# --- Main execution block ---
if __name__ == '__main__':
    # Ensure the instance folder exists
    if not os.path.exists(app.instance_path):
        os.makedirs(app.instance_path)
        print(f"Created instance folder: {app.instance_path}")

    create_tables() # This will now drop and recreate mioty_data
    load_data_from_excel()
    generate_and_save_graphs() # Load data into the (newly created) mioty_data table

    # Iniciar aplicación Flask
    with app.app_context():
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)

