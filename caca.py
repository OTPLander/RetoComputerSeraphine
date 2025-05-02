import os
import threading
import time
import json
import struct
import paho.mqtt.client as mqtt
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import random
import smtplib
from email.mime.text import MIMEText
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'your-secret-key-here'
# Use the DATABASE_URL from environment variables, default to sqlite if not set
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///studyrooms.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration (assuming this is still needed for the Flask app)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'mail.smtp2go.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 2525))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() in ('true', '1', 't')
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'roommonito')
app.config['MAIL_PASSWORD'] = os.getenv("SMTP2GO_PASSWORD") # Still using getenv for consistency with original
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'lnietourret@alumni.unav.es')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # type: ignore

# --- Database Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(6), unique=True)
    bookings = db.relationship('Booking', backref='user', lazy=True)

class Classroom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    color = db.Column(db.String(7), nullable=False) # Store color as hex string
    description = db.Column(db.Text, nullable=True)
    bookings = db.relationship('Booking', backref='classroom', lazy=True, cascade='all, delete-orphan')
    # Added relationship to MiotyData
    mioty_data = db.relationship('MiotyData', backref='classroom', lazy=True, cascade='all, delete-orphan')

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    # Added status for booking
    status = db.Column(db.String(20), default='confirmed') # e.g., 'confirmed', 'cancelled'

# New model for Mioty data
class MiotyData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    classroom_id = db.Column(db.Integer, db.ForeignKey('classroom.id'), nullable=False) # Link to classroom
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    key = db.Column(db.Integer, nullable=True) # Using nullable=True as keypad data might not always be present
    noise = db.Column(db.Integer, nullable=True)
    temperature = db.Column(db.Float, nullable=True) # Store temperature as float
    luminosity = db.Column(db.Integer, nullable=True)


# --- Flask-Login Callbacks ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Decorators ---
def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin: # type: ignore
            abort(403) # Forbidden
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions ---
def generate_verification_code():
    return ''.join(random.choices('0123456789', k=6))

def send_verification_email(user):
    msg = MIMEText(f'Your verification code is: {user.verification_code}')
    msg['Subject'] = 'Verify Your Email Address'
    msg['From'] = app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = user.email

    try:
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.sendmail(app.config['MAIL_DEFAULT_SENDER'], [user.email], msg.as_bytes())
    except Exception as e:
        print(f"Error sending email: {e}")


# --- Routes ---

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: # type: ignore
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if user.email_verified:
                login_user(user)
                return redirect(url_for('index'))
            else:
                flash('Please verify your email address before logging in.', 'warning')
                return redirect(url_for('verify_email_request'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated: # type: ignore
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        existing_email = User.query.filter_by(email=email).first()
        if existing_email:
            flash('Email address already registered.', 'danger')
            return redirect(url_for('register'))

        verification_code = generate_verification_code()
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, email=email, verification_code=verification_code)

        db.session.add(new_user)
        db.session.commit()

        send_verification_email(new_user)

        flash('A verification code has been sent to your email address. Please verify your email to log in.', 'info')
        return redirect(url_for('verify_email'))

    return render_template('register.html')

@app.route('/verify_email', methods=['GET', 'POST'])
def verify_email():
    if request.method == 'POST':
        email = request.form.get('email')
        code = request.form.get('code')

        user = User.query.filter_by(email=email).first()

        if user and user.verification_code == code:
            user.email_verified = True
            user.verification_code = None # Clear the verification code after successful verification
            db.session.commit()
            flash('Email successfully verified! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid email or verification code.', 'danger')

    return render_template('verify_email.html')

@app.route('/verify_email_request', methods=['GET', 'POST'])
@login_required
def verify_email_request():
    if current_user.email_verified: # type: ignore
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Resend verification email
        current_user.verification_code = generate_verification_code() # type: ignore
        db.session.commit()
        send_verification_email(current_user) # type: ignore
        flash('New verification code sent to your email.', 'info')
        return redirect(url_for('verify_email'))

    return render_template('verify_email_request.html')


# Main Dashboard Route
@app.route('/')
@login_required
def index():
    classrooms = Classroom.query.all()
    # Fetch recent mioty data for display (optional, depending on dashboard design)
    # For example, get the latest data point for each classroom if available
    latest_mioty_data = {}
    for classroom in classrooms:
         latest_data = MiotyData.query.filter_by(classroom_id=classroom.id).order_by(MiotyData.timestamp.desc()).first()
         latest_mioty_data[classroom.id] = latest_data

    return render_template('index.html', classrooms=classrooms, latest_mioty_data=latest_mioty_data)

# Classroom Routes
@app.route('/classroom/<int:classroom_id>')
@login_required
def classroom_detail(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)
    bookings = Booking.query.filter_by(classroom_id=classroom.id).order_by(Booking.start_time).all()
    # Fetch mioty data for this classroom (e.g., last 24 hours)
    time_threshold = datetime.utcnow() - timedelta(days=1)
    recent_mioty_data = MiotyData.query.filter(
        MiotyData.classroom_id == classroom.id,
        MiotyData.timestamp >= time_threshold
    ).order_by(MiotyData.timestamp).all()

    # Prepare data for charting (example: temperature over time)
    mioty_timestamps = [data.timestamp.isoformat() for data in recent_mioty_data if data.temperature is not None]
    mioty_temperatures = [data.temperature for data in recent_mioty_data if data.temperature is not None]
    mioty_noise = [data.noise for data in recent_mioty_data if data.noise is not None]
    mioty_luminosity = [data.luminosity for data in recent_mioty_data if data.luminosity is not None]


    return render_template('classroom_detail.html',
                           classroom=classroom,
                           bookings=bookings,
                           mioty_timestamps=mioty_timestamps,
                           mioty_temperatures=mioty_temperatures,
                           mioty_noise=mioty_noise,
                           mioty_luminosity=mioty_luminosity)

@app.route('/admin/classrooms', methods=['GET', 'POST'])
@admin_required
def manage_classrooms():
    if request.method == 'POST':
        name = request.form.get('name')
        capacity = request.form.get('capacity')
        color = request.form.get('color')
        description = request.form.get('description')

        if not name or not capacity or not color:
            flash('Name, capacity, and color are required.', 'danger')
            return redirect(url_for('manage_classrooms'))

        try:
            capacity = int(capacity)
        except ValueError:
            flash('Capacity must be an integer.', 'danger')
            return redirect(url_for('manage_classrooms'))

        existing_classroom = Classroom.query.filter_by(name=name).first()
        if existing_classroom:
            flash(f'Classroom with name "{name}" already exists.', 'danger')
            return redirect(url_for('manage_classrooms'))


        new_classroom = Classroom(name=name, capacity=capacity, color=color, description=description)
        db.session.add(new_classroom)
        db.session.commit()
        flash(f'Classroom "{name}" added successfully!', 'success')
        return redirect(url_for('manage_classrooms'))

    classrooms = Classroom.query.all()
    return render_template('manage_classrooms.html', classrooms=classrooms)

@app.route('/admin/classroom/edit/<int:classroom_id>', methods=['GET', 'POST'])
@admin_required
def edit_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)
    if request.method == 'POST':
        classroom.name = request.form.get('name')
        classroom.capacity = int(request.form.get('capacity')) # type: ignore
        classroom.color = request.form.get('color') # type: ignore
        classroom.description = request.form.get('description') # type: ignore

        db.session.commit()
        flash(f'Classroom "{classroom.name}" updated successfully!', 'success')
        return redirect(url_for('manage_classrooms'))
    return render_template('edit_classroom.html', classroom=classroom)

@app.route('/admin/classroom/delete/<int:classroom_id>', methods=['POST'])
@admin_required
def delete_classroom(classroom_id):
    classroom = Classroom.query.get_or_404(classroom_id)
    db.session.delete(classroom)
    db.session.commit()
    flash(f'Classroom "{classroom.name}" deleted successfully!', 'success')
    return redirect(url_for('manage_classrooms'))


# Booking Routes
@app.route('/book', methods=['GET', 'POST'])
@login_required
def book_classroom():
    if request.method == 'POST':
        classroom_id = request.form.get('classroom_id')
        start_time_str = request.form.get('start_time')
        end_time_str = request.form.get('end_time')

        classroom = Classroom.query.get(classroom_id)
        if not classroom:
            flash('Invalid classroom selected.', 'danger')
            return redirect(url_for('book_classroom'))

        try:
            start_time = datetime.strptime(start_time_str, '%Y-%m-%dT%H:%M') # type: ignore
            end_time = datetime.strptime(end_time_str, '%Y-%m-%dT%H:%M') # type: ignore
        except ValueError:
            flash('Invalid date or time format.', 'danger')
            return redirect(url_for('book_classroom'))

        if start_time >= end_time:
            flash('End time must be after start time.', 'danger')
            return redirect(url_for('book_classroom'))

        # Check for booking conflicts
        conflicting_bookings = Booking.query.filter(
            Booking.classroom_id == classroom.id,
            Booking.end_time > start_time,
            Booking.start_time < end_time
        ).first()

        if conflicting_bookings:
            flash('This time slot is already booked.', 'danger')
            return redirect(url_for('book_classroom'))

        new_booking = Booking(user_id=current_user.id, classroom_id=classroom.id, start_time=start_time, end_time=end_time) # type: ignore
        db.session.add(new_booking)
        db.session.commit()
        flash('Classroom booked successfully!', 'success')
        return redirect(url_for('index'))

    classrooms = Classroom.query.all()
    return render_template('book_classroom.html', classrooms=classrooms)

@app.route('/my_bookings')
@login_required
def my_bookings():
    bookings = Booking.query.filter_by(user_id=current_user.id).order_by(Booking.start_time.desc()).all() # type: ignore
    return render_template('my_bookings.html', bookings=bookings)

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    if booking.user_id != current_user.id: # type: ignore
        abort(403) # Forbidden if the user didn't make the booking

    db.session.delete(booking)
    db.session.commit()
    flash('Booking cancelled successfully.', 'success')
    return redirect(url_for('my_bookings'))

@app.route('/admin/bookings')
@admin_required
def manage_bookings():
    bookings = Booking.query.order_by(Booking.start_time.desc()).all()
    return render_template('manage_bookings.html', bookings=bookings)

@app.route('/admin/booking/delete/<int:booking_id>', methods=['POST'])
@admin_required
def delete_booking(booking_id):
    booking = Booking.query.get_or_404(booking_id)
    db.session.delete(booking)
    db.session.commit()
    flash('Booking deleted successfully.', 'success')
    return redirect(url_for('manage_bookings'))

# Admin User Management
@app.route('/admin/users')
@admin_required
def manage_users():
    users = User.query.all()
    return render_template('manage_users.html', users=users)

@app.route('/admin/user/toggle_admin/<int:user_id>', methods=['POST'])
@admin_required
def toggle_admin_status(user_id):
    user = User.query.get_or_404(user_id)
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f'Admin status for user "{user.username}" toggled.', 'success')
    return redirect(url_for('manage_users'))

@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.username}" deleted.', 'success')
    return redirect(url_for('manage_users'))

# Helper route to add default admin/classrooms (tables are now created on startup)
@app.route('/init_default_data')
def init_default_data():
    with app.app_context():
        # Create a default admin user if none exists
        if not User.query.filter_by(username='admin').first():
            hashed_password = generate_password_hash(os.environ.get('DEFAULT_ADMIN_PASSWORD', 'adminpassword'), method='pbkdf2:sha256')
            admin_user = User(username='admin', password=hashed_password, is_admin=True, email='admin@example.com', email_verified=True)
            db.session.add(admin_user)
            db.session.commit()
            print("Default admin user created.")

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
                    description=f"The {room_data['name']} classroom is a quiet space ideal for focused study or small group work."
                )
                db.session.add(classroom)
            db.session.commit()
            print("Default classrooms created.")

    return 'Default data added!'

# --- Mioty Data Reception with Threading ---

brokerMioty = os.environ.get('MIOTY_BROKER', "192.168.10.153")
portMioty = int(os.environ.get('MIOTY_PORT', 1883))
topicMioty = os.environ.get('MIOTY_TOPIC', 'mioty/00-00-00-00-00-00-00-00/70-b3-d5-67-70-11-01-98/uplink')

# Mapping dictionary for mioty typeEui to classroom_id
# You will need to configure this based on your actual mioty devices and classrooms
# Example: {'mioty_device_typeEui': classroom_id_in_database}
# You might need a more robust mapping mechanism if you have many devices/classrooms
MIOTY_TO_CLASSROOM_MAP = {
    '70b3d56770110198': 1, # Example: map this mioty device EUI to classroom with ID 1
    # Add other mappings here
}


def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Conectado al broker Mioty")
        client.subscribe(topicMioty)
    else:
        print("❌ Error al conectar al broker Mioty, código:", rc)

def on_message(client, userdata, msg):
    print("\n📥 Mensaje Mioty recibido:")
    try:
        js = json.loads(msg.payload.decode("utf-8"))
        data = js.get("data", [])
        device_eui = js.get("device", {}).get("eui") # Assuming device EUI is in the payload

        # Check for expected data length based on your struct.unpack format
        # The format '<BHHH' expects 1 + 2 + 2 + 2 = 7 bytes
        expected_data_length = 7

        if not isinstance(data, list) or len(data) < expected_data_length:
            print(f"⚠️ Datos Mioty insuficientes. Se esperaban al menos {expected_data_length} bytes.")
            print("📦 Recibido:", data)
            return

        # Convertimos a bytes (take only the expected number of bytes)
        byte_data = bytes(data[:expected_data_length])

        # Desempaquetamos en Little Endian: 1B + 3x 2B
        try:
            # Unpack the data according to the format
            key, noise, temperature_raw, luminosity = struct.unpack('<BHHH', byte_data)

            # Apply scaling and unit conversion based on config.json/data.json snippets
            # Assuming temperature needs division by 100 based on "func": "$*100" and unit "celsius_x100"
            temperature = temperature_raw / 100.0 if temperature_raw is not None else None

            print(f"🎹 Tecla: {key if 32 <= key <= 126 else key}")
            print(f"🎧 Ruido: {noise}")
            print(f"🌡️ Temperatura: {temperature}°C")
            print(f"💡 Luminosidad: {luminosity}")

            # Find the corresponding classroom based on device EUI
            classroom_id = MIOTY_TO_CLASSROOM_MAP.get(device_eui)

            if classroom_id:
                # Save data to the database
                # Use app.app_context() to interact with Flask-SQLAlchemy in a thread
                with app.app_context():
                    try:
                        new_mioty_data = MiotyData(
                            classroom_id=classroom_id,
                            timestamp=datetime.utcnow(),
                            key=key,
                            noise=noise,
                            temperature=temperature,
                            luminosity=luminosity
                        )
                        db.session.add(new_mioty_data)
                        db.session.commit()
                        print("💾 Mioty data saved to database.")
                    except Exception as db_error:
                        db.session.rollback()
                        print(f"❌ Error saving mioty data to database: {db_error}")
            else:
                print(f"Skipping data save: No classroom found for device EUI {device_eui}")


        except struct.error as e:
            print(f"❌ Error unpacking mioty data: {e}. Check the data format and unpack string.")
        except Exception as e:
            print(f"❌ Error processing mioty message: {e}")

    except json.JSONDecodeError:
        print("❌ Error decoding JSON payload")
    except Exception as e:
        print(f"❌ An unexpected error occurred: {e}")


def run_mqtt_client():
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1) # Specify API version
    client.on_connect = on_connect
    client.on_message = on_message

    try:
        client.connect(brokerMioty, portMioty, 60)
        client.loop_forever()
    except ConnectionRefusedError:
        print(f"❌ Conexión rechazada. Asegúrate de que el broker MQTT en {brokerMioty}:{portMioty} esté activo.")
    except Exception as e:
        print(f"❌ Error en el cliente MQTT: {e}")

# --- Main Execution ---
if __name__ == '__main__':
    # Create database tables if they don't exist
    with app.app_context():
        db.create_all()
        print("Database tables checked/created.")

    # Start the MQTT client in a separate thread
    mqtt_thread = threading.Thread(target=run_mqtt_client)
    mqtt_thread.daemon = True # Allow the main thread to exit even if MQTT thread is running
    mqtt_thread.start()

    # Run the Flask application
    # In a production environment, use a production-ready WSGI server like Gunicorn or uWSGI
    app.run(debug=True, host='0.0.0.0', port=5000)

