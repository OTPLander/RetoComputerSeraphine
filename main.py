import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
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
import threading
import paho.mqtt.client as mqtt
import json
import struct




def run_mqtt_client():
    brokerMioty = "192.168.10.153"
    portMioty = 1883
    topicMioty = 'mioty/00-00-00-00-00-00-00-00/70-b3-d5-67-70-11-01-98/uplink'

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            print("✅ Conectado al broker MQTT")
            client.subscribe(topicMioty)
        else:
            print("❌ Error al conectar MQTT, código:", rc)

    def on_message(client, userdata, msg):
        print("\n📥 Mensaje MQTT recibido:")
        try:
            js = json.loads(msg.payload.decode("utf-8"))
            data = js.get("data", [])
            byte_data = bytes(data[:7])
            key, noise, temperature, luminosity = struct.unpack('<BHHH', byte_data)
            
            print(f"🎹 Tecla: {chr(key) if 32 <= key <= 126 else key}")
            print(f"🎧 Ruido: {noise}")
            print(f"🌡️ Temperatura: {temperature / 100:.2f}°C")
            print(f"💡 Luminosidad: {luminosity}")

            with app.app_context(): # Crea un contexto de aplicación para operaciones de DB
                new_mioty_data = MiotyData(
                    key_code=key,
                    noise=noise,
                    temperature=temperature, # Guarda el valor ya convertido a float
                    luminosity=luminosity,
                    timestamp=datetime.utcnow() # Guarda el timestamp actual
                )
                db.session.add(new_mioty_data) # Añade el nuevo objeto a la sesión
                db.session.commit() # Guarda los cambios en la base de datos
                print("✅ Datos MQTT guardados en la base de datos.")

        except Exception as e:
            print("❌ Error procesando mensaje MQTT:", e)

    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message

    client.connect(brokerMioty, portMioty, 60)
    client.loop_forever()

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
class MiotyData(db.Model):
    __tablename__ = 'mioty_data' # Asegúrate de que coincida con el nombre de la tabla
    id = db.Column(db.Integer, primary_key=True)
    key_code = db.Column(db.Integer, nullable=False) # Almacenar el valor entero de la tecla
    noise = db.Column(db.Integer, nullable=False)
    temperature = db.Column(db.Float, nullable=False) # Usar Float para la temperatura decimal
    luminosity = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # Para saber cuándo se recibió el dato

    def __repr__(self):
        return f'<MiotyData {self.timestamp}>'

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
    description = db.Column(db.Text)

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
            # Corrected typo in app.config key name
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

# ========== ADMIN ROUTES ==========

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

    # *** CORRECCIÓN: Obtiene todos los mensajes de la tabla mioty_data ***
    # Usa el modelo MiotyData para consultar la tabla 'mioty_data'
    # Ordena los mensajes por timestamp de forma descendente para ver los más recientes primero
    mioty_messages_list = MiotyData.query.order_by(MiotyData.timestamp.desc()).all()


    # Renderiza la plantilla HTML del panel de administración
    # Pasa los datos obtenidos de las consultas a la plantilla
    return render_template(
        'admin_dashboard.html',
        users=users,         # Lista de objetos User
        classrooms=classrooms, # Lista de objetos Classroom
        reservations=reservations, # Lista de objetos Reservation con user y classroom cargados
        messages=mioty_messages_list, # <-- Lista de objetos MiotyData (los mensajes)
        datetime=datetime    # Pasa el objeto datetime (opcional si no lo usas mucho en el template)
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
    with app.app_context():
        # This will create User, Classroom, Reservation, and the correctly defined ReservationCodes tables
        db.create_all()

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

if __name__ == '__main__':
        create_tables()
    
    # Iniciar cliente MQTT en un hilo separado
        mqtt_thread = threading.Thread(target=run_mqtt_client, daemon=True)
        mqtt_thread.start()
    
    # Iniciar aplicación Flask
        app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=True)