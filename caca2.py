import threading
import os
import json
import struct
import random
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import paho.mqtt.client as mqtt

# ==========================================
#               CONFIGURACIÓN
# ==========================================
load_dotenv()

# Configuración Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'secret-key-123'
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///studyrooms.db').replace('postgres://', 'postgresql://')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = "mail.smtp2go.com"
app.config['MAIL_PORT'] = 2525
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = "roommonito"
app.config['MAIL_PASSWORD'] = os.getenv("SMTP2GO_PASSWORD")
app.config['MAIL_DEFAULT_SENDER'] = "lnietourret@alumni.unav.es"

# Configuración MQTT
MQTT_BROKER = "192.168.10.153"
MQTT_PORT = 1883
MQTT_TOPIC = 'mioty/00-00-00-00-00-00-00-00/70-b3-d5-67-70-11-01-98/uplink'

# Configuración tiempo
TIME_SLOTS = [
    {'start': '09:00', 'end': '10:30', 'label': '9:00-10:30'},
    {'start': '10:30', 'end': '12:00', 'label': '10:30-12:00'},
    {'start': '12:00', 'end': '13:30', 'label': '12:00-13:30'},
    {'start': '13:30', 'end': '15:00', 'label': '13:30-15:00'},
    {'start': '15:00', 'end': '16:30', 'label': '15:00-16:30'},
    {'start': '16:30', 'end': '18:00', 'label': '16:30-18:00'},
    {'start': '18:00', 'end': '19:30', 'label': '18:00-19:30'}
]

# ==========================================
#               BASE DE DATOS
# ==========================================
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    # ... (resto del modelo User)

class Classroom(db.Model):
    __tablename__ = 'classrooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    capacity = db.Column(db.Integer, nullable=False)
    # ... (resto del modelo Classroom)

class Reservation(db.Model):
    __tablename__ = 'reservations'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    # ... (resto del modelo Reservation)

class ReservationCodes(db.Model):
    __tablename__ = 'acces_codes'
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(2), nullable=False)
    # ... (resto del modelo ReservationCodes)

# ==========================================
#               FUNCIONALIDAD MQTT
# ==========================================
def mqtt_on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("[MQTT] ✅ Conexión establecida")
        client.subscribe(MQTT_TOPIC)
    else:
        print(f"[MQTT] ❌ Error de conexión: Código {rc}")

def mqtt_on_message(client, userdata, msg):
    try:
        data = json.loads(msg.payload.decode())['data']
        if len(data) >= 7:
            byte_data = bytes(data[:7])
            key, noise, temp, lux = struct.unpack('<BHHH', byte_data)
            print(f"\n[MQTT] Datos recibidos:\n"
                  f"  Tecla: {chr(key) if 32 <= key <= 126 else key}\n"
                  f"  Ruido: {noise} dB\n"
                  f"  Temp: {temp/100:.1f}°C\n"
                  f"  Luminosidad: {lux} lux")
    except Exception as e:
        print(f"[MQTT] ❌ Error procesando mensaje: {str(e)}")

def mqtt_thread():
    client = mqtt.Client()
    client.on_connect = mqtt_on_connect
    client.on_message = mqtt_on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_forever()

# ==========================================
#               FUNCIONALIDAD WEB
# ==========================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_tables():
    with app.app_context():
        db.create_all()
        # Crear admin si no existe
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True,
                is_verified=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()

# ... (Todas las rutas de Flask del main.py original)
# ... (login, register, index, reserve, my_reservations, etc.)
# ... (Funciones auxiliares: send_email, admin_required, etc.)

# ==========================================
#               EJECUCIÓN
# ==========================================
if __name__ == '__main__':
    create_tables()
    
    # Iniciar servidor Flask en un hilo
    flask_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False)
    )
    
    # Iniciar cliente MQTT en otro hilo
    mqtt_thread = threading.Thread(target=mqtt_thread)

    try:
        flask_thread.start()
        mqtt_thread.start()
        print("[SISTEMA] 🔥 Servicios iniciados")
        
        # Mantener hilos activos
        flask_thread.join()
        mqtt_thread.join()
        
    except KeyboardInterrupt:
        print("\n[SISTEMA] 🔌 Apagando servicios...")
        os._exit(0)