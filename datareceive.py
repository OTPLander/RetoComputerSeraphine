import paho.mqtt.client as mqtt
import json
import struct
import sqlite3
from datetime import datetime

# --- MQTT Configuration ---
brokerMioty = "192.168.10.153"
portMioty = 1883
topicMioty = 'mioty/00-00-00-00-00-00-00-00/70-b3-d5-67-70-11-01-98/uplink'

# --- Database Configuration ---
database_file = "mioty_messages.db"

# --- Database Connection and Setup ---
def connect_db():
    """Connects to the SQLite database."""
    try:
        conn = sqlite3.connect(database_file)
        print(f"✅ Conectado a la base de datos: {database_file}")
        return conn
    except sqlite3.Error as e:
        print(f"❌ Error al conectar a la base de datos: {e}")
        return None

def create_table(conn):
    """Creates the messages table if it doesn't exist."""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                key_value INTEGER,
                noise INTEGER,
                temperature REAL,
                luminosity INTEGER,
                raw_data TEXT -- Store raw data as text for debugging/completeness
            )
        ''')
        conn.commit()
        print("✅ Tabla 'messages' verificada/creada.")
    except sqlite3.Error as e:
        print(f"❌ Error al crear la tabla: {e}")

# --- MQTT Callbacks ---
def on_connect(client, userdata, flags, rc):
    """Callback function when the client connects to the MQTT broker."""
    if rc == 0:
        print("✅ Conectado al broker MQTT")
        client.subscribe(topicMioty)
        print(f"✅ Suscrito al tema: {topicMioty}")
    else:
        print("❌ Error al conectar al broker MQTT, código:", rc)

def on_message(client, userdata, msg):
    """Callback function when a message is received."""
    print("\n📥 Mensaje recibido:")
    conn = userdata['db_conn'] # Get the database connection from userdata
    try:
        # Decode the payload and parse JSON
        payload_str = msg.payload.decode("utf-8")
        js = json.loads(payload_str)
        data = js.get("data", [])

        # Validate data length
        if not isinstance(data, list) or len(data) < 7:
            print("⚠️ Datos insuficientes. Se esperaban al menos 7 bytes.")
            print("📦 Recibido:", data)
            # Optionally log the insufficient data
            insert_message(conn, None, None, None, None, payload_str)
            return

        # Convert list of integers to bytes
        byte_data = bytes(data[:7])

        # Unpack the bytes according to the structure (Little Endian: 1B + 3x 2B)
        # B: unsigned char (1 byte)
        # H: unsigned short (2 bytes)
        key, noise, temperature_raw, luminosity = struct.unpack('<BHHH', byte_data)

        # Apply scaling for temperature as per config (assuming $*100 in config.json)
        temperature_celsius = temperature_raw / 100.0

        # Print decoded data
        print(f"🎹 Tecla: {key if 32 <= key <= 126 else key}")
        print(f"🎧 Ruido: {noise}")
        print(f"🌡️ Temperatura: {temperature_celsius:.2f}°C")
        print(f"💡 Luminosidad: {luminosity}")

        # Insert data into the database
        insert_message(conn, key, noise, temperature_celsius, luminosity, payload_str)

    except json.JSONDecodeError:
        print("❌ Error al decodificar JSON del mensaje.")
        # Optionally log the raw non-JSON payload
        insert_message(conn, None, None, None, None, msg.payload.decode('utf-8', errors='ignore'))
    except struct.error as e:
        print(f"❌ Error al desempaquetar los datos binarios: {e}")
        insert_message(conn, None, None, None, None, payload_str)
    except Exception as e:
        print(f"❌ Error general procesando mensaje: {e}")
        insert_message(conn, None, None, None, None, payload_str)

def insert_message(conn, key_value, noise, temperature, luminosity, raw_data):
    """Inserts a new row into the messages table."""
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (key_value, noise, temperature, luminosity, raw_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (key_value, noise, temperature, luminosity, raw_data))
        conn.commit()
        print("✅ Mensaje insertado en la base de datos.")
    except sqlite3.Error as e:
        print(f"❌ Error al insertar mensaje en la base de datos: {e}")

# --- Main Execution ---
if __name__ == "__main__":
    # Connect to the database
    db_connection = connect_db()
    if db_connection is None:
        exit() # Exit if database connection fails

    # Create the table
    create_table(db_connection)

    # Set up MQTT client
    client = mqtt.Client(userdata={'db_conn': db_connection}) # Pass the db connection as userdata
    client.on_connect = on_connect
    client.on_message = on_message

    # Connect to MQTT broker and start the loop
    try:
        client.connect(brokerMioty, portMioty, 60)
        print("Iniciando bucle MQTT. Presiona Ctrl+C para salir.")
        client.loop_forever()
    except KeyboardInterrupt:
        print("\nDeteniendo el cliente MQTT.")
    except Exception as e:
        print(f"❌ Error durante el bucle MQTT: {e}")
    finally:
        # Close the database connection when the script stops
        if db_connection:
            db_connection.close()
            print("✅ Conexión a la base de datos cerrada.")

