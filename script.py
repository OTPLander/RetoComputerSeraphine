import paho.mqtt.client as mqtt
from datetime import datetime

# Configuración MQTT
BROKER = "192.168.10.153"  # IP del broker
PORT = 1883
TOPIC = "mioty/70-b3-d5-67-70-0f-00-00/70-b3-d5-67-70-11-01-98/uplink"

def on_message(client, userdata, message):
    """Callback para mensajes recibidos"""
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    raw_data = message.payload
    print(f"\n[{timestamp}] Topic: {message.topic}")
    print(f"Longitud: {len(raw_data)} bytes")
    print("Datos brutos:", raw_data)
    print("Hex:", ' '.join(f"{b:02x}" for b in raw_data))

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("Conectado al broker!")
        client.subscribe(TOPIC)
    else:
        print(f"Error conexión: Código {rc}")

# Configurar cliente
client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

# Conectar y comenzar loop
client.connect(BROKER, PORT, 60)
print(f"Escuchando broker {BROKER} en el topic {TOPIC}...")
client.loop_forever()