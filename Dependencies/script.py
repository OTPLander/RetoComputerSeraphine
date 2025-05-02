import paho.mqtt.client as mqtt
import json
import struct

brokerMioty = "192.168.10.153"
portMioty = 1883
topicMioty = 'mioty/00-00-00-00-00-00-00-00/70-b3-d5-67-70-11-01-98/uplink'

def on_connect(client, userdata, flags, rc):
    if rc == 0:
        print("✅ Conectado al broker")
        client.subscribe(topicMioty)
    else:
        print("❌ Error al conectar, código:", rc)

def on_message(client, userdata, msg):
    print("\n📥 Mensaje recibido:")
    try:
        js = json.loads(msg.payload.decode("utf-8"))
        data = js.get("data", [])

        if not isinstance(data, list) or len(data) < 7:
            print("⚠️ Datos insuficientes. Se esperaban 7 bytes.")
            print("📦 Recibido:", data)
            return

        # Convertimos a bytes
        byte_data = bytes(data[:7])

        # Desempaquetamos en Little Endian: 1B + 3x 2B
        key, noise, temperature, luminosity = struct.unpack('<BHHH', byte_data)

        print(f"🎹 Tecla: {key if 32 <= key <= 126 else key}")
        print(f"🎧 Ruido: {noise}")
        print(f"🌡️ Temperatura: {temperature *1:.2f}°C")
        print(f"💡 Luminosidad: {luminosity}")

    except Exception as e:
        print("❌ Error procesando mensaje:", e)

client = mqtt.Client()
client.on_connect = on_connect
client.on_message = on_message

client.connect(brokerMioty, portMioty, 60)
client.loop_forever()


