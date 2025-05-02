#include <m3bDemoHelper.h>
#include <m3b_sensors/si1141.h>
#include <miotyAtClient.h>
#include <SHT31.h>
#include <SparkFun_MS5637_Arduino_Library.h>
#include <Keypad.h>
#include "SoftwareSerial.h"
#include <Wire.h>

// Debug Serial
SoftwareSerial SerialM3B(PA10, PA9);
// Mioty Bidi Stamp Serial
SoftwareSerial SerialMioty(PC11, PC10);

// Sensor Declaration
TwoWire Wire2(PB9, PB8);
MS5637 ms5637;
SHT31 sht31;
SI1141 si1141;
M3BDemoHelper m3bDemo;

// Variables
uint16_t noise;
uint16_t luminosity;
uint16_t humidity;
uint16_t temperature;
uint32_t userKey;
uint32_t currentTickRed;
uint32_t currentTickBlue;
uint8_t blue_state;
uint8_t red_state;
uint8_t youCanWrite;
uint8_t key = 0;
uint8_t key1, key2;
uint8_t finished = 0;

// MIOTY Data
uint32_t cnt = 25;
uint8_t TxData[8];
uint8_t eui64[8] = { 0x70, 0xb3, 0xd5, 0x67, 0x70, 0x11, 0x01, 0x98 };
uint8_t shortAdress[2] = { eui64[6], eui64[7] };
uint8_t nwKey[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 
                      0x09, 0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

// Microphone Sensor
#define MIC_PIN PC1

// Keypad setup
const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
  { '1', '2', '3', 'A' },
  { '4', '5', '6', 'B' },
  { '7', '8', '9', 'C' },
  { '*', '0', '#', 'D' }
};
byte rowPins[COLS] = { PA6, PA7, PA5, PA4 };
byte colPins[ROWS] = { PA1, PA0, PC3, PC2 };
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);

void setup() {
  m3bDemo.begin();
  SerialM3B.begin(9600);
  SerialMioty.begin(9600);
  Wire2.begin();
  pinMode(MIC_PIN, INPUT);
  pinMode(BLUE_LED, OUTPUT);
  
  if (!ms5637.begin(Wire2)) {
    SerialM3B.println("MS5637 sensor did not respond. Please check wiring.");
  }
  sht31.begin(0x44, &Wire2);
  si1141.begin(&Wire2);

  // MIOTY Configuration
  uint8_t MSTA;
  miotyAtClient_macDetachLocal(&MSTA);
  miotyAtClient_getOrSetEui(eui64, true);
  miotyAtClient_getOrSetShortAdress(shortAdress, true);
  miotyAtClient_setNetworkKey(nwKey);
  miotyAtClient_macAttachLocal(&MSTA);

  // Display EUI
  uint8_t eui64[8];
  miotyAtClient_getOrSetEui(eui64, false);
  SerialM3B.print("Device EUI: ");
  for (int i = 0; i < 8; i++) {
    SerialM3B.print(eui64[i], HEX);
    if (i < 7) SerialM3B.print("-");
  }
  SerialM3B.println();
}

void loop() {
  uint32_t currentTick = HAL_GetTick();

  // Read sensors every 5 seconds
  if (currentTick - currentTickRed >= 5000) {
    SerialM3B.println("im alive");
    readData();
    currentTickRed = currentTick;
  }

  // Check for password input with timeout
  uint32_t passwordStartTime = HAL_GetTick();
  while (HAL_GetTick() - passwordStartTime < 5000 && !finished) {
    getPassword();
    HAL_Delay(50); // Prevent busy-waiting
  }

  // Send data every 10 seconds or immediately after password entry
  if (finished || (currentTick - currentTickBlue >= 10000)) {
    sendData();
    cleanVars();
    currentTickBlue = currentTick;
    blue_state = !blue_state;
    digitalWrite(BLUE_LED, blue_state);
  }
}

void readData() {
  noise = analogRead(MIC_PIN);
  si1141.readLuminosity(&luminosity);
  temperature = (uint16_t)ms5637.getTemperature(); // Truncate to integer
  humidity = (uint16_t)sht31.getHumidity(); // Added humidity reading
}

void sendData() {
  TxData[0] = 0; // Packet identifier
  TxData[1] = key;
  TxData[2] = noise & 0xFF;
  TxData[3] = (noise >> 8) & 0xFF;
  TxData[4] = temperature & 0xFF;
  TxData[5] = (temperature >> 8) & 0xFF;
  TxData[6] = luminosity & 0xFF;
  TxData[7] = (luminosity >> 8) & 0xFF;
  miotyAtClient_sendMessageUniMPF(TxData, 8, &cnt);
}

void cleanVars() {
  key = 0;
  key1 = 0;
  key2 = 0;
  finished = 0;
}

void getPassword() {
  static uint8_t state = 0; // 0: first key, 1: second key
  char keyChar = keypad.getKey();

  if (keyChar != NO_KEY) {
    if (state == 0 && isDigit(keyChar)) {
      key1 = keyChar - '0';
      state = 1;
      SerialM3B.print("First key: ");
      SerialM3B.println(key1);
    } else if (state == 1 && isDigit(keyChar)) {
      key2 = keyChar - '0';
      key = key1 * 10 + key2;
      state = 0;
      finished = 1;
      SerialM3B.print("Password entered: ");
      SerialM3B.println(key);
    }
  }
}

