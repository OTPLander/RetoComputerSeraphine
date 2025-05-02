#include <m3bDemoHelper.h>
#include <m3b_sensors/si1141.h>


// Libraries for Sensor use, MIOTY and M3 Board
#include <miotyAtClient.h>
#include <SHT31.h>
#include <SparkFun_MS5637_Arduino_Library.h>
#include <Keypad.h>
//enable Serial Monitor
#include "SoftwareSerial.h"
// Debug Serial
SoftwareSerial SerialM3B(PA10, PA9);
// Mioty Bidi Stamp Serial
SoftwareSerial SerialMioty(PC11, PC10);
//enable I2C
#include <Wire.h>
//Sensor Declaration
TwoWire Wire2(PB9, PB8);
MS5637 ms5637;
SHT31 sht31;
SI1141 si1141;
M3BDemoHelper m3bDemo;
//variables
char key;
uint16_t noise;
uint32_t userKey;
uint32_t currentTick;

//TxData[8];
// input new EUI
uint32_t cnt = 0;
uint8_t TxData[7];
uint8_t eui64[8] = {0x70, 0xb3, 0xd5, 0x67, 0x70, 0x11, 0x01, 0x98};
uint8_t shortAdress[2] = {eui64[6], eui64[7]}; // get the last two byte as the short address

// input new Network Key
uint8_t nwKey[16]={0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
0x01, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
#define SET_NETWORKKEY
// Microphone Sensor
#define MIC_PIN PC1 // Pin analógico para el micrófono MAX4466
// Keypad setup
const byte ROWS = 4;
const byte COLS = 4;
char keys[ROWS][COLS] = {
    {'1', '2', '3', 'A'},
    {'4', '5', '6', 'B'},
    {'7', '8', '9', 'C'},
    {'*', '0', '#', 'D'}
};
//byte colPins[ROWS] = {PC2, PC3, PA0, PA1}; // Pines de las filas
byte colPins[ROWS] = {PA1, PA0, PC3, PC2}; // Pines de las filas
//byte rowPins[COLS] = {PA2, PA3, PA4, PA7}; // Pines de las columnas
byte rowPins[COLS] = {PA6, PA7, PA5, PA4}; // Pines de las columnas
Keypad keypad = Keypad(makeKeymap(keys), rowPins, colPins, ROWS, COLS);




void setup(){
  //miotyAtClient_getOrSetShortAdress(shortAdress, true);
  m3bDemo.begin();
SerialM3B.begin(9600);
SerialMioty.begin(9600);
Wire2.begin();
 pinMode(MIC_PIN, INPUT); // Configurar el pin del micrófono como entrada
if (ms5637.begin(Wire2) == false)
{
SerialM3B.println("MS5637 sensor did not respond. Please check wiring.");
}
sht31.begin(0x44, &Wire2);
si1141.begin(&Wire2);
pinMode(BLUE_LED, OUTPUT);
//Code for initial one-time setting of the network key, will only be executed if the constant SET_NETWORKKEY was defined previously
//#ifdef SET_NETWORKKEY
// assign new EUI and Network Key
uint8_t MSTA; // status of mac state machine
// Local Dettach
SerialM3B.print("Local Dettach:");
miotyAtClient_macDetachLocal(&MSTA);
// Set-EUI
SerialM3B.print("Set EUI");
miotyAtClient_getOrSetEui(eui64, true);
miotyAtClient_getOrSetShortAdress(shortAdress, true);
SerialM3B.println("");
// Set-Network Key
SerialM3B.print("Set Network Key");
miotyAtClient_setNetworkKey(nwKey);
SerialM3B.println(miotyAtClient_setNetworkKey(nwKey));
SerialM3B.println("");
// Local Attach - required only once
SerialM3B.print("Local Attach:");
miotyAtClient_macAttachLocal(&MSTA);
SerialM3B.print("New Mac State:");
SerialM3B.println(MSTA);
SerialM3B.println("");
//#endif
// get Device EUI
uint8_t eui64[8];
//miotyAtClient_getOrSetShortAdress(shortAdress, true);
miotyAtClient_getOrSetEui( eui64, false);
SerialM3B.print("Device EuI ");
for (int i = 0; i < 8;i++) {
SerialM3B.print(eui64[i], HEX);
SerialM3B.print("-");}
}



void loop(){
digitalWrite(BLUE_LED, LOW);
digitalWrite(BLUE_LED, HIGH);
if(currentTick+1000 < HAL_GetTick()){
sendData();
cleanVars();
currentTick = HAL_GetTick();
digitalWrite(BLUE_LED, HIGH);}
}
void sendData() {
    // 8bitKeyboard (2 bytes)
    TxData[0] = key;
    // 16bitNoise (2 bytes)
    TxData[1] = noise & 0xFF; // Parte baja del número
    TxData[2] = (noise >> 8) & 0xFF;  // Parte alta
    //32 bit UserKey
    TxData[3] = userKey & 0xFF;        // Byte menos significativo (LSB)
    TxData[4] = (userKey >> 8) & 0xFF;
    TxData[5] = (userKey >> 16) & 0xFF;
    TxData[6] = (userKey >> 24) & 0xFF; // Byte más significativo (MSB)

miotyAtClient_sendMessageUniMPF(TxData, 7, &cnt);
//SerialM3B.println("");
}

void readData() {
  key = keypad.getKey();
  sound = analogRead(MIC_PIN); // Leer el valor del micrófono
}

void cleanVars(){
  key = '\0';
}


