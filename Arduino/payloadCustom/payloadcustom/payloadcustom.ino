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
//TxData[8];
// input new EUI
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
while(1);
}
sht31.begin(0x44, &Wire2);
si1141.begin(&Wire2);
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
sendData();
digitalWrite(BLUE_LED, HIGH);
}
void sendData() {
int TxData[8];
TxData[0]=01000101b;
TxData[1]=01000101b;
TxData[2]=01000101b;
TxData[3]=01000101b;
TxData[4]=01000101b;
TxData[5]=01000101b;
TxData[6]=01000101b;
TxData[7]=01000101b;
//#miotyAtClient_sendData(&TxData);
delay(1000);
//SerialM3B.println("");
}