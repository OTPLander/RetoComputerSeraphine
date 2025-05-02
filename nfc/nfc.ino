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

#include <Adafruit_PN532.h>
// Mioty Bidi Stamp Serial
//enable I2C
#include <Wire.h>
//Sensor Declaration
TwoWire Wire2(PIN_WIRE_SDA, PIN_WIRE_SCL);
MS5637 ms5637;
SHT31 sht31;
SI1141 si1141;
//M3BDemoHelper m3bDemo;

//varia

#define PN532_IRQ   (PB6)
// PIN_WIRE_SDA
// PIN_WIRE_SCL
#define PN532_RESET (PA6)  // Not connected by default on the NFC Shield
Adafruit_PN532 nfc(PN532_IRQ,PN532_RESET,&SoftwareSerial);


void setup(){
    //m3bDemo.begin();
    SerialM3B.begin(9600);
    //Wire2.begin();
    nfc.begin();
    SerialM3B.println("PN53x not found");
  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    SerialM3B.println("PN53x not found");
  }

  // Display sensor data
  SerialM3B.println("Found chip PN5"); SerialM3B.println((versiondata>>24) & 0xFF, HEX); 
  SerialM3B.println("Firmware ver. "); SerialM3B.println((versiondata>>16) & 0xFF, DEC); 
  SerialM3B.println('.'); SerialM3B.println((versiondata>>8) & 0xFF, DEC);
  
  // Configure to read RFID tags
  nfc.setPassiveActivationRetries(0xFF);
  nfc.SAMConfig();
  
  SerialM3B.println("Waiting for ISO14443A card");
}

// Auxiliary function to display the buffer
void printArray(byte *buffer, byte bufferSize) {
   for (byte i = 0; i < bufferSize; i++) {
      SerialM3B.println(buffer[i] < 0x10 ? " 0" : " ");
      SerialM3B.println(buffer[i], HEX);
   }
}





void loop(){
   SerialM3B.println("test");
 boolean success;
  uint8_t uid[] = { 0, 0, 0, 0, 0, 0, 0 };
  uint8_t uidLength;

  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, &uid[0], &uidLength,5);
  SerialM3B.println(success);
  if (success) {
    SerialM3B.println("Card found");
    SerialM3B.print("UID Length: ");SerialM3B.print(uidLength, DEC);SerialM3B.println(" bytes");
    SerialM3B.print("UID: "); printArray(uid, uidLength);
    SerialM3B.println("");
  
    delay(1000);
  }
  else
  {    
    SerialM3B.println("Card not found");
  }
}
