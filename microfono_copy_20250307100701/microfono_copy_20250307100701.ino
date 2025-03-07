#include <Arduino.h>
#include <miotyAtClient.h>
#include "m3bDemoHelper.h"
#include "m3b_sensors/si1141.h"
#include <SHT31.h>
#include <SparkFun_MS5637_Arduino_Library.h>
#include <Keypad.h>

// Enable Serial Monitor
#include "SoftwareSerial.h"
// Debug Serial
SoftwareSerial SerialM3B(PA10, PA9); // Pines TX y RX para debug
// Mioty Bidi Stamp Serial
SoftwareSerial SerialMioty(PC11, PC10); // Pines TX y RX para Mioty

// Enable I2C
#include <Wire.h>
// Sensor Declaration
TwoWire Wire2(PB9, PB8);
MS5637 ms5637;
SHT31 sht31;
SI1141 si1141;
M3BDemoHelper m3bDemo;

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

void setup() {
    SerialM3B.begin(9600); // Comunicación para debug
    SerialMioty.begin(9600); //  con el módulo Mioty
    while (!SerialM3B); // Espera a que el puerto serie esté listo
    SerialM3B.println("Inicio del sistema STM32L0 con MIOTY");
    pinMode(MIC_PIN, INPUT); // Configurar el pin del micrófono como entrada
}

void loop() {
    /*int micValue = analogRead(MIC_PIN); // Leer el valor del micrófono
    SerialM3B.print("Nivel de sonido: ");
    SerialM3B.println(micValue); // Enviar el valor del micrófono al monitor serial
    */
    char key = keypad.getKey();
    if (key) {
        SerialM3B.print("Tecla presionada: ");
        SerialM3B.println(key);
    }
    
    //delay(2000); // Espera 2 segundos
}
