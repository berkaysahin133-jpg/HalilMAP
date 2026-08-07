// Arduino API taklidi -- sadece derleme dogrulamasi icin
#include <cstdint>
#include <cstdio>
#include <string>
#include <algorithm>
using std::min; using std::max;
#define INPUT 0
#define INPUT_PULLUP 2
#define HIGH 1
#define LOW 0
static unsigned long _ms = 0;
unsigned long millis() { return _ms; }
void delay(unsigned long) {}
void delayMicroseconds(unsigned int) {}
void pinMode(uint8_t, uint8_t) {}
int  digitalRead(uint8_t) { return HIGH; }
struct _Serial {
  void begin(long) {}
  void setTimeout(long) {}
  int  available() { return 0; }
  int  read() { return -1; }
  void print(const char*) {}
  void print(unsigned int) {}
  void print(int) {}
  void print(unsigned long) {}
  void print(long) {}
  void println(long) {}
  void println(const char*) {}
  void println(unsigned int) {}
  void println(int) {}
} Serial;
struct _Wire { void begin() {} void setClock(long) {} } Wire;
struct Adafruit_MCP4725 {
  void begin(uint8_t) {}
  void setVoltage(uint16_t, bool) {}
};
#include <cstring>
#include <cstdlib>
#define constrain(v,lo,hi) ((v)<(lo)?(lo):((v)>(hi)?(hi):(v)))

// --- kesme / zaman taklidi (enkoder testi icin) ---
#define CHANGE 1
static unsigned long _us = 0;
unsigned long micros() { return _us; }
int  digitalPinToInterrupt(uint8_t p) { return p; }
void attachInterrupt(int, void (*)(), int) {}
void noInterrupts() {}
void interrupts() {}
