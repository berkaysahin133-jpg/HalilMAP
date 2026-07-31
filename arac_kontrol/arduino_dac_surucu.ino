/*
 * RoboVizyon - MCP4725 cift kanal DAC motor surucu
 * Raspberry Pi 5 <-> Arduino (USB seri, 115200)
 *
 * Protokol : "<solDAC,sagDAC>\n"   (0..4095, 2048 = notr/duruş)
 * Cevap    : "OK,<sol>,<sag>\n"    (500 ms'de bir, Pi tarafi canlilik icin okur)
 *
 * v2 degisiklikleri:
 *   - parseInt() kaldirildi (1000 ms timeout ile loop'u kilitliyordu)
 *   - Karakter bazli bloklamayan ayristirici
 *   - RX buffer'daki TUM paketler okunur, sadece EN YENISI uygulanir (bayat komut yok)
 *   - I2C 400 kHz
 *   - Watchdog 400 -> 250 ms
 *   - Slew-rate limiter (akim sicramasi / patinaj engelleyici)
 */

#include <Wire.h>
#include <Adafruit_MCP4725.h>

Adafruit_MCP4725 dacSol, dacSag;

// ---------------- Ayarlar ----------------
const uint16_t NOTR         = 2048;   // 2.5V -> tam durus
const uint16_t WATCHDOG_MS  = 250;    // bu sure komut gelmezse cakili dur
const uint16_t HEARTBEAT_MS = 500;    // Pi'ye canlilik bildirimi

const bool     SLEW_AKTIF   = true;   // rampa sinirlayici
const uint8_t  SLEW_ADIM_MS = 14;     // ms basina izin verilen max DAC degisimi
                                      // 900 count'luk komut ~65 ms'de oturur
// -----------------------------------------

char    buf[16];
uint8_t bufLen       = 0;
bool    paketBasladi = false;

uint16_t hedefSol = NOTR, hedefSag = NOTR;   // Pi'den gelen son komut
uint16_t anlikSol = NOTR, anlikSag = NOTR;   // DAC'a fiilen yazilan (rampali)

unsigned long sonKomutMs     = 0;
unsigned long sonSlewMs      = 0;
unsigned long sonHeartbeatMs = 0;
bool          watchdogAktif  = true;         // acilista guvenli tarafta basla

void dacYaz(uint16_t sol, uint16_t sag) {
  dacSol.setVoltage(sol, false);   // false = EEPROM'a yazma (omur + hiz)
  dacSag.setVoltage(sag, false);
}

// Tek karakter isle. Tam paket tamamlandiysa true doner.
bool karakterIsle(char c) {
  if (c == '<') {                       // yeni paket basi -> yarim kalani at
    paketBasladi = true;
    bufLen = 0;
    return false;
  }
  if (!paketBasladi) return false;

  if (c == '>') {
    paketBasladi = false;
    buf[bufLen] = '\0';

    char *virgul = strchr(buf, ',');
    if (virgul == NULL) return false;
    *virgul = '\0';

    long sol = atol(buf);
    long sag = atol(virgul + 1);

    hedefSol = (uint16_t)constrain(sol, 0, 4095);
    hedefSag = (uint16_t)constrain(sag, 0, 4095);
    return true;
  }

  if (bufLen < sizeof(buf) - 1) {
    buf[bufLen++] = c;
  } else {                              // tasma -> paketi cop at
    paketBasladi = false;
    bufLen = 0;
  }
  return false;
}

// Hedefe dogru en fazla "adim" kadar yaklas
uint16_t rampala(uint16_t anlik, uint16_t hedef, uint16_t adim) {
  if (hedef > anlik) return (hedef - anlik <= adim) ? hedef : anlik + adim;
  if (hedef < anlik) return (anlik - hedef <= adim) ? hedef : anlik - adim;
  return anlik;
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(20);          // her ihtimale karsi

  Wire.begin();
  Wire.setClock(400000);          // 100k -> 400k, DAC yazimi ~yari sure

  dacSol.begin(0x60);
  dacSag.begin(0x61);

  dacYaz(NOTR, NOTR);
  delay(1000);                    // suruculerin notru gormesi icin

  sonSlewMs = millis();
}

void loop() {
  unsigned long simdi = millis();

  // --- 1) Seri: buffer'daki her seyi oku, sadece en yeni paketi tut ---
  bool yeniKomut = false;
  while (Serial.available() > 0) {
    if (karakterIsle((char)Serial.read())) yeniKomut = true;
  }
  if (yeniKomut) {
    sonKomutMs    = simdi;
    watchdogAktif = false;
  }

  // --- 2) Watchdog: komut kesilirse ANINDA notr (rampa yok) ---
  if (!watchdogAktif && (simdi - sonKomutMs > WATCHDOG_MS)) {
    watchdogAktif = true;
    hedefSol = hedefSag = NOTR;
    anlikSol = anlikSag = NOTR;
    dacYaz(NOTR, NOTR);
  }

  // --- 3) Rampa + DAC yazimi (sadece deger degistiyse I2C trafigi) ---
  if (!watchdogAktif) {
    uint16_t oncekiSol = anlikSol, oncekiSag = anlikSag;

    if (SLEW_AKTIF) {
      unsigned long gecen = simdi - sonSlewMs;
      if (gecen >= 1) {
        uint16_t adim = (uint16_t)min((unsigned long)SLEW_ADIM_MS * gecen, 4095UL);
        anlikSol  = rampala(anlikSol, hedefSol, adim);
        anlikSag  = rampala(anlikSag, hedefSag, adim);
        sonSlewMs = simdi;
      }
    } else {
      anlikSol = hedefSol;
      anlikSag = hedefSag;
    }

    if (anlikSol != oncekiSol || anlikSag != oncekiSag) {
      dacYaz(anlikSol, anlikSag);
    }
  } else {
    sonSlewMs = simdi;             // watchdog'dan cikinca rampa sifirdan
  }

  // --- 4) Heartbeat: Pi bagli mi, hangi degerdeyiz ---
  if (simdi - sonHeartbeatMs > HEARTBEAT_MS) {
    sonHeartbeatMs = simdi;
    Serial.print("OK,");
    Serial.print(anlikSol);
    Serial.print(",");
    Serial.println(anlikSag);
  }
}
