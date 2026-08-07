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




Adafruit_MCP4725 dacSol, dacSag;

// ---------------- Ayarlar ----------------
const uint16_t NOTR         = 2048;   // 2.5V -> tam durus
const uint16_t WATCHDOG_MS  = 250;    // bu sure komut gelmezse cakili dur
const uint16_t HEARTBEAT_MS = 500;    // Pi'ye canlilik bildirimi

const bool     SLEW_AKTIF   = true;   // rampa sinirlayici
const uint8_t  SLEW_ADIM_MS = 14;     // ms basina izin verilen max DAC degisimi

// ---------------- ACIL STOP ----------------
// Buton PWR hattini keser (asil koruma DONANIMSAL, bu kod onun yedegi degil).
// Buradaki is: buton BIRAKILDIGINDA aracin firlamasini onlemek.
//
// Senaryo: butona bastin, Kelly kapandi, ama Pi/Jetson hala "tam gaz"
// yaziyor. Butonu cevirip biraktigin anda Kelly aciliyor ve arac FIRLIYOR.
// Bu kod, buton birakildiktan sonra Pi NOTR gonderene kadar DAC'i notrde
// kilitli tutar.
//
// BAGLANTI -- iki secenek:
//   A) Butonun bos NO kontagi varsa:   NO -> D4,  diger uc -> GND
//      ACIL_TERS = false  (basilinca pin LOW olur, dahili pull-up yeterli)
//
//   B) Tek NC kontak varsa (PWR hattinda): butonun CIKIS ucundan gerilim
//      bolucu ile okuyoruz. 42 V paket icin:
//          PWR_cikis --[100k]--+--[10k]-- GND
//                              |
//                              +-- D4        (42 V -> 3.8 V, 5 V pin icin guvenli)
//      10k'nin uzerine 5.1 V zener + 100 nF koy (gurultu/asiri gerilim).
//      Basilinca hat 0 V olur -> pin LOW.  ACIL_TERS = false
const uint8_t  ACIL_PIN     = 4;      // acil stop okuma pini (0 = kullanma)
const bool     ACIL_TERS    = false;  // true: basilinca HIGH okunuyorsa
const uint16_t ACIL_NOTR_MS = 300;    // birakildiktan sonra bu kadar notr bekle
// A secenegi (NO kontak -> GND): true  -- dahili cekme direnci gerekli
// B secenegi (gerilim bolucu) : false -- bolucu zaten seviyeyi belirliyor
const bool     ACIL_PULLUP  = true;

// ---------------- ENKODER (Kelly "Meter" pini) ----------------
// Kelly KLS-S kilavuzu, bolum 3.2.1, DJ7091Y-2.3-21 konnektoru:
//     (8) Meter: Copy signal of hall sensors.   -- KOYU GRI kablo
// Motorun hall soketine DOKUNMADAN, gaz konnektorundeki koyu gri telden tek
// hall fazinin sinyali okunur.
//
// BAGLANTI:
//     SOL  Kelly pin 8 (koyu gri) -> D2      <- kesme pini
//     SAG  Kelly pin 8 (koyu gri) -> D3      <- kesme pini
//     Kelly pin 20 (RTN, siyah)   -> Arduino GND
//
//   DIKKAT: (15) Micro_SW "Gray", (8) Meter "Dark Gray". Renge guvenme --
//   tekerlegi elle cevirip multimetreyle oynayan teli bul.
//   5 V ustu olcersen dogrudan bagLAMA: 10k/4k7 gerilim bolucu koy.
//
// BEKLENEN: hoverboard hub motoru 15 kutup cifti, Meter tek faz kopyalar
//   -> elektriksel turda 2 kenar -> TUR BASINA ~30 kenar
//   -> 6.5 inc tekerde (518 mm cevre) ~17 mm/darbe, ~2.5 derece pivot
//
// GURULTU SUZGECI: 17.3 mm/darbe oldugu icin 10 m/s de bile darbeler 1727 us
// aralikli gelir. 500 us esik, gercek darbeye 3.5x pay birakirken 2 kHz ustu
// gurultuyu tamamen eler. (40 us denenmisti: gurultuyu ELEMIYOR, sadece
// 40 us de bire seyreltiyor -- test bunu yakaladi.)
//
// YON: Meter tek faz oldugu icin yon BILGISI YOK. Yonu biz biliyoruz --
// DAC'a yazdigimiz degerin isareti. NOTR'un altinda ileri, ustunde geri.
const uint8_t  ENK_SOL_PIN  = 2;      // 0 = enkoder kullanma
const uint8_t  ENK_SAG_PIN  = 3;
const uint16_t ENK_MIN_US   = 500;   // gurultu suzgeci -- asagidaki hesaba bak
const uint16_t ENK_YON_BANT = 30;     // NOTR yakininda son yonu koru
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

// ---------------- Acil stop durumu ----------------
bool          acilBasili   = false;   // su an basili mi
bool          acilKilit    = true;    // acilista KILITLI basla (guvenli taraf)
unsigned long acilBirakMs  = 0;       // ne zaman birakildi
bool          piNotrde     = true;    // Pi'nin gonderdigi son komut notr mu

// ---------------- Enkoder durumu ----------------
volatile long          enkSol = 0,        enkSag = 0;        // ISARETLI sayim
volatile unsigned long enkSonSolUs = 0,   enkSonSagUs = 0;
volatile int8_t        enkYonSol = 1,     enkYonSag = 1;     // +1 ileri, -1 geri
volatile unsigned int  enkElenen = 0;                        // gurultu sayaci

// Kesme yordamlari. Faz kablolarinin yanindan gecen hatlarda ani gurultu
// darbeleri olur; ENK_MIN_US'ten kisa araliklari saymiyoruz.
void enkISRSol() {
  unsigned long t = micros();
  if (t - enkSonSolUs < ENK_MIN_US) { enkElenen++; return; }
  enkSonSolUs = t;
  enkSol += enkYonSol;
}

void enkISRSag() {
  unsigned long t = micros();
  if (t - enkSonSagUs < ENK_MIN_US) { enkElenen++; return; }
  enkSonSagUs = t;
  enkSag += enkYonSag;
}

// Komut isaretinden yon. NOTR civarinda tekerlek serbest doner (kayis),
// o yuzden son yonu koruyoruz -- sifirlarsak yavaslarken sayim durur.
int8_t enkYonHesapla(uint16_t anlik, int8_t onceki) {
  if ((long)anlik + ENK_YON_BANT < (long)NOTR) return  1;   // ileri
  if ((long)anlik > (long)NOTR + ENK_YON_BANT) return -1;   // geri
  return onceki;
}

// Buton basili mi? Titremeye karsi 2 ardisik okuma.
bool acilOku() {
  if (ACIL_PIN == 0) return false;
  bool a = digitalRead(ACIL_PIN);
  delayMicroseconds(200);
  bool b = digitalRead(ACIL_PIN);
  if (a != b) return acilBasili;          // kararsiz -> onceki durumu koru
  return ACIL_TERS ? a : !a;              // varsayilan: basili = LOW
}

void setup() {
  Serial.begin(115200);
  Serial.setTimeout(20);          // her ihtimale karsi

  if (ACIL_PIN != 0) pinMode(ACIL_PIN, ACIL_PULLUP ? INPUT_PULLUP : INPUT);

  // Meter cikisi acik kolektorlu olabilir -> cekme direnci gerekli.
  if (ENK_SOL_PIN != 0) {
    pinMode(ENK_SOL_PIN, INPUT_PULLUP);
    attachInterrupt(digitalPinToInterrupt(ENK_SOL_PIN), enkISRSol, CHANGE);
  }
  if (ENK_SAG_PIN != 0) {
    pinMode(ENK_SAG_PIN, INPUT_PULLUP);
    attachInterrupt(digitalPinToInterrupt(ENK_SAG_PIN), enkISRSag, CHANGE);
  }

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
    // Pi'nin GERCEKTEN gonderdigi deger. Acil kilidi bunu okur; hedefSol'u
    // okusaydi kilitliyken zorladigimiz notru "Pi notr gonderdi" sanardik.
    piNotrde = (hedefSol == NOTR && hedefSag == NOTR);
  }

  // --- 1b) ACIL STOP: basiliyken notr, birakilinca Pi notre donene kadar kilit ---
  //
  // DIKKAT: kilit sartinda hedefSol/hedefSag OKUNMAZ. Cunku kilitliyken onlari
  // notre zorlarsak, bir sonraki dongude "Pi notr gonderdi" saniriz ve kilit
  // kendiliginden acilir. Bu yuzden Pi'nin GERCEKTEN gonderdigi son degeri
  // ayri bir bayrakta (piNotrde) tutuyoruz.
  bool oncekiAcil = acilBasili;
  acilBasili = acilOku();

  if (acilBasili) {
    if (!oncekiAcil) Serial.println("ACIL,BASILI");
    acilKilit = true;
  } else {
    if (oncekiAcil) {
      acilBirakMs = simdi;                 // birakildi, sayaci baslat
      Serial.println("ACIL,BIRAKILDI");
    }
    // Kilit ancak SU IKISI birden saglaninca acilir:
    //   1) Pi'den GELEN son komut notr (yazilim gaz vermiyor)
    //   2) Birakilali ACIL_NOTR_MS gecti (surucunun acilmasi icin sure)
    if (acilKilit && piNotrde && (simdi - acilBirakMs > ACIL_NOTR_MS)) {
      acilKilit = false;
      Serial.println("ACIL,SERBEST");
    }
  }

  // --- 1c) Enkoder yon isareti: DAC komutunun isaretinden ---
  enkYonSol = enkYonHesapla(anlikSol, enkYonSol);
  enkYonSag = enkYonHesapla(anlikSag, enkYonSag);

  if (acilKilit && (anlikSol != NOTR || anlikSag != NOTR)) {
    anlikSol = anlikSag = NOTR;            // hedef* DEGISTIRILMEZ
    dacYaz(NOTR, NOTR);                    // sadece degisince yaz, I2C'yi bogma
  }

  // --- 2) Watchdog: komut kesilirse ANINDA notr (rampa yok) ---
  if (!watchdogAktif && (simdi - sonKomutMs > WATCHDOG_MS)) {
    watchdogAktif = true;
    hedefSol = hedefSag = NOTR;
    anlikSol = anlikSag = NOTR;
    dacYaz(NOTR, NOTR);
  }

  // --- 3) Rampa + DAC yazimi (sadece deger degistiyse I2C trafigi) ---
  if (!watchdogAktif && !acilKilit) {
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
    // long 4 bayt, AVR'de tek islemde okunmaz -> kesmeleri kisa sure kapat
    noInterrupts();
    long eSol = enkSol, eSag = enkSag;
    unsigned int eGur = enkElenen;
    interrupts();

    Serial.print("OK,");
    Serial.print(anlikSol);
    Serial.print(",");
    Serial.print(anlikSag);
    Serial.print(",");
    Serial.print(acilBasili ? "ACIL" : (acilKilit ? "KILIT" : "HAZIR"));
    Serial.print(",");
    Serial.print(eSol);
    Serial.print(",");
    Serial.print(eSag);
    Serial.print(",");
    Serial.println(eGur);
  }
}
