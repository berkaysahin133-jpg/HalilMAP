/* ===========================================================================
   DARBE TEST  --  bir pinde hiz/tako darbesi var mi, tur basina kac darbe?

   Ne ise yarar:
     Kelly surucusunun konnektorunde "speed / meter / tacho / pulse / hall out"
     benzeri bir cikis olabilir. Kilavuzdan hangi pin oldugunu bulunca BU KODLA
     dogrularsin: darbe geliyor mu, tur basina kac tane, yon bilgisi var mi.
     Ayni kod motorun hall sensorune paralel baglandiginda da calisir.

   ---------------------------------------------------------------------------
   ONCE MULTIMETRE  --  Arduino'yu yakmadan once bunu yap
   ---------------------------------------------------------------------------
     1. Kelly'yi calistir, tekerlegi ELLE yavasca cevir.
     2. Aday pin ile GND arasini DC voltta olc.
     3. 0-5 V arasi oynuyorsa  -> guvenli, dogrudan bagla.
        5 V'un USTUNDE ise     -> DOGRUDAN BAGLAMA. Once gerilim bolucu:
                                  sinyal --[10k]--+--[10k]-- GND
                                                  |
                                               Arduino pini      (12V -> 6V,
                                  12 V icin 10k/4.7k daha iyi: 12 -> 3.8 V)
     4. Hic oynamiyorsa -> yanlis pin, listedeki digerini dene.

   ---------------------------------------------------------------------------
   BAGLANTI
   ---------------------------------------------------------------------------
     Aday sinyal 1  -> D2
     Aday sinyal 2  -> D3        (ikinci bir pini ayni anda denemek icin)
     Kelly GND      -> Arduino GND     <-- ORTAK TOPRAK SART, unutma

   ---------------------------------------------------------------------------
   KULLANIM  (Seri Monitor, 115200)
   ---------------------------------------------------------------------------
     Yarim saniyede bir: pin durumu, saniyedeki darbe, toplam darbe.

     r  sayaclari sifirla
     k  KALIBRASYON: bas, tekerlegi ELLE TAM 1 TUR cevir, tekrar bas.
        Tur basina darbe sayisini yazar. Odometri icin gereken sayi budur.

   Beklenen sonuclar:
     hall sensorune paralel, tek hat  -> tur basina ~30 darbe (CHANGE ile)
     Kelly tako cikisi                -> genelde cok daha az (1-15)
     hicbir sey                       -> 0, baska pin dene
   =========================================================================== */

const uint8_t PIN_A = 2;              // Uno/Nano/Mega: D2 ve D3 kesme pinidir
const uint8_t PIN_B = 3;

/* Faz kablolarinin yanindan gecen hatlarda ani gurultu darbeleri olur.
   Bundan kisa araliklari saymiyoruz. Cok yuksek yaparsan gercek darbeleri de
   yersin: 5000 d/dk ve tur basina 90 darbe -> darbe arasi ~133 us. */
const uint16_t MIN_ARALIK_US = 40;

volatile uint32_t sayacA = 0, sayacB = 0;
volatile uint32_t sonA = 0, sonB = 0;
volatile uint32_t elenenA = 0, elenenB = 0;

void isrA() {
  uint32_t t = micros();
  if (t - sonA < MIN_ARALIK_US) { elenenA++; return; }
  sonA = t;
  sayacA++;
}

void isrB() {
  uint32_t t = micros();
  if (t - sonB < MIN_ARALIK_US) { elenenB++; return; }
  sonB = t;
  sayacB++;
}

uint32_t sonYazma = 0;
uint32_t oncekiA = 0, oncekiB = 0;
bool kalibrasyon = false;
uint32_t kalibA = 0, kalibB = 0;

void setup() {
  Serial.begin(115200);
  /* INPUT_PULLUP: acik kolektorlu cikislar (hall sensorleri boyledir) kendi
     basina yuksek seviye uretemez, cekme direnci gerekir. Push-pull bir cikis
     icin de zararsizdir. */
  pinMode(PIN_A, INPUT_PULLUP);
  pinMode(PIN_B, INPUT_PULLUP);
  attachInterrupt(digitalPinToInterrupt(PIN_A), isrA, CHANGE);
  attachInterrupt(digitalPinToInterrupt(PIN_B), isrB, CHANGE);

  Serial.println();
  Serial.println(F("=== DARBE TEST ==="));
  Serial.println(F("D2 ve D3'u izliyorum. Ortak toprak bagli olmali."));
  Serial.println(F("Tekerlegi elle cevir; darbe/sn sifirdan buyuk olmali."));
  Serial.println(F("r = sifirla    k = tur basina darbe kalibrasyonu"));
  Serial.println();
}

void loop() {
  if (Serial.available()) {
    char c = Serial.read();
    if (c == 'r' || c == 'R') {
      noInterrupts();
      sayacA = sayacB = elenenA = elenenB = 0;
      interrupts();
      oncekiA = oncekiB = 0;
      Serial.println(F("[sifirlandi]"));
    } else if (c == 'k' || c == 'K') {
      noInterrupts();
      uint32_t a = sayacA, b = sayacB;
      interrupts();
      if (!kalibrasyon) {
        kalibA = a; kalibB = b;
        kalibrasyon = true;
        Serial.println();
        Serial.println(F(">>> TEKERLEGI ELLE TAM 1 TUR CEVIR, sonra tekrar 'k'"));
        Serial.println(F("    (isaret koy: supap, vida, bant -- tam ayni yere gelsin)"));
      } else {
        kalibrasyon = false;
        Serial.println();
        Serial.println(F(">>> TUR BASINA DARBE"));
        Serial.print(F("    D2: ")); Serial.println(a - kalibA);
        Serial.print(F("    D3: ")); Serial.println(b - kalibB);
        uint32_t n = a - kalibA;
        if (n > 0) {
          /* 6.5 inc hoverboard tekeri: 165 mm cap -> 518 mm cevre.
             Baska olcuyse bu sayiyi kendin degistir. */
          Serial.print(F("    -> cozunurluk: "));
          Serial.print(518.0 / n, 2);
          Serial.println(F(" mm/darbe  (165 mm capli teker icin)"));
          if (n < 10) {
            Serial.println(F("    [UYARI] Cok dusuk. Odometri icin zayif;"));
            Serial.println(F("            pivot acisi icin yine de ise yarar."));
          }
        } else {
          Serial.println(F("    [YOK] Hic darbe gelmedi -- yanlis pin ya da"));
          Serial.println(F("          ortak toprak bagli degil."));
        }
        Serial.println();
      }
    }
  }

  uint32_t simdi = millis();
  if (simdi - sonYazma < 500) return;
  uint32_t dt = simdi - sonYazma;
  sonYazma = simdi;

  noInterrupts();
  uint32_t a = sayacA, b = sayacB, ea = elenenA, eb = elenenB;
  interrupts();

  uint32_t hizA = (a - oncekiA) * 1000UL / dt;
  uint32_t hizB = (b - oncekiB) * 1000UL / dt;
  oncekiA = a; oncekiB = b;

  Serial.print(F("D2 sev=")); Serial.print(digitalRead(PIN_A));
  Serial.print(F(" darbe/sn=")); Serial.print(hizA);
  Serial.print(F(" toplam=")); Serial.print(a);
  Serial.print(F("   |   D3 sev=")); Serial.print(digitalRead(PIN_B));
  Serial.print(F(" darbe/sn=")); Serial.print(hizB);
  Serial.print(F(" toplam=")); Serial.print(b);
  if (ea || eb) {
    Serial.print(F("   [gurultu elendi A=")); Serial.print(ea);
    Serial.print(F(" B=")); Serial.print(eb); Serial.print(F("]"));
  }
  if (kalibrasyon) Serial.print(F("   *KALIBRASYON*"));
  Serial.println();
}
