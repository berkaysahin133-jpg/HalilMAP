// ACIL STOP KILIT MANTIGI -- davranis testi (donanimsiz)
#include "arduino_stub.h"
#define digitalRead(p) _pinDurum
static int _pinDurum = HIGH;              // HIGH = buton BIRAKILMIS
#include "govde_test.inc"

static int gecti = 0, kaldi = 0;
void kontrol(const char* ad, bool sart, const char* detay = "") {
  if (sart) { gecti++; printf("  OK   %s  %s\n", ad, detay); }
  else      { kaldi++; printf("  FAIL %s  %s\n", ad, detay); }
}

// Pi'yi TAKLIT ET: gercek Pi 30 Hz komut gonderir. Tazelemezsek watchdog
// (250 ms) devreye girer ve testi biz bozariz.
void sur(uint16_t sol, uint16_t sag, int ms) {
  for (int gecen = 0; gecen < ms; gecen += 10) {
    hedefSol = sol; hedefSag = sag;
    sonKomutMs = _ms; watchdogAktif = false;
    piNotrde = (sol == NOTR && sag == NOTR);
    _ms += 10;
    loop();
  }
}

int main() {
  setup();
  printf("\n=== ACIL STOP KILIDI ===\n");

  kontrol("acilista KILITLI basliyor", acilKilit);
  sur(NOTR, NOTR, 600);
  kontrol("Pi notr gonderince kilit aciliyor", !acilKilit);

  sur(1500, 1500, 300);
  kontrol("kilit acikken gaz gecebiliyor", anlikSol != NOTR,
          anlikSol != NOTR ? "" : "DAC notrde kaldi");

  // --- BUTONA BAS ---
  _pinDurum = LOW;
  sur(1200, 1200, 30);
  kontrol("basilinca DAC ANINDA notr", anlikSol == NOTR && anlikSag == NOTR);
  kontrol("basiliyken kilit aktif", acilKilit);

  sur(1200, 1200, 500);          // basiliyken Pi tam gaz veriyor
  kontrol("basiliyken gaz komutu ETKISIZ", anlikSol == NOTR && anlikSag == NOTR);

  // --- BIRAK, ama Pi hala gaz veriyor: ASIL TEHLIKE ---
  _pinDurum = HIGH;
  sur(1200, 1200, 1000);
  kontrol("birakildi + Pi gaz veriyor -> KILIT DURUYOR", acilKilit);
  kontrol("  ve DAC hala notr (arac FIRLAMIYOR)",
          anlikSol == NOTR && anlikSag == NOTR);

  // --- Pi notre donunce serbest kalmali ---
  sur(NOTR, NOTR, 400);
  kontrol("Pi notre donunce kilit aciliyor", !acilKilit);
  sur(1500, 1500, 300);
  kontrol("sonra tekrar surulebiliyor", anlikSol != NOTR);

  // --- Kisa basma (500 ms) sonrasi da ayni kural ---
  _pinDurum = LOW;  sur(1400, 1400, 500);
  _pinDurum = HIGH; sur(1400, 1400, 3000);   // Pi hic notre donmuyor
  kontrol("Pi hic notre donmezse 3 sn sonra bile kilitli", acilKilit);
  kontrol("  DAC notrde", anlikSol == NOTR);

  // --- Birakma anindan itibaren bekleme suresi ---
  sur(NOTR, NOTR, 20);           // notr geldi ama birakilali cok oldu
  kontrol("birakilali cok olduysa notr gelince hemen acilir", !acilKilit,
          "(300 ms birakma anindan sayilir, notr anindan degil)");

  printf("\n GECTI: %d   BASARISIZ: %d\n", gecti, kaldi);
  return kaldi ? 1 : 0;
}
