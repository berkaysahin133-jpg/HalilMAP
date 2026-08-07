// ENKODER SAYIMI -- kart ve motor olmadan davranis testi
#include "arduino_stub.h"
#define digitalRead(p) _pinDurum
static int _pinDurum = HIGH;              // acil stop birakilmis
#include "govde_test.inc"

static int gecti = 0, kaldi = 0;
void kontrol(const char* ad, bool sart, const char* d = "") {
  if (sart) { gecti++; printf("  OK   %s  %s\n", ad, d); }
  else      { kaldi++; printf("  FAIL %s  %s\n", ad, d); }
}
void sur(uint16_t sol, uint16_t sag, int ms) {
  for (int g = 0; g < ms; g += 10) {
    hedefSol = sol; hedefSag = sag;
    sonKomutMs = _ms; watchdogAktif = false;
    piNotrde = (sol == NOTR && sag == NOTR);
    _ms += 10; _us += 10000;
    loop();
  }
}
// Meter pininden n darbe gelmis gibi yap (araliklari genis, suzgec elemesin)
void darbe(int n, unsigned long aralik_us = 1000) {
  for (int i = 0; i < n; i++) { _us += aralik_us; enkISRSol(); enkISRSag(); }
}

int main() {
  setup();
  printf("\n=== ENKODER SAYIMI ===\n");

  sur(NOTR, NOTR, 600);                       // acil kilidi acilsin

  // --- ILERI ---
  sur(1500, 1500, 100);                       // NOTR altinda = ileri
  long once = enkSol;
  darbe(30);
  kontrol("ileri surerken sayim ARTIYOR", enkSol - once == 30,
          (std::to_string(enkSol - once) + " darbe").c_str());

  // --- GERI ---
  sur(2600, 2600, 100);                       // NOTR ustunde = geri
  once = enkSol;
  darbe(30);
  kontrol("geri surerken sayim AZALIYOR", enkSol - once == -30,
          (std::to_string(enkSol - once) + " darbe").c_str());

  // --- Bir tur ileri + bir tur geri = net sifir ---
  long baslangic = enkSol;
  sur(1500, 1500, 60); darbe(30);
  sur(2600, 2600, 60); darbe(30);
  kontrol("30 ileri + 30 geri = net 0", enkSol - baslangic == 0,
          (std::to_string(enkSol - baslangic)).c_str());

  // --- NOTR'da son yon korunuyor (yavaslarken sayim durmasin) ---
  sur(1500, 1500, 60);                        // ileri
  sur(NOTR, NOTR, 60);                        // notre cek
  once = enkSol;
  darbe(10);
  kontrol("notrde son yon korunuyor (kayarken sayiyor)", enkSol - once == 10,
          (std::to_string(enkSol - once) + " darbe").c_str());

  // --- GURULTU SUZGECI ---
  unsigned int gurOnce = enkElenen;
  once = enkSol;
  darbe(20, 10);                              // 10 us aralik -> hepsi elenmeli
  kontrol("40 us'ten kisa darbeler ELENIYOR", enkSol - once == 0,
          (std::to_string(enkElenen - gurOnce) + " darbe elendi").c_str());

  once = enkSol;
  darbe(20, 5000);                            // 5 ms = ~3.5 m/s -> gecmeli
  kontrol("gercek darbeler suzgecten GECIYOR", enkSol - once == 20,
          (std::to_string(enkSol - once)).c_str());

  // --- SOL ve SAG bagimsiz ---
  long s0 = enkSol, g0 = enkSag;
  _us += 1000; enkISRSol();                   // sadece sol
  kontrol("sol ve sag bagimsiz sayiyor",
          enkSol - s0 == 1 && enkSag - g0 == 0,
          ("sol +" + std::to_string(enkSol - s0) +
           "  sag +" + std::to_string(enkSag - g0)).c_str());

  // --- Acil stop enkoderi bozmamali ---
  _pinDurum = LOW; sur(1500, 1500, 50);
  once = enkSol; darbe(15);
  kontrol("acil stop basiliyken de sayim devam ediyor", enkSol - once != 0,
          "(tekerlek elle dondurulebilir, konum kaybolmamali)");
  _pinDurum = HIGH; sur(NOTR, NOTR, 500);

  // --- Cozunurluk hesabi ---
  printf("\n  Hoverboard 15 kutup cifti, Meter tek faz:\n");
  printf("    tur basina 30 kenar  ->  518 mm / 30 = %.1f mm/darbe\n", 518.0/30);
  printf("    40 cm iz genisliginde tek darbe = %.2f derece pivot\n",
         (518.0/30) / 400.0 * 57.2958);

  printf("\n GECTI: %d   BASARISIZ: %d\n", gecti, kaldi);
  return kaldi ? 1 : 0;
}
