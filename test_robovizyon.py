#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RoboVizyon dogrulama: birim testler + KAPALI CEVRIM simulasyon.

    python3 test_robovizyon.py

Son bolum asil onemli olan: sentetik pistte robotu surup GERCEK sapmayi olcer.
"""

import sys

import numpy as np
import cv2

from robovizyon import Konfig, Perspektif, SeritDedektoru, PurePursuit, MotorLink
from robovizyon.simulasyon import (SimKamera, SimArac, Sahne,
                                   pist_duz, pist_yay, pist_kose)

GECTI = BASARISIZ = 0


def kontrol(ad, sart, detay=""):
    global GECTI, BASARISIZ
    if sart:
        GECTI += 1
        print(f"  OK   {ad}  {detay}")
    else:
        BASARISIZ += 1
        print(f"  FAIL {ad}  {detay}")


def baslik(s):
    print(f"\n{'=' * 66}\n {s}\n{'=' * 66}")


# ============================================================================
baslik("1. PERSPEKTIF -- kusbakisi donusumu")
k = Konfig()
per = Perspektif(k.kamera, k.perspektif)
print("  " + per.gorus_alani_bilgisi())

for X, Y in [(0, 20), (-15, 40), (12, 60), (25, 30)]:
    u, v = per.dunya_to_kus(X, Y)
    X2, Y2 = per.kus_to_dunya(u, v)
    kontrol(f"gidis-donus ({X:+.0f},{Y:.0f}) cm",
            abs(X - X2) < 0.3 and abs(Y - Y2) < 0.3, f"-> ({X2:+.1f},{Y2:.1f})")

kontrol("kusbakisi boyutu makul",
        100 < per.genislik_px < 800 and 100 < per.yukseklik_px < 800,
        f"{per.genislik_px}x{per.yukseklik_px}")

# ============================================================================
baslik("2. BINARIZASYON -- esit olmayan aydinlatma altinda")
sim_kam = SimKamera(k.perspektif, k.kamera)
sahne = Sahne(pist_duz(200), sim_kam, k.serit.cizgi_genislik_cm)
ded = SeritDedektoru(k, per)

for carpan, ad in [(0.45, "cok karanlik"), (1.0, "normal"), (1.6, "cok parlak")]:
    kare = sahne.kare((0.0, 0.0, 0.0), isik_carpani=carpan)
    kus = per.warp(kare)
    ded.sifirla()
    o = None
    for _ in range(3):
        o = ded.isle(kus)
    kontrol(f"{ad} ({carpan:.2f}x) cizgi bulundu",
            o.gecerli and o.guven > 0.5,
            f"guven={o.guven:.2f} yanal={o.yanal_hata_cm:+.1f}cm")

# Bos zemin -> cizgi YOK demeli
bos = Sahne(np.array([[500.0, 500.0], [500.0, 501.0]]), sim_kam)
o = ded.isle(per.warp(bos.kare((0.0, 0.0, 0.0))))
kontrol("bos zeminde cizgi bulunmuyor", not o.gecerli, f"guven={o.guven:.2f}")

# ============================================================================
baslik("3. OLCUM DOGRULUGU -- yanal hata ve yon acisi gercekle uyusuyor mu")
sahne = Sahne(pist_duz(250), sim_kam, k.serit.cizgi_genislik_cm)

for gercek_X in (-10.0, -4.0, 0.0, 5.0, 11.0):
    ded.sifirla()
    o = None
    for _ in range(3):
        o = ded.isle(per.warp(sahne.kare((gercek_X, 0.0, 0.0))))
    # Arac X'te ise cizgi -X'te gorunur
    beklenen = -gercek_X
    hata = abs(o.yanal_hata_cm - beklenen) if o.gecerli else 99
    kontrol(f"yanal olcum  arac X={gercek_X:+5.1f} cm", o.gecerli and hata < 1.5,
            f"olculen={o.yanal_hata_cm:+.2f} beklenen={beklenen:+.1f} (fark {hata:.2f})")

for gercek_aci in (-12.0, -5.0, 0.0, 6.0, 14.0):
    ded.sifirla()
    o = None
    for _ in range(3):
        o = ded.isle(per.warp(sahne.kare((0.0, 0.0, np.radians(gercek_aci)))))
    olculen = np.degrees(o.yon_hatasi_rad) if o.gecerli else 99
    hata = abs(olculen - (-gercek_aci))
    kontrol(f"yon olcumu   arac {gercek_aci:+5.1f} deg", o.gecerli and hata < 4.0,
            f"olculen={olculen:+.1f} beklenen={-gercek_aci:+.1f}")

# ============================================================================
baslik("4. KOSE TESPITI -- 90 derece L viraj")
for sag, ad in [(True, "SAG"), (False, "SOL")]:
    sahne_k = Sahne(pist_kose(giris=70, cikis=80, sag=sag), sim_kam,
                    k.serit.cizgi_genislik_cm)
    ded.sifirla()
    tespit = None
    for Y in np.arange(0.0, 45.0, 3.0):          # koseye dogru yaklas
        o = ded.isle(per.warp(sahne_k.kare((0.0, Y, 0.0))))
        if o.kose_yonu != 0:
            tespit = (Y, o.kose_yonu, o.kose_mesafe_cm)
            break
    beklenen = +1 if sag else -1
    kontrol(f"{ad} kose tespit edildi", tespit is not None and tespit[1] == beklenen,
            f"Y={tespit[0]:.0f}cm'de, mesafe={tespit[2]:.0f}cm" if tespit else "TESPIT YOK")
    if tespit:
        gercek_mesafe = 70.0 - tespit[0]
        kontrol(f"{ad} kose mesafesi dogru", abs(tespit[2] - gercek_mesafe) < 12.0,
                f"olculen={tespit[2]:.0f} gercek={gercek_mesafe:.0f} cm")

# Duz yolda kose TETIKLENMEMELI (yanlis pozitif = gorev biter)
sahne_d = Sahne(pist_duz(250), sim_kam, k.serit.cizgi_genislik_cm)
ded.sifirla()
yanlis = 0
for Y in np.arange(0.0, 60.0, 2.0):
    o = ded.isle(per.warp(sahne_d.kare((0.0, Y, 0.0))))
    if o.kose_yonu != 0:
        yanlis += 1
kontrol("duz yolda YANLIS kose yok", yanlis == 0, f"{yanlis} yanlis tetikleme")

# Yumusak yayda da kose tetiklenmemeli
sahne_y = Sahne(pist_yay(yaricap=70, sag=True), sim_kam, k.serit.cizgi_genislik_cm)
ded.sifirla()
yanlis = 0
for Y in np.arange(0.0, 55.0, 2.0):
    o = ded.isle(per.warp(sahne_y.kare((0.0, Y, 0.0))))
    if o.kose_yonu != 0:
        yanlis += 1
kontrol("yumusak yayda YANLIS kose yok", yanlis == 0, f"{yanlis} yanlis tetikleme")

# ============================================================================
baslik("5. PURE PURSUIT -- isaret ve doyma")
pp = PurePursuit(k)


class SahteOlcum:
    def __init__(self, yanal, egrilik=0.0, bitis=70.0):
        self.gecerli = True
        self.guven = 1.0
        self.yanal_hata_cm = yanal
        self.yon_hatasi_rad = 0.0
        self.egrilik = egrilik
        self.bitis_y_cm = bitis
        self.referans_y_cm = k.perspektif.y_min_cm
        self._y = yanal

    def X_of_Y(self, Y):
        return self._y


pp.sifirla()
for _ in range(30):
    komut = pp.hesapla(SahteOlcum(+8.0), 0.033)
kontrol("cizgi SAGDA -> sol teker hizli", komut.sol_cm_s > komut.sag_cm_s,
        f"sol={komut.sol_cm_s:.1f} sag={komut.sag_cm_s:.1f} kappa={komut.egrilik:+.4f}")

pp.sifirla()
for _ in range(30):
    komut = pp.hesapla(SahteOlcum(-8.0), 0.033)
kontrol("cizgi SOLDA -> sag teker hizli", komut.sag_cm_s > komut.sol_cm_s,
        f"sol={komut.sol_cm_s:.1f} sag={komut.sag_cm_s:.1f}")

pp.sifirla()
for _ in range(30):
    komut = pp.hesapla(SahteOlcum(0.0), 0.033)
kontrol("cizgi ORTADA -> tekerler esit", abs(komut.sol_cm_s - komut.sag_cm_s) < 0.5,
        f"sol={komut.sol_cm_s:.1f} sag={komut.sag_cm_s:.1f}")

pp.sifirla()
duz = pp.hesapla(SahteOlcum(0.0), 0.033)
for _ in range(60):
    duz = pp.hesapla(SahteOlcum(0.0), 0.033)
pp.sifirla()
for _ in range(60):
    viraj = pp.hesapla(SahteOlcum(0.0, egrilik=0.03), 0.033)
kontrol("virajda hiz otomatik dusuyor", viraj.hiz_cm_s < duz.hiz_cm_s * 0.85,
        f"duz={duz.hiz_cm_s:.1f} viraj={viraj.hiz_cm_s:.1f} cm/s")

pp.sifirla()
for _ in range(60):
    komut = pp.hesapla(SahteOlcum(+28.0), 0.033)
kontrol("asiri hatada bile hiz sinirinda kaliyor",
        max(abs(komut.sol_cm_s), abs(komut.sag_cm_s)) <= k.kontrol.hiz_max_cm_s + 0.01,
        f"tepe={max(abs(komut.sol_cm_s), abs(komut.sag_cm_s)):.1f} "
        f"sinir={k.kontrol.hiz_max_cm_s}")

# ============================================================================
baslik("6. MOTOR CEVRIMI")
mot = MotorLink(k.motor, k.kontrol, kuru=True)
kontrol("0 cm/s -> notr", mot.hiz_to_dac(0) == k.motor.notr, f"{mot.hiz_to_dac(0)}")
kontrol("ileri > notr (YON=+1)", mot.hiz_to_dac(30) > k.motor.notr, f"{mot.hiz_to_dac(30)}")
kontrol("geri < notr", mot.hiz_to_dac(-30) < k.motor.notr, f"{mot.hiz_to_dac(-30)}")
kontrol("DAC araligi korunuyor",
        all(0 <= mot.hiz_to_dac(v) <= 4095 for v in (-999, -45, 0, 45, 999)))
s, g = mot.pivot_dac(+1)
kontrol("sag pivot simetrik", (s - k.motor.notr) == -(g - k.motor.notr), f"({s},{g})")
k2 = Konfig(); k2.motor.yon = -1
mot2 = MotorLink(k2.motor, k2.kontrol, kuru=True)
kontrol("YON=-1 tum yonleri ceviriyor",
        mot2.hiz_to_dac(30) < k2.motor.notr and mot2.pivot_dac(+1)[0] < k2.motor.notr,
        f"ileri={mot2.hiz_to_dac(30)} pivot={mot2.pivot_dac(+1)}")

# ============================================================================
baslik("7. KAPALI CEVRIM SIMULASYON -- gercek sapma olcumu")


def kosu(pist, ad, baslangic=(0.0, 0.0, 0.0), sure=14.0, dt=1 / 30.0,
         isik=1.0, gurultu=4.0):
    """Sentetik pistte tam yigini kostur, capraz hatayi olc."""
    kf = Konfig()
    pf = Perspektif(kf.kamera, kf.perspektif)
    df = SeritDedektoru(kf, pf)
    cf = PurePursuit(kf)
    sk = SimKamera(kf.perspektif, kf.kamera)
    sh = Sahne(pist, sk, kf.serit.cizgi_genislik_cm, gurultu=gurultu)
    ar = SimArac(kf.kontrol.iz_genisligi_cm, baslangic)

    hatalar, hizlar, gecersiz = [], [], 0
    n = int(sure / dt)
    for i in range(n):
        kare = sh.kare(ar.poz, isik_carpani=isik)
        olcum = df.isle(pf.warp(kare))
        if not olcum.gecerli:
            gecersiz += 1
        komut = cf.hesapla(olcum, dt)
        ar.adim(komut.sol_cm_s, komut.sag_cm_s, dt)

        # Pistin sonuna varinca bitir.
        # DIKKAT: "ar.Y > max(Y)" kullanmak SAGA/SOLA donen pistlerde hataliydi --
        # 90 derece donusten sonra Y sabit kalir, kosu virajin ORTASINDA kesilir
        # ve olculen sapma sadece giris gecici rejimini yansitirdi.
        # Pist sonu GORUS ALANINA girdiginde olcumu bitir. 20 cm gibi dar bir
        # esik kullanmak yanlisti: kamera y_max kadar ileriye baktigi icin arac
        # daha oraya varamadan cizgi biter, dogru sekilde durur, ve kalan
        # kareler sahte "cizgi kaybi" olarak sayilirdi.
        if np.hypot(ar.X - pist[-1, 0], ar.Y - pist[-1, 1]) < kf.perspektif.y_max_cm:
            break
        if i > n * 0.15:                       # ilk oturma suresini sayma
            hatalar.append(sh.capraz_hata(ar.poz))
            hizlar.append(komut.hiz_cm_s)

    if not hatalar:
        return None
    h = np.array(hatalar)
    return {
        "ad": ad,
        "ort_mm": float(np.mean(h) * 10.0),          # isaretli: + saga kaymis
        "rms_mm": float(np.sqrt(np.mean(h ** 2)) * 10.0),
        "max_mm": float(np.max(np.abs(h)) * 10.0),
        "ort_hiz": float(np.mean(hizlar)),
        "gecersiz_oran": gecersiz / max(1, i + 1),
        "kare": i + 1,
    }


senaryolar = [
    (pist_duz(320), "duz yol", (0.0, 0.0, 0.0), 1.0, 4.0),
    (pist_duz(320), "duz yol / 12 cm yanal offset ile basla", (12.0, 0.0, 0.0), 1.0, 4.0),
    (pist_duz(320), "duz yol / 20 derece egik basla", (0.0, 0.0, np.radians(20)), 1.0, 4.0),
    (pist_yay(yaricap=90, sag=True), "genis sag yay (R=90cm)", (0.0, 0.0, 0.0), 1.0, 4.0),
    (pist_yay(yaricap=55, sag=False), "dar sol yay (R=55cm)", (0.0, 0.0, 0.0), 1.0, 4.0),
    (pist_duz(320), "duz yol / KARANLIK salon", (0.0, 0.0, 0.0), 0.5, 4.0),
    (pist_duz(320), "duz yol / PARLAK + agir gurultu", (0.0, 0.0, 0.0), 1.5, 12.0),
]

print(f"\n  {'senaryo':<38} {'ORT':>9} {'RMS':>8} {'MAX':>8} {'hiz':>9} {'kayip':>7}")
print(f"  {'-' * 38} {'-' * 9} {'-' * 8} {'-' * 8} {'-' * 9} {'-' * 7}")
sonuclar = []
for pist, ad, bas, isik, gur in senaryolar:
    r = kosu(pist, ad, bas, isik=isik, gurultu=gur)
    if r is None:
        print(f"  {ad:<38} {'KOSU YOK':>8}")
        BASARISIZ += 1
        continue
    sonuclar.append(r)
    print(f"  {ad:<38} {r['ort_mm']:+7.1f}mm {r['rms_mm']:6.1f}mm {r['max_mm']:6.1f}mm "
          f"{r['ort_hiz']:6.1f}cm/s {r['gecersiz_oran'] * 100:5.1f}%")

print()
for r in sonuclar:
    duz = "duz" in r["ad"]
    # Esikler simulasyonda olculen gercek performansa gore, makul paylı.
    # Yayda kalan sapma Pure Pursuit'in geometrik ic-kesmesi + cember fit
    # yanliligidir; duz yolda ikisi de sifirdir.
    esik_rms = 8.0 if duz else 40.0
    esik_max = 25.0 if duz else 60.0
    kontrol(f"[{r['ad']}] RMS sapma < {esik_rms:.0f} mm",
            r["rms_mm"] < esik_rms, f"{r['rms_mm']:.1f} mm")
    kontrol(f"[{r['ad']}] tepe sapma < {esik_max:.0f} mm",
            r["max_mm"] < esik_max, f"{r['max_mm']:.1f} mm")
    kontrol(f"[{r['ad']}] cizgi kaybi < %5",
            r["gecersiz_oran"] < 0.05, f"%{r['gecersiz_oran'] * 100:.1f}")

# ============================================================================
baslik("8. GOREV -- 90 derece kose manevrasi (uctan uca)")

from robovizyon import Gorev, Durum, MotorLink as _ML
from robovizyon.kontrol import PurePursuit as _PP


def kose_kosusu(sag=True, sure=25.0, dt=1 / 30.0):
    """Kose iceren pistte tam yigini (algilama+kontrol+durum makinesi) kostur."""
    kf = Konfig()
    pf = Perspektif(kf.kamera, kf.perspektif)
    df = SeritDedektoru(kf, pf)
    cf = _PP(kf)
    mf = _ML(kf.motor, kf.kontrol, kuru=True)
    gf = Gorev(kf, df, cf, mf, qr_okuyucu=None)

    pist = pist_kose(giris=95, cikis=110, sag=sag)
    sh = Sahne(pist, SimKamera(kf.perspektif, kf.kamera), kf.serit.cizgi_genislik_cm)
    ar = SimArac(kf.kontrol.iz_genisligi_cm, (0.0, 0.0, 0.0))

    durumlar, hatalar = [], []
    pivot_gordu = False
    for i in range(int(sure / dt)):
        kare = sh.kare(ar.poz)
        olcum = df.isle(pf.warp(kare))
        tele = gf.adim(olcum, kare, dt, simdi=i * dt)
        durumlar.append(tele["durum"])
        if tele["durum"] in ("KOSE_PIVOT",):
            pivot_gordu = True

        sol, sag_ = mf._son_paket if mf._son_paket else (kf.motor.notr,) * 2
        # DAC -> cm/s geri cevrim (kuru modda gercek komutu izlemek icin)
        v = lambda dac: (dac - kf.motor.notr) / (kf.motor.yon * kf.motor.tam_gaz_ofset) \
                        * kf.kontrol.hiz_max_cm_s
        ar.adim(v(sol), v(sag_), dt)

        # Kose sonrasi duz kisimda hatayi olc
        if pivot_gordu and tele["durum"] == "TAKIP":
            hatalar.append(sh.capraz_hata(ar.poz))
        if np.hypot(ar.X - pist[-1, 0], ar.Y - pist[-1, 1]) < kf.perspektif.y_max_cm:
            break

    return durumlar, hatalar, ar.poz, pist


for sag, ad in [(True, "SAG"), (False, "SOL")]:
    durumlar, hatalar, son_poz, pist = kose_kosusu(sag)
    sira = []
    for d_ in durumlar:
        if not sira or sira[-1] != d_:
            sira.append(d_)
    print(f"  {ad} kose durum sirasi: {' -> '.join(sira)}")

    kontrol(f"{ad}: kose tespit edilip yaklasildi", "KOSE_YAKLAS" in sira)
    kontrol(f"{ad}: pivot manevrasi yapildi", "KOSE_PIVOT" in sira)
    kontrol(f"{ad}: pivot sonrasi TAKIP'e donuldu",
            "KOSE_PIVOT" in sira and sira.index("KOSE_PIVOT") < len(sira) - 1
            and "TAKIP" in sira[sira.index("KOSE_PIVOT"):])
    kontrol(f"{ad}: guvenli durusa dusmedi", "GUVENLI_DURUS" not in sira)
    if hatalar:
        h = np.array(hatalar)
        rms = float(np.sqrt(np.mean(h ** 2)) * 10)
        kontrol(f"{ad}: kose sonrasi takip saglam (RMS < 40 mm)", rms < 40.0,
                f"{rms:.1f} mm, {len(hatalar)} kare")
    else:
        kontrol(f"{ad}: kose sonrasi takibe donuldu", False, "hic TAKIP karesi yok")

    # Kose sonrasi dogru yone gitti mi?
    beklenen_x = pist[-1, 0]
    kontrol(f"{ad}: kose sonrasi dogru yonde ilerledi",
            (son_poz[0] > 25) if sag else (son_poz[0] < -25),
            f"son konum X={son_poz[0]:+.0f} cm (hedef {beklenen_x:+.0f})")

# ============================================================================
print(f"\n{'=' * 66}")
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print(f"{'=' * 66}")
sys.exit(1 if BASARISIZ else 0)
