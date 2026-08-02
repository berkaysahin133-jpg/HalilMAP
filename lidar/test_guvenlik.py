#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Guvenlik bolgesi testi -- LIDAR TAKILI OLMADAN calisir.

Sentetik taramalarla "engel su konumda" deyip beklenen karari dogrular.

    python3 test_guvenlik.py
"""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import guvenlik as G

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


def nokta(x_m, y_m):
    """Kartezyen konumu tarama olcumune cevirir (0 derece = ileri = +Y)."""
    aci = np.degrees(np.arctan2(x_m, y_m)) % 360.0
    return (aci, np.hypot(x_m, y_m) * 1000.0, 47)


def kutu(x_m, y_m, en=0.30, n=12):
    """(x,y) merkezli, `en` genisliginde yatay bir engel yuzeyi."""
    return [nokta(x_m + d, y_m) for d in np.linspace(-en / 2, en / 2, n)]


def bos_oda(yari=3.0, n=360):
    """Uzak duvarlar -- koridorda hicbir sey yok."""
    tur = []
    for i in range(n):
        a = i * (360.0 / n)
        r = np.radians(a)
        dx, dy = np.sin(r), np.cos(r)
        en_yakin = min(yari / abs(dx) if abs(dx) > 1e-6 else 1e9,
                       yari / abs(dy) if abs(dy) > 1e-6 else 1e9)
        tur.append((a, en_yakin * 1000.0, 47))
    return tur


def yeni(**kw):
    v = dict(yari_genislik_m=0.30, dur_m=0.40, yavas_m=0.90, min_nokta=2)
    v.update(kw)
    return G.Guvenlik(**v)


# ============================================================================
baslik("1. KOORDINAT DONUSUMU  (0 derece = ileri)")
P = G.tur_xy([(0.0, 1000.0, 47), (90.0, 2000.0, 47),
              (180.0, 1500.0, 47), (270.0, 500.0, 47)])
kontrol("0 derece -> ileri (+Y)", abs(P[0, 0]) < 1e-6 and abs(P[0, 1] - 1.0) < 1e-6,
        f"{P[0]}")
kontrol("90 derece -> sag (+X)", abs(P[1, 0] - 2.0) < 1e-6, f"{P[1]}")
kontrol("180 derece -> geri (-Y)", abs(P[2, 1] + 1.5) < 1e-6, f"{P[2]}")
kontrol("270 derece -> sol (-X)", abs(P[3, 0] + 0.5) < 1e-6, f"{P[3]}")

uc = [(0.0, 1000.0, 47), (180.0, 800.0, 47), (350.0, 900.0, 47)]
kontrol("duz kor aralik (170-190) sadece 180'i eliyor",
        len(G.tur_xy(uc, kor_acilar=[(170, 190)])) == 2,
        f"{len(G.tur_xy(uc, kor_acilar=[(170, 190)]))} nokta kaldi")
# 340-20 sarmal aralik: hem 350 hem 0 icine duser, geriye 180 kalir
kontrol("sarmal kor aralik (340-20) 0 ve 350'yi eliyor",
        len(G.tur_xy(uc, kor_acilar=[(340, 20)])) == 1,
        f"{len(G.tur_xy(uc, kor_acilar=[(340, 20)]))} nokta kaldi")
kontrol("kor aci yokken hicbir nokta elenmiyor", len(G.tur_xy(uc)) == 3)

# ============================================================================
baslik("2. TEMEL KARARLAR")
g = yeni()
kontrol("bos koridor -> SERBEST", g.degerlendir(bos_oda())["durum"] == "SERBEST")

g = yeni()
s = g.degerlendir(bos_oda() + kutu(0.0, 0.30))
kontrol("30 cm onde engel -> DUR", s["durum"] == "DUR",
        f"en yakin {s['en_yakin_m']*100:.0f} cm")

g = yeni()
s = g.degerlendir(bos_oda() + kutu(0.0, 0.70))
kontrol("70 cm onde engel -> YAVAS", s["durum"] == "YAVAS",
        f"en yakin {s['en_yakin_m']*100:.0f} cm")

g = yeni()
s = g.degerlendir(bos_oda() + kutu(0.0, 1.50))
kontrol("150 cm onde engel -> SERBEST", s["durum"] == "SERBEST",
        f"en yakin {s['en_yakin_m']*100:.0f} cm")

# ============================================================================
baslik("3. KORIDOR DISI GORMEZDEN GELINIYOR")
g = yeni()
s = g.degerlendir(bos_oda() + kutu(0.75, 0.30, en=0.20))
kontrol("75 cm yanda duran engel -> SERBEST", s["durum"] == "SERBEST",
        f"koridorda {s['koridor_nokta']} nokta")

g = yeni()
s = g.degerlendir(bos_oda() + kutu(0.0, -0.30))
kontrol("arkadaki engel -> SERBEST", s["durum"] == "SERBEST")

g = yeni()
s = g.degerlendir(bos_oda() + kutu(0.20, 0.30, en=0.10))
kontrol("koridor kenarindaki engel yakalaniyor", s["durum"] == "DUR",
        f"koridorda {s['koridor_nokta']} nokta")

# ============================================================================
baslik("4. GURULTUYE DAYANIKLILIK")
g = yeni()
s = g.degerlendir(bos_oda() + [nokta(0.05, 0.25)])          # tek nokta
kontrol("tek gurultu noktasi araci DURDURMUYOR", s["durum"] == "SERBEST",
        f"koridorda {s['koridor_nokta']} nokta, min_nokta=2")

g = yeni()
s = g.degerlendir(bos_oda() + [nokta(0.05, 0.25), nokta(0.08, 0.26)])
kontrol("iki nokta DURDURUYOR", s["durum"] == "DUR")

g = yeni(en_yakin_m=0.10)
s = g.degerlendir(bos_oda() + kutu(0.0, 0.05, en=0.10))     # govdenin uzeri
kontrol("5 cm'deki kendi govdesi sayilmiyor", s["durum"] == "SERBEST",
        f"koridorda {s['koridor_nokta']} nokta")

# ============================================================================
baslik("5. HISTEREZIS  --  esikte dur-kalk titremesi olmamali")
g = yeni(histerezis_m=0.12)
g.degerlendir(bos_oda() + kutu(0.0, 0.35))
kontrol("once DUR", g.durum == "DUR")
s = g.degerlendir(bos_oda() + kutu(0.0, 0.45))     # esigin 5 cm otesi
kontrol("esigin hemen otesinde DUR'da kaliyor", s["durum"] == "DUR",
        "45 cm, giris esigi 40 cm, cikis esigi 52 cm")
s = g.degerlendir(bos_oda() + kutu(0.0, 0.60))     # net cekildi
kontrol("net cekilince birakiyor", s["durum"] == "YAVAS",
        "60 cm -> yavas bolgesi")
s = g.degerlendir(bos_oda())
kontrol("engel gidince SERBEST", s["durum"] == "SERBEST")

# Titreme testi: engel esikte 20 kare boyunca +-2 cm oynasin
g = yeni(histerezis_m=0.12)
degisim = 0
onceki = None
rng = np.random.default_rng(0)
for _ in range(20):
    s = g.degerlendir(bos_oda() + kutu(0.0, 0.40 + rng.uniform(-0.02, 0.02)))
    if onceki is not None and s["durum"] != onceki:
        degisim += 1
    onceki = s["durum"]
kontrol("esikte titreyen engelde durum degisimi <= 1", degisim <= 1,
        f"{degisim} degisim / 20 kare")

# ============================================================================
baslik("6. HIZ CARPANI")
g = yeni()
kontrol("SERBEST -> x1.0", g.degerlendir(bos_oda())["hiz_carpani"] == 1.0)
g = yeni()
kontrol("YAVAS   -> x0.4",
        g.degerlendir(bos_oda() + kutu(0.0, 0.70))["hiz_carpani"] == 0.4)
g = yeni()
kontrol("DUR     -> x0.0",
        g.degerlendir(bos_oda() + kutu(0.0, 0.30))["hiz_carpani"] == 0.0)

# ============================================================================
baslik("7. GENISLIK/MESAFE AYARLARI ETKILI MI")
dar = yeni(yari_genislik_m=0.15)
s = dar.degerlendir(bos_oda() + kutu(0.25, 0.30, en=0.10))
kontrol("dar koridorda 25 cm yandaki engel gecersiz", s["durum"] == "SERBEST")
genis = yeni(yari_genislik_m=0.45)
s = genis.degerlendir(bos_oda() + kutu(0.25, 0.30, en=0.10))
kontrol("genis koridorda ayni engel DUR", s["durum"] == "DUR")

uzak = yeni(dur_m=0.80)
s = uzak.degerlendir(bos_oda() + kutu(0.0, 0.70))
kontrol("dur mesafesi 80 cm olunca 70 cm -> DUR", s["durum"] == "DUR")

# ============================================================================
baslik("8. BAYAT VERI GUVENLI TARAFA DUSUYOR MU")
oku = G.GuvenlikOkuyucu.__new__(G.GuvenlikOkuyucu)      # __init__ atla (LiDAR yok)
import threading as _t
oku._kilit = _t.Lock()
oku.bayat_s = 0.7
oku._son = {"durum": "SERBEST", "hiz_carpani": 1.0,
            "en_yakin_m": float("inf"), "koridor_nokta": 0}
oku._zaman = 0.0                                        # hic veri gelmemis
d = oku.durum()
kontrol("sensor susunca SERBEST'te kalmiyor", d["durum"] == "YAVAS",
        f"durum {d['durum']}, hiz x{d['hiz_carpani']}")
kontrol("bayat bayragi set", d["bayat"] is True)

import time as _time
oku._zaman = _time.monotonic()
d = oku.durum()
kontrol("taze veride durum korunuyor", d["durum"] == "SERBEST" and not d["bayat"])

# ============================================================================
print(f"\n{'=' * 66}")
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print(f"{'=' * 66}")
sys.exit(1 if BASARISIZ else 0)
