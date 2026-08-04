#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kara kutu testi -- ARAC OLMADAN calisir.

Bilinen sekilli konturlar uretip kara kutunun DOGRU teshisi koydugunu
dogrular. Teshis araci yanlis teshis koyarsa hic olmamasindan kotudur.

    python3 test_kara_kutu.py
"""

import csv
import os
import shutil
import sys
import tempfile

import cv2
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import kara_kutu as KK

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


def maske_kur(dikdortgenler):
    """160x120 maske uretir. dikdortgen = (x, y, w, h)."""
    m = np.zeros((120, 160), np.uint8)
    for x, y, w, h in dikdortgenler:
        m[y:y + h, x:x + w] = 255
    return m


def en_buyuk_kontur(maske):
    c, _ = cv2.findContours(maske, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)
    return max(c, key=cv2.contourArea) if c else None


def kutu_kur(klasor):
    return KK.KaraKutu(klasor=klasor, saniye=1.0, acik=True)


gecici = tempfile.mkdtemp(prefix="kk_test_")

# ============================================================================
baslik("1. OLCUMLER DOGRU SUTUNA YAZILIYOR MU")
# Bilinen kutu: x=20, y=30, w=100, h=12  -> alan 1200
maske = maske_kur([(20, 30, 100, 12)])
goruntu = cv2.cvtColor(maske, cv2.COLOR_GRAY2BGR)
kk = kutu_kur(os.path.join(gecici, "t1"))
kk.kare("CIZGI_TAKIP", goruntu, maske, en_buyuk_kontur(maske))
kk.kapat()

with open(os.path.join(gecici, "t1", "surekli.csv"), encoding="utf-8") as f:
    satirlar = list(csv.DictReader(f))
s = satirlar[0]
kontrol("x dogru", int(s["x"]) == 20, f"x={s['x']}")
kontrol("y dogru", int(s["y"]) == 30, f"y={s['y']}")
kontrol("w dogru (h ile karismamis)", int(s["w"]) == 100, f"w={s['w']} h={s['h']}")
kontrol("h dogru", int(s["h"]) == 12, f"h={s['h']}")
kontrol("alan dogru (~1200)", 1000 <= int(s["alan"]) <= 1300, f"alan={s['alan']}")
kontrol("cx dogru (~70)", 60 <= int(s["cx"]) <= 80, f"cx={s['cx']}")

# ============================================================================
baslik("2. KOSE KOSULLARI KODLA AYNI SONUCU VERIYOR MU")


def kosullar(dikdortgenler):
    m = maske_kur(dikdortgenler)
    kk = kutu_kur(os.path.join(gecici, "k" + str(abs(hash(str(dikdortgenler))))))
    kk.kare("CIZGI_TAKIP", cv2.cvtColor(m, cv2.COLOR_GRAY2BGR), m,
            en_buyuk_kontur(m))
    kk.kapat()
    with open(os.path.join(kk.klasor, "surekli.csv"), encoding="utf-8") as f:
        r = list(csv.DictReader(f))[0]
    return int(r["sol_kosul"]), int(r["sag_kosul"]), r


# Sol L-viraj: sol kenara dayanmis genis yatay kol (x<15, w>65, alan>600)
sol, sag, r = kosullar([(5, 40, 90, 14)])
kontrol("sol L-viraj tetikleniyor", sol == 1 and sag == 0,
        f"sol={sol} sag={sag} (x=5 w=90 alan={r['alan']})")

# Sag L-viraj: sag kenara dayanmis (x+w>145, w>65)
sol, sag, r = kosullar([(65, 40, 92, 14)])
kontrol("sag L-viraj tetikleniyor", sag == 1 and sol == 0,
        f"sol={sol} sag={sag} (x+w={65+92})")

# Duz cizgi: ortada dar dikey serit -> hicbiri tetiklenmemeli
sol, sag, r = kosullar([(72, 10, 16, 100)])
kontrol("duz cizgide kose tetiklenmiyor", sol == 0 and sag == 0,
        f"sol={sol} sag={sag} (w=16)")

# Genis ama alan kucuk (ince uzun): alan>600 saglanmazsa tetiklenmemeli
sol, sag, r = kosullar([(5, 60, 80, 4)])
kontrol("alan yetersizse tetiklenmiyor", sol == 0,
        f"alan={r['alan']} (600'un altinda)")

# ============================================================================
baslik("3. TESHIS DOGRU MU  --  alan hic yetmiyorsa")
kk = kutu_kur(os.path.join(gecici, "t3"))
for _ in range(10):
    m = maske_kur([(5, 60, 80, 5)])          # genis ama cok ince -> alan ~400
    kk.kare("CIZGI_TAKIP", cv2.cvtColor(m, cv2.COLOR_GRAY2BGR), m,
            en_buyuk_kontur(m))
kk.dok("kayip")
kk.kapat()
ozet = open(os.path.join(gecici, "t3", "kayip_001", "ozet.txt"),
            encoding="utf-8").read()
kontrol("ALGILAMA sorunu teshisi konuldu", "ALGILAMA sorunu" in ozet)
kontrol("sebep olarak alan gosterildi", "alan hic 600" in ozet)
kontrol("somut yeni esik onerildi", "Denenecek: alan esigini" in ozet,
        [x for x in ozet.splitlines() if "Denenecek" in x])

# ============================================================================
baslik("4. TESHIS DOGRU MU  --  genislik hic yetmiyorsa")
kk = kutu_kur(os.path.join(gecici, "t4"))
for _ in range(10):
    m = maske_kur([(5, 40, 40, 30)])         # alan 1200 ama w=40 (<65)
    kk.kare("CIZGI_TAKIP", cv2.cvtColor(m, cv2.COLOR_GRAY2BGR), m,
            en_buyuk_kontur(m))
kk.dok("kayip")
kk.kapat()
ozet = open(os.path.join(gecici, "t4", "kayip_001", "ozet.txt"),
            encoding="utf-8").read()
kontrol("genislik sebebi dogru tespit edildi", "genisligi hic 65" in ozet,
        [x for x in ozet.splitlines() if "Sebep" in x])
kontrol("en buyuk w dogru raporlandi", "en buyuk w 40" in ozet,
        [x for x in ozet.splitlines() if "w > 65" in x])

# ============================================================================
baslik("5. TESHIS DOGRU MU  --  kose tetiklendiyse pivot sorunu demeli")
kk = kutu_kur(os.path.join(gecici, "t5"))
for _ in range(10):
    m = maske_kur([(5, 40, 90, 14)])         # gercek sol L-viraj
    kk.kare("KESKIN_VIRAJ_SOL", cv2.cvtColor(m, cv2.COLOR_GRAY2BGR), m,
            en_buyuk_kontur(m))
kk.dok("kayip")
kk.kapat()
ozet = open(os.path.join(gecici, "t5", "kayip_001", "ozet.txt"),
            encoding="utf-8").read()
kontrol("algilama calisiyor denildi", "algilama calisiyor" in ozet)
kontrol("pivot/sure sorununa yonlendirdi", "VIRAJ_ILERI_SURESI" in ozet)

# ============================================================================
baslik("6. DOKUM DOSYALARI YAZILDI MI")
yol = os.path.join(gecici, "t5", "kayip_001")
pngler = [f for f in os.listdir(yol) if f.endswith(".png")]
kontrol("kareler PNG olarak yazildi", len(pngler) == 10, f"{len(pngler)} dosya")
kontrol("olcumler.csv yazildi", os.path.exists(os.path.join(yol, "olcumler.csv")))
kontrol("ozet.txt yazildi", os.path.exists(os.path.join(yol, "ozet.txt")))
ornek = cv2.imread(os.path.join(yol, pngler[0]))
kontrol("PNG okunabilir ve 640 genisliginde",
        ornek is not None and ornek.shape[1] == 640,
        f"{ornek.shape if ornek is not None else 'okunamadi'}")

# ============================================================================
baslik("7. KONTUR YOKKEN COKMUYOR")
kk = kutu_kur(os.path.join(gecici, "t7"))
bos = np.zeros((120, 160), np.uint8)
try:
    kk.kare("KURTARMA_MODU", cv2.cvtColor(bos, cv2.COLOR_GRAY2BGR), bos, None)
    kk.dok("kayip")
    kk.kapat()
    kontrol("kontur None iken calisiyor", True)
except Exception as e:
    kontrol("kontur None iken calisiyor", False, str(e))

kk = KK.KaraKutu(klasor=os.path.join(gecici, "t8"), acik=False)
try:
    kk.kare("X", None, None, None)
    kk.dok()
    kk.kapat()
    kontrol("ACIK=False iken hicbir sey yapmiyor", True)
except Exception as e:
    kontrol("ACIK=False iken hicbir sey yapmiyor", False, str(e))

shutil.rmtree(gecici, ignore_errors=True)

print(f"\n{'=' * 66}")
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print(f"{'=' * 66}")
sys.exit(1 if BASARISIZ else 0)
