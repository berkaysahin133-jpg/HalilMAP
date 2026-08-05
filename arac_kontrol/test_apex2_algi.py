#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cizgi_takip_apex2.py ALGI katmanini KAMERASIZ olcer.

Sentetik 320x240 goruntuler uretip Algi.isle() ne dondugune bakar:
duz cizgide sapma dogru mu, 90 derece kose YAKALANIYOR MU ve hangi
mesafede yakalaniyor.

    python3 test_apex2_algi.py
"""

import os
import sys

import cv2
import numpy as np

KLASOR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, KLASOR)

# apex2 modul seviyesinde argparse calistiriyor -> once argv'yi temizle
sys.argv = [sys.argv[0], "--kuru"]
try:
    import cizgi_takip_apex2 as A
except SystemExit:
    print("[HATA] cizgi_takip_apex2.py ice aktarilamadi")
    raise

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
    print(f"\n{'=' * 72}\n {s}\n{'=' * 72}")


# ---------------------------------------------------------------- goruntuler
def bos(deger=200):
    """320x240 acik zemin (kamera cozunurlugu)."""
    return np.full((240, 320, 3), deger, np.uint8)


def duz(kayma_px=0, kalinlik=24):
    """Dikey siyah cizgi. kayma_px: 320'lik goruntude merkezden sapma."""
    g = bos()
    x = 160 + kayma_px
    cv2.rectangle(g, (x - kalinlik // 2, 0), (x + kalinlik // 2, 240), (30, 30, 30), -1)
    return g


def kose(yon="SOL", kol_y=120, kalinlik=24):
    """90 derece L viraj.

    Dikey cizgi asagidan yukari `kol_y` seviyesine kadar gelir, orada
    yatay kol baslar ve kadrajin kenarina uzanir.
    kol_y kucuk = kose UZAKTA (goruntude yukarida)
    kol_y buyuk = kose YAKINDA
    """
    g = bos()
    x = 160
    y = kol_y
    cv2.rectangle(g, (x - kalinlik // 2, y), (x + kalinlik // 2, 240), (30, 30, 30), -1)
    if yon == "SOL":
        cv2.rectangle(g, (0, y - kalinlik // 2), (x + kalinlik // 2, y + kalinlik // 2),
                      (30, 30, 30), -1)
    else:
        cv2.rectangle(g, (x - kalinlik // 2, y - kalinlik // 2), (320, y + kalinlik // 2),
                      (30, 30, 30), -1)
    return g


def olc(goruntu, kare=8):
    """Algi'yi birkac kare besleyip (esik EMA otursun) sonucu doner."""
    a = A.Algi()
    s = None
    for _ in range(kare):
        s = a.isle(goruntu)
    return s


# ============================================================================
baslik("1. DUZ CIZGI  --  sapma dogru olculuyor mu")
for kayma, beklenen_isaret in [(0, 0), (+60, +1), (-60, -1)]:
    s = olc(duz(kayma))
    # 320 -> 160 kucultme: 1 px sapma = 0.5 px isleme sapmasi
    beklenen = kayma / 2.0
    kontrol(f"kayma {kayma:+4d} px  ->  cizgi bulundu", s["bulundu"],
            f"profil {len(s['profil'])} satir, esik {s['esik']}")
    if s["bulundu"]:
        olculen = s["cx_yakin"] - A.ORTA
        kontrol(f"kayma {kayma:+4d} px  ->  sapma dogru",
                abs(olculen - beklenen) < 4.0,
                f"beklenen {beklenen:+.1f}, olculen {olculen:+.1f} px")
        kontrol(f"kayma {kayma:+4d} px  ->  kose YOK sayildi",
                s["kose_yon"] is None,
                f"kose_yon={s['kose_yon']}")

# ============================================================================
baslik("2. 90 DERECE KOSE  --  hangi mesafede yakalaniyor")
print("  kol_y kucuk = kose uzakta (kadrajin ustunde)")
print("  kol_y buyuk = kose yakinda (arac uzerinde)")
print()
print("  yon   kol_y  bulundu  profil  cizgi_gen  kose_esigi  kose_yon  kose_y")
print("  " + "-" * 68)

yakalama = {"SOL": [], "SAG": []}
for yon in ("SOL", "SAG"):
    for kol_y in (60, 80, 100, 120, 140, 160, 180, 200):
        s = olc(kose(yon, kol_y))
        gen = s["cizgi_gen"]
        esik = max(A.L_GEN_KAT * gen, A.L_MIN_GEN)
        ky = s["kose_y"]
        print(f"  {yon:4s}  {kol_y:4d}   {str(s['bulundu']):5s}   "
              f"{len(s['profil']):4d}    {gen:6.1f}     {esik:6.1f}    "
              f"{str(s['kose_yon']):5s}    {'-' if ky is None else ky}")
        if s["kose_yon"] == yon:
            yakalama[yon].append(kol_y)

print()
for yon in ("SOL", "SAG"):
    kontrol(f"{yon} kose en az bir mesafede yakalandi", len(yakalama[yon]) > 0,
            f"yakalanan kol_y degerleri: {yakalama[yon] or 'HICBIRI'}")

# Apex tetigi icin kose_y >= KOSE_TETIK_Y (78) olmali; isleme cozunurlugunde
kontrol("SOL kose apex tetigine kadar izlenebiliyor",
        any(olc(kose("SOL", k))["kose_y"] is not None and
            olc(kose("SOL", k))["kose_y"] >= A.KOSE_TETIK_Y
            for k in (140, 160, 180, 200)),
        f"KOSE_TETIK_Y={A.KOSE_TETIK_Y}")

# ============================================================================
baslik("3. KOSE YONU DOGRU MU  --  sol/sag karismiyor mu")
for yon in ("SOL", "SAG"):
    yanlis = []
    for kol_y in (100, 120, 140, 160, 180):
        s = olc(kose(yon, kol_y))
        if s["kose_yon"] is not None and s["kose_yon"] != yon:
            yanlis.append((kol_y, s["kose_yon"]))
    kontrol(f"{yon} kose ters yon olarak okunmuyor", not yanlis, str(yanlis))

# ============================================================================
baslik("4. KOSEDE cx_yakin KAYIYOR MU  --  yanal konum bozuluyor mu")
# Kose kolu genis satirlari cx hesabindan cikarilmali; cikarilmazsa arac
# viraja girmeden kolun icine dogru savrulur.
for yon in ("SOL", "SAG"):
    for kol_y in (120, 160, 200):
        s = olc(kose(yon, kol_y))
        if not s["bulundu"]:
            continue
        sapma = s["cx_yakin"] - A.ORTA
        kontrol(f"{yon} kose kol_y={kol_y}: cx_yakin merkeze yakin",
                abs(sapma) < 12.0,
                f"sapma {sapma:+.1f} px (0 olmali, cizgi tam ortada)")

# ============================================================================
baslik("5. PID CIKISI  --  olu bant / MIN_BOOST sicramasi")
p = A.Pid()
dt = 1.0 / 30
print("  hata(px)   u (DAC)   not")
print("  " + "-" * 48)
onceki_u = None
for h in (0.0, 1.0, 1.4, 1.6, 2.0, 3.0, 5.0, 10.0, 20.0, 40.0, 80.0):
    p.sifirla()
    u = p(h, dt, A.Kp, A.Kd, A.Ki)
    not_ = ""
    if onceki_u is not None and abs(u - onceki_u) > 20:
        not_ = f"<-- SICRAMA {u - onceki_u:+.0f}"
    print(f"  {h:7.1f}   {u:7.1f}   {not_}")
    onceki_u = u

p.sifirla()
u_alt = p(A.OLU_BANT - 0.1, dt, A.Kp, A.Kd, A.Ki)
p.sifirla()
u_ust = p(A.OLU_BANT + 0.1, dt, A.Kp, A.Kd, A.Ki)
kontrol("olu bant cikisinda sicrama makul (<15 DAC)",
        abs(u_ust - u_alt) < 15.0,
        f"{A.OLU_BANT-0.1:.1f}px -> {u_alt:.0f} DAC,  "
        f"{A.OLU_BANT+0.1:.1f}px -> {u_ust:.0f} DAC  (fark {u_ust-u_alt:+.0f})")

p.sifirla()
doyum = None
for h in np.arange(1.0, 80.0, 0.5):
    p.sifirla()
    if abs(p(float(h), dt, A.Kp, A.Kd, A.Ki)) >= A.U_LIMIT - 0.5:
        doyum = float(h)
        break
kontrol("doyuma girmeden once makul bir aralik var (>25 px)",
        doyum is None or doyum > 25.0,
        f"u, {doyum} px hatada U_LIMIT={A.U_LIMIT}'e dayaniyor"
        if doyum else "doyum yok")

# ============================================================================
baslik("6. tork_dagit  --  direksiyon farki korunuyor mu")
for temel, u in [(A.SEYIR, 0), (A.SEYIR, 50), (A.SEYIR, -50),
                 (A.KOR_HIZ, 150), (A.DUZELTME_HIZ, 150)]:
    sol, sag = A.tork_dagit(temel, u)
    kontrol(f"temel={temel} u={u:+4d}: fark korundu",
            abs((sol - sag) - 2 * u) < 1e-6,
            f"sol={sol:.0f} sag={sag:.0f} fark={sol-sag:+.0f} (2u={2*u:+d})")

print(f"\n{'=' * 72}")
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print(f"{'=' * 72}")
sys.exit(1 if BASARISIZ else 0)
