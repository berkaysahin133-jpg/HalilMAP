#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Harita/ICP/SLAM dogrulamasi -- LIDAR TAKILI OLMADAN calisir.

Sentetik bir odada sensoru BILINEN bir yorunge uzerinde gezdirip, SLAM'in
tahmin ettigi yorungeyi gercekle karsilastirir. Yani "harita guzel gorunuyor"
demiyoruz, kac santim saptigini olcuyoruz.

    python3 test_harita.py
"""

import os
import sys

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import harita as H

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
#  Sentetik oda tarayici (isin-dogru parcasi kesisimi)
# ============================================================================
def dikdortgen(cx, cy, yw, yh):
    """Merkez + yari boyutlardan 4 kenar parcasi."""
    x0, x1 = cx - yw, cx + yw
    y0, y1 = cy - yh, cy + yh
    return [((x0, y0), (x1, y0)), ((x1, y0), (x1, y1)),
            ((x1, y1), (x0, y1)), ((x0, y1), (x0, y0))]


ODA = (dikdortgen(0, 0, 3.0, 2.0)          # 6 x 4 m oda
       + dikdortgen(-1.6, 1.0, 0.45, 0.35)  # kutu 1
       + dikdortgen(1.9, -0.8, 0.30, 0.60)  # kutu 2
       + dikdortgen(0.7, 1.3, 0.25, 0.25))  # kutu 3


def tara(poz, parcalar=ODA, nokta=500, gurultu_m=0.008, menzil=12.0, tohum=None):
    """poz=(x, y, teta) icin sentetik tarama uretir: [(aci, mesafe_mm, kalite)]."""
    rng = np.random.default_rng(tohum)
    sx, sy, st = poz
    tur = []
    c, sn = np.cos(st), np.sin(st)
    for i in range(nokta):
        aci = i * (360.0 / nokta)
        # Sensor cercevesindeki isin yonu (sin a, cos a), poz donme matrisi
        # R(teta) = [[c,-s],[s,c]] ile dunyaya tasinir. "yon = aci + teta"
        # yazmak TERS yonde donme demekti (harita.py'deki donusum() saat
        # yonunun tersine doner) ve aci hatasi 180 derece cikiyordu.
        sa, ca = np.sin(np.radians(aci)), np.cos(np.radians(aci))
        dx, dy = c * sa - sn * ca, sn * sa + c * ca
        en_yakin = menzil
        for (ax, ay), (bx, by) in parcalar:
            ex, ey = bx - ax, by - ay
            payda = dx * ey - dy * ex
            if abs(payda) < 1e-12:
                continue
            t = ((ax - sx) * ey - (ay - sy) * ex) / payda      # isin parametresi
            u = ((ax - sx) * dy - (ay - sy) * dx) / payda      # parca parametresi
            if t > 0.05 and 0.0 <= u <= 1.0:
                en_yakin = min(en_yakin, t)
        if en_yakin < menzil:
            m = en_yakin + rng.normal(0, gurultu_m)
            tur.append((aci, max(50.0, m * 1000.0), 47))
    return tur


# ============================================================================
baslik("1. TARAMA -> NOKTA BULUTU")
# Sensor merkezde, dogru bakan: 0 derece = +Y (ileri), 90 derece = +X (sag)
tur = [(0.0, 1000.0, 47), (90.0, 2000.0, 47), (180.0, 1500.0, 47), (270.0, 500.0, 47)]
P = H.tarama_xy(tur)
kontrol("0 derece -> ileri (+Y)", abs(P[0, 0]) < 1e-6 and abs(P[0, 1] - 1.0) < 1e-6,
        f"{P[0]}")
kontrol("90 derece -> sag (+X)", abs(P[1, 0] - 2.0) < 1e-6 and abs(P[1, 1]) < 1e-6,
        f"{P[1]}")
kontrol("180 derece -> geri (-Y)", abs(P[2, 1] + 1.5) < 1e-6, f"{P[2]}")
kontrol("270 derece -> sol (-X)", abs(P[3, 0] + 0.5) < 1e-6, f"{P[3]}")

menzil_disi = H.tarama_xy([(0.0, 50.0, 47), (10.0, 20000.0, 47)])
kontrol("menzil disi noktalar atiliyor", len(menzil_disi) == 0,
        f"{len(menzil_disi)} nokta kaldi")

# ============================================================================
baslik("2. ICP -- bilinen donusum geri bulunuyor mu")
kaynak = H.tarama_xy(tara((0.0, 0.0, 0.0), tohum=1))
esl = H.Eslestirici()
for dx, dy, derece in [(0.20, 0.00, 0.0), (0.00, 0.30, 0.0), (0.0, 0.0, 8.0),
                       (0.25, -0.15, 6.0), (-0.30, 0.20, -10.0)]:
    T_gercek = H.donusum(dx, dy, np.radians(derece))
    hedef = H.uygula(T_gercek, kaynak)
    T, hata, oran = esl.hizala(kaynak, hedef)
    bx, by = T[0, 2], T[1, 2]
    bteta = np.degrees(np.arctan2(T[1, 0], T[0, 0]))
    kon_hata = np.hypot(bx - dx, by - dy)
    aci_hata = abs(bteta - derece)
    kontrol(f"dx={dx:+.2f} dy={dy:+.2f} aci={derece:+5.1f} geri bulundu",
            kon_hata < 0.02 and aci_hata < 1.0,
            f"konum hatasi {kon_hata*1000:.1f} mm, aci hatasi {aci_hata:.2f} deg")

# ============================================================================
baslik("3. TEK TARAMA HARITASI -- oda olculeri dogru mu")
izg = H.Izgara(boyut_m=10.0, cozunurluk_m=0.03)
P = H.tarama_xy(tara((0.0, 0.0, 0.0), tohum=2))
izg.ekle(P, np.zeros(2))
dolu = izg.noktalar(esik=0.5)
en = np.ptp(dolu[:, 0])
boy = np.ptp(dolu[:, 1])
kontrol("oda genisligi ~6.0 m", abs(en - 6.0) < 0.12, f"olculen {en:.3f} m")
kontrol("oda derinligi ~4.0 m", abs(boy - 4.0) < 0.12, f"olculen {boy:.3f} m")
bos_oran = float((izg.izgara < -0.05).mean())
kontrol("bos alan isaretlendi", 0.05 < bos_oran < 0.60, f"%{bos_oran*100:.1f}")

# ============================================================================
baslik("4. SLAM -- bilinen yorunge geri bulunuyor mu")


def yorunge_kos(yorunge, gurultu=0.008, tohum=10):
    slam = H.Slam(H.Izgara(boyut_m=14.0, cozunurluk_m=0.03))
    onceki = np.eye(3)
    tahmin, gercek = [], []
    for k, poz in enumerate(yorunge):
        tur = tara(poz, gurultu_m=gurultu, tohum=tohum + k)
        hiz = slam.poz @ np.linalg.inv(onceki)
        onceki = slam.poz.copy()
        ok, x, y, t = slam.adim(tur, hiz_tahmini=hiz)
        tahmin.append((x, y, t))
        gercek.append(poz)
    return np.array(tahmin), np.array(gercek), slam


# --- 4a: duz cizgi boyunca ilerle ---
yol = [(0.0, -1.2 + 0.06 * i, 0.0) for i in range(40)]     # 2.34 m ileri
tahmin, gercek = yorunge_kos(yol)[:2]
# SLAM ilk pozu orijin kabul eder -> gercegi de ilk poza gore kaydir
gercek_bagil = gercek - gercek[0]
sapma = np.hypot(tahmin[:, 0] - gercek_bagil[:, 0], tahmin[:, 1] - gercek_bagil[:, 1])
kontrol("duz cizgi: son konum hatasi < 5 cm", sapma[-1] < 0.05,
        f"{sapma[-1]*100:.1f} cm ({gercek_bagil[-1,1]:.2f} m yol sonunda)")
kontrol("duz cizgi: ortalama sapma < 3 cm", sapma.mean() < 0.03,
        f"{sapma.mean()*100:.1f} cm")

# --- 4b: donerek gez (kare guzergah) ---
yol = []
for i in range(25):
    yol.append((-1.0 + i * 0.06, -1.0, 0.0))
for i in range(20):
    yol.append((0.5, -1.0, np.radians(i * 4.5)))
for i in range(25):
    yol.append((0.5, -1.0 + i * 0.06, np.radians(90)))
tahmin, gercek = yorunge_kos(yol, tohum=50)[:2]
gercek_bagil = gercek - gercek[0]
sapma = np.hypot(tahmin[:, 0] - gercek_bagil[:, 0], tahmin[:, 1] - gercek_bagil[:, 1])
d_aci = (tahmin[:, 2] - gercek_bagil[:, 2] + np.pi) % (2*np.pi) - np.pi
aci_sapma = np.degrees(np.abs(d_aci))
kontrol("donusla: son konum hatasi < 10 cm", sapma[-1] < 0.10,
        f"{sapma[-1]*100:.1f} cm")
kontrol("donusla: son aci hatasi < 5 derece", aci_sapma[-1] < 5.0,
        f"{aci_sapma[-1]:.2f} deg")

# --- 4c: gurultu artinca da dagilmasin ---
tahmin, gercek = yorunge_kos([(0.0, -1.2 + 0.06 * i, 0.0) for i in range(40)],
                             gurultu=0.03, tohum=99)[:2]
gercek_bagil = gercek - gercek[0]
sapma = np.hypot(tahmin[:, 0] - gercek_bagil[:, 0], tahmin[:, 1] - gercek_bagil[:, 1])
kontrol("3 cm olcum gurultusunde bile < 10 cm", sapma[-1] < 0.10,
        f"{sapma[-1]*100:.1f} cm")

# ============================================================================
baslik("5. SLAM SONRASI HARITA -- oda olculeri hala dogru mu")
tahmin, gercek, slam = yorunge_kos(
    [(-0.8 + 0.05 * i, -0.8 + 0.03 * i, np.radians(i * 1.5)) for i in range(45)],
    tohum=200)
dolu = slam.izgara.noktalar(esik=0.5)
en, boy = np.ptp(dolu[:, 0]), np.ptp(dolu[:, 1])
kontrol("gezdikten sonra oda genisligi ~6.0 m", abs(en - 6.0) < 0.30,
        f"olculen {en:.3f} m")
kontrol("gezdikten sonra oda derinligi ~4.0 m", abs(boy - 4.0) < 0.30,
        f"olculen {boy:.3f} m")

# ============================================================================
print(f"\n{'=' * 66}")
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print(f"{'=' * 66}")
sys.exit(1 if BASARISIZ else 0)
