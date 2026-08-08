#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RPLIDAR C1 canli gorunum / kayit / oynatma.

    python3 goster.py --sahte              # LIDAR YOKKEN sentetik oda (deneme)
    python3 goster.py                      # canli (portu otomatik bulur)
    python3 goster.py --port /dev/ttyUSB0
    python3 goster.py --kayit oda1         # canli + kayit (oda1.npz)
    python3 goster.py --oynat oda1.npz     # kayittan oynat

Tuslar:  q cikis   +/- yakinlastir   k kayit ac/kapa   BOSLUK duraklat
"""

import argparse
import os
import sys
import time

import numpy as np

try:
    import cv2
except ImportError:
    cv2 = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c1

TUVAL = 760                      # pencere kenari (px)
RENK_ZEMIN = (18, 18, 20)
RENK_IZGARA = (55, 58, 62)
RENK_NOKTA = (90, 230, 120)
RENK_YAKIN = (80, 120, 250)      # 50 cm'den yakin -> uyari rengi
RENK_ARAC = (240, 200, 80)
RENK_YAZI = (235, 235, 235)


def cizim(tur, olcek_m, fps=0.0, kayit=False, ek=""):
    """Bir turu kus bakisi cizer. tur = [(aci_derece, mesafe_mm, kalite), ...]"""
    img = np.full((TUVAL, TUVAL, 3), RENK_ZEMIN, np.uint8)
    mer = TUVAL // 2
    px_m = (TUVAL / 2.0) / olcek_m          # piksel / metre

    # Menzil halkalari (her 1 m)
    for r in range(1, int(olcek_m) + 1):
        cv2.circle(img, (mer, mer), int(r * px_m), RENK_IZGARA, 1, cv2.LINE_AA)
        cv2.putText(img, f"{r}m", (mer + int(r * px_m) - 22, mer - 5),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.35, RENK_IZGARA, 1, cv2.LINE_AA)
    cv2.line(img, (mer, 0), (mer, TUVAL), RENK_IZGARA, 1)
    cv2.line(img, (0, mer), (TUVAL, mer), RENK_IZGARA, 1)

    yakin_sayi = 0
    for aci, mesafe, kalite in tur:
        m = mesafe / 1000.0
        if m <= 0 or m > olcek_m:
            continue
        # LiDAR 0 derece = ileri (+Y). Ekranda yukari = ileri.
        rad = np.radians(aci)
        x = mer + int(m * px_m * np.sin(rad))
        y = mer - int(m * px_m * np.cos(rad))
        if 0 <= x < TUVAL and 0 <= y < TUVAL:
            if m < 0.5:
                cv2.circle(img, (x, y), 2, RENK_YAKIN, -1)
                yakin_sayi += 1
            else:
                img[y, x] = RENK_NOKTA
                cv2.circle(img, (x, y), 1, RENK_NOKTA, -1)

    # Arac (merkez) ve ileri yonu
    cv2.circle(img, (mer, mer), 6, RENK_ARAC, -1, cv2.LINE_AA)
    cv2.arrowedLine(img, (mer, mer), (mer, mer - 26), RENK_ARAC, 2,
                    tipLength=0.35, line_type=cv2.LINE_AA)

    bilgi = f"{len(tur):4d} nokta   olcek {olcek_m:.0f} m   {fps:4.1f} tur/s"
    if yakin_sayi:
        bilgi += f"   YAKIN:{yakin_sayi}"
    cv2.putText(img, bilgi, (10, 24), cv2.FONT_HERSHEY_SIMPLEX, 0.5,
                RENK_YAZI, 1, cv2.LINE_AA)
    if ek:
        cv2.putText(img, ek, (10, 46), cv2.FONT_HERSHEY_SIMPLEX, 0.45,
                    RENK_YAZI, 1, cv2.LINE_AA)
    if kayit:
        cv2.circle(img, (TUVAL - 26, 24), 7, (60, 60, 235), -1)
        cv2.putText(img, "REC", (TUVAL - 78, 30), cv2.FONT_HERSHEY_SIMPLEX,
                    0.5, (60, 60, 235), 2)
    cv2.putText(img, "q cikis   +/- olcek   k kayit   BOSLUK duraklat",
                (10, TUVAL - 14), cv2.FONT_HERSHEY_SIMPLEX, 0.4,
                (140, 140, 145), 1, cv2.LINE_AA)
    return img


# ---------------------------------------------------------------- sentetik oda
def sahte_oda(kare):
    """LIDAR YOKKEN deneme icin: 6x4 m oda + iki kutu + donen bir engel."""
    tur = []
    t = kare * 0.03
    oda_x, oda_y = 3.0, 2.0            # yari boyutlar (m)
    rx, ry = 0.6 * np.sin(t * 0.4), 0.4 * np.cos(t * 0.3)   # sensor gezinir
    kutular = [(-1.6, 1.0, 0.45, 0.35), (1.9, -0.8, 0.3, 0.6),
               (0.9 + 0.5 * np.sin(t), 1.2 + 0.3 * np.cos(t), 0.22, 0.22)]

    for i in range(500):                # C1 ~500 nokta/tur (5kHz / 10Hz)
        aci = i * 0.72
        rad = np.radians(aci)
        dx, dy = np.sin(rad), np.cos(rad)
        en_yakin = 1e9
        # Oda duvarlari (dikdortgen ile isin kesisimi)
        for sinir, bilesen, yon in ((oda_x, dx, rx), (-oda_x, dx, rx),
                                    (oda_y, dy, ry), (-oda_y, dy, ry)):
            if abs(bilesen) > 1e-6:
                mesafe = (sinir - yon) / bilesen
                if mesafe > 0.05:
                    px, py = rx + dx * mesafe, ry + dy * mesafe
                    if -oda_x - 0.01 <= px <= oda_x + 0.01 and \
                       -oda_y - 0.01 <= py <= oda_y + 0.01:
                        en_yakin = min(en_yakin, mesafe)
        # Kutular
        for kx, ky, kw, kh in kutular:
            t_gir, t_cik = 0.05, en_yakin
            gecerli = True
            for sinir_dus, sinir_ust, b, o in ((kx - kw, kx + kw, dx, rx),
                                               (ky - kh, ky + kh, dy, ry)):
                if abs(b) < 1e-6:
                    if not (sinir_dus <= o <= sinir_ust):
                        gecerli = False; break
                else:
                    t1, t2 = (sinir_dus - o) / b, (sinir_ust - o) / b
                    t_gir, t_cik = max(t_gir, min(t1, t2)), min(t_cik, max(t1, t2))
            if gecerli and t_gir <= t_cik:
                en_yakin = min(en_yakin, t_gir)
        if en_yakin < 12.0:
            gurultu = np.random.randn() * 0.008
            tur.append((aci, max(50.0, (en_yakin + gurultu) * 1000.0), 47))
    return tur


# ------------------------------------------------------------------------ ana
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=460800)
    ap.add_argument("--sahte", action="store_true", help="LIDAR olmadan sentetik oda")
    ap.add_argument("--kayit", default=None, metavar="AD")
    ap.add_argument("--oynat", default=None, metavar="DOSYA")
    ap.add_argument("--olcek", type=float, default=6.0, help="yariçap (m)")
    ap.add_argument("--kare-yaz", default=None, help="tek kare PNG yazip cik (test)")
    args = ap.parse_args()

    if cv2 is None:
        print("opencv gerekli:  pip install opencv-python")
        return 1

    olcek = args.olcek
    kayit_acik = args.kayit is not None
    kayitlar = []
    duraklat = False
    fps = 0.0
    son = time.monotonic()

    # ---- kaynak secimi ----
    lid = None
    if args.oynat:
        veri = np.load(args.oynat, allow_pickle=True)
        turlar = list(veri["turlar"])
        print(f"[OYNAT] {args.oynat}: {len(turlar)} tur")
        kaynak = ("oynat", turlar)
    elif args.sahte:
        print("[SAHTE] Sentetik oda. Gercek LiDAR icin --sahte'yi kaldir.")
        kaynak = ("sahte", None)
    else:
        port = args.port or c1.port_bul()
        if port is None:
            print("[HATA] Seri port bulunamadi. LiDAR takili mi?")
            print("       Denemek icin:  python3 goster.py --sahte")
            return 1
        print(f"[BAGLAN] {port} @ {args.baud}")
        lid = c1.RPLidarC1(port, args.baud)
        try:
            print(f"[BILGI]  {lid.bilgi()}")
            s = lid.saglik()
            print(f"[SAGLIK] {s['metin']} (kod {s['hata_kodu']})")
            if s["durum"] == 2:
                print("[UYARI] Cihaz hata durumunda. lid.sifirla() denenebilir.")
        except c1.LidarHatasi as e:
            print(f"[UYARI] Bilgi okunamadi: {e}")
        kaynak = ("canli", lid.taramalar())

    # ---- tek kare yazip cik (donanimsiz test) ----
    if args.kare_yaz:
        tur = sahte_oda(40) if kaynak[0] == "sahte" else (
            kaynak[1][0] if kaynak[0] == "oynat" else next(kaynak[1]))
        cv2.imwrite(args.kare_yaz, cizim(tur, olcek, 10.0, ek="sentetik oda"))
        print(f"[YAZILDI] {args.kare_yaz}  ({len(tur)} nokta)")
        if lid:
            lid.kapat()
        return 0

    pencere = "RPLIDAR C1"
    cv2.namedWindow(pencere)
    kare = 0
    try:
        while True:
            if not duraklat:
                if kaynak[0] == "sahte":
                    tur = sahte_oda(kare)
                    time.sleep(0.1)
                elif kaynak[0] == "oynat":
                    tur = kaynak[1][kare % len(kaynak[1])]
                    time.sleep(0.1)
                else:
                    tur = next(kaynak[1])
                kare += 1
                simdi = time.monotonic()
                dt = simdi - son
                son = simdi
                if dt > 0:
                    fps += 0.2 * (1.0 / dt - fps)
                if kayit_acik:
                    kayitlar.append(tur)

            ek = f"kare {kare}" + ("  [DURAKLADI]" if duraklat else "")
            cv2.imshow(pencere, cizim(tur, olcek, fps, kayit_acik, ek))

            t = cv2.waitKey(1) & 0xFF
            if t == ord("q"):
                break
            elif t in (ord("+"), ord("=")):
                olcek = max(1.0, olcek - 1.0)
            elif t == ord("-"):
                olcek = min(12.0, olcek + 1.0)
            elif t == ord(" "):
                duraklat = not duraklat
            elif t == ord("k"):
                kayit_acik = not kayit_acik
                print(f"[KAYIT] {'ACIK' if kayit_acik else 'kapali'}")

    except (KeyboardInterrupt, StopIteration):
        pass
    except c1.LidarHatasi as e:
        print(f"[HATA] {e}")
    finally:
        if lid:
            lid.kapat()
        cv2.destroyAllWindows()
        if kayitlar:
            ad = (args.kayit or "kayit") + ".npz"
            np.savez_compressed(ad, turlar=np.array(kayitlar, dtype=object))
            print(f"[KAYDEDILDI] {ad}  ({len(kayitlar)} tur)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
