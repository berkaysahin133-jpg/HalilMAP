#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kusbakisi kalibrasyonu ve canli esik ayari.

IKI MOD:

1) GEOMETRIK (hizli, mezura yeter) -- onerilen baslangic
       python3 kalibre.py --geometrik
   Kamera yuksekligi / egim acisi / FOV degerlerini trackbar'dan kaydir,
   yerdeki cizgi kusbakisinda DUZ ve GERCEK GENISLIGINDE gorunene kadar ayarla.

2) 4 NOKTA (en hassas)
       python3 kalibre.py --dortnokta
   Yere, aracin onune bilinen olculerde bir DIKDORTGEN yapistir (orn. 40x60 cm),
   sonra goruntude koselerine sirayla tikla:
       1. sol-yakin   2. sag-yakin   3. sag-uzak   4. sol-uzak
   Olculeri --en / --boy / --uzaklik ile ver.

Her iki modda da 's' tusu ayarlari konfig.json'a kaydeder.
"""

import argparse
import sys

import cv2
import numpy as np

from robovizyon import Konfig, Perspektif, SeritDedektoru, Kamera


TIKLAMALAR = []


def _fare(olay, x, y, bayrak, veri):
    if olay == cv2.EVENT_LBUTTONDOWN and len(TIKLAMALAR) < 4:
        TIKLAMALAR.append([float(x), float(y)])
        print(f"  nokta {len(TIKLAMALAR)}: ({x}, {y})")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--konfig", default="konfig.json")
    ap.add_argument("--video", default=None, help="kamera yerine video dosyasi")
    ap.add_argument("--geometrik", action="store_true")
    ap.add_argument("--dortnokta", action="store_true")
    ap.add_argument("--en", type=float, default=40.0, help="dikdortgen eni (cm)")
    ap.add_argument("--boy", type=float, default=60.0, help="dikdortgen boyu (cm)")
    ap.add_argument("--uzaklik", type=float, default=15.0,
                    help="dikdortgenin yakin kenarinin araca uzakligi (cm)")
    args = ap.parse_args()

    if not (args.geometrik or args.dortnokta):
        args.geometrik = True

    k = Konfig.yukle(args.konfig)
    kam = Kamera(k.kamera, kaynak=args.video)

    # ------------------------------------------------------------ 4 NOKTA
    if args.dortnokta:
        print("\n4 NOKTA MODU")
        print(f"  Yere {args.en}x{args.boy} cm dikdortgen yapistir, yakin kenari "
              f"aractan {args.uzaklik} cm uzakta olsun.")
        print("  Sirayla tikla: 1) sol-yakin  2) sag-yakin  3) sag-uzak  4) sol-uzak")
        print("  'r' sifirla, 'ENTER' onayla, 'q' cik\n")

        cv2.namedWindow("Kalibrasyon")
        cv2.setMouseCallback("Kalibrasyon", _fare)

        while True:
            ok, _, islem = kam.oku()
            if not ok:
                break
            g = islem.copy()
            for i, (x, y) in enumerate(TIKLAMALAR):
                cv2.circle(g, (int(x), int(y)), 5, (60, 60, 235), -1)
                cv2.putText(g, str(i + 1), (int(x) + 8, int(y)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (60, 220, 60), 2)
            if len(TIKLAMALAR) == 4:
                cv2.polylines(g, [np.array(TIKLAMALAR, np.int32)], True, (60, 220, 60), 2)
            cv2.putText(g, f"{len(TIKLAMALAR)}/4 nokta", (6, 18),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (245, 245, 245), 1)
            cv2.imshow("Kalibrasyon", g)

            t = cv2.waitKey(30) & 0xFF
            if t == ord("q"):
                kam.kapat(); cv2.destroyAllWindows(); return 0
            if t == ord("r"):
                TIKLAMALAR.clear()
            if t in (13, 10) and len(TIKLAMALAR) == 4:
                break

        yari = args.en / 2.0
        yakin, uzak = args.uzaklik, args.uzaklik + args.boy
        k.perspektif.kaynak_noktalar = TIKLAMALAR
        k.perspektif.hedef_noktalar_cm = [[-yari, yakin], [yari, yakin],
                                          [yari, uzak], [-yari, uzak]]
        k.perspektif.y_min_cm = min(k.perspektif.y_min_cm, yakin)
        k.perspektif.y_max_cm = max(k.perspektif.y_max_cm, uzak)
        print("[OK] 4 nokta kaydedildi. Simdi canli onizleme...")

    # ------------------------------------------------------ CANLI ONIZLEME
    pencere = "Kalibrasyon  |  sol: kamera   sag: kusbakisi"
    cv2.namedWindow(pencere)

    if args.geometrik:
        cv2.createTrackbar("yukseklik cm", pencere,
                           int(k.perspektif.kamera_yuksekligi_cm), 80, lambda v: None)
        cv2.createTrackbar("egim derece", pencere,
                           int(k.perspektif.egim_derece), 85, lambda v: None)
        cv2.createTrackbar("FOV derece", pencere,
                           int(k.perspektif.yatay_fov_derece), 120, lambda v: None)
    cv2.createTrackbar("kontrast esigi", pencere, k.serit.kontrast_esigi, 80, lambda v: None)
    cv2.createTrackbar("yerel pencere cm", pencere,
                       int(k.serit.yerel_pencere_cm), 40, lambda v: None)

    print("\nCANLI ONIZLEME")
    print("  Hedef: yerdeki DUZ cizgi, sagdaki kusbakisi panelinde de DUZ ve")
    print("         dikey gorunmeli; genisligi her mesafede AYNI kalmali.")
    print("  Kirmizi maske sadece cizgiyi kaplamali (zemin/golge kaplamamali).")
    print("  's' kaydet, 'q' cik\n")

    per = Perspektif(k.kamera, k.perspektif)
    dedektor = SeritDedektoru(k, per)
    onceki = None

    while True:
        ok, _, islem = kam.oku()
        if not ok:
            if args.video:
                kam = Kamera(k.kamera, kaynak=args.video)   # videoyu dondur
                continue
            break

        if args.geometrik:
            yeni = (cv2.getTrackbarPos("yukseklik cm", pencere),
                    cv2.getTrackbarPos("egim derece", pencere),
                    cv2.getTrackbarPos("FOV derece", pencere))
            if yeni != onceki and all(v > 0 for v in yeni):
                k.perspektif.kamera_yuksekligi_cm = float(yeni[0])
                k.perspektif.egim_derece = float(yeni[1])
                k.perspektif.yatay_fov_derece = float(yeni[2])
                try:
                    per = Perspektif(k.kamera, k.perspektif)
                    dedektor = SeritDedektoru(k, per)
                except ValueError as e:
                    print(f"  [gecersiz geometri] {e}")
                onceki = yeni

        k.serit.kontrast_esigi = max(3, cv2.getTrackbarPos("kontrast esigi", pencere))
        yp = max(3, cv2.getTrackbarPos("yerel pencere cm", pencere))
        if yp != int(k.serit.yerel_pencere_cm):
            k.serit.yerel_pencere_cm = float(yp)
            dedektor = SeritDedektoru(k, per)

        kus = per.warp(islem)
        olcum = dedektor.isle(kus)

        panel = kus.copy()
        if olcum.maske is not None:
            renkli = cv2.cvtColor(olcum.maske, cv2.COLOR_GRAY2BGR)
            renkli[:, :, 0] = 0; renkli[:, :, 1] = 0
            panel = cv2.addWeighted(panel, 0.6, renkli, 0.4, 0)

        # Her 10 cm'de bir mesafe cizgisi -- kusbakisinin dogrulugunu gozle dogrula
        for Y in range(int(k.perspektif.y_min_cm), int(k.perspektif.y_max_cm) + 1, 10):
            _, v = per.dunya_to_kus(0, Y)
            cv2.line(panel, (0, int(v)), (panel.shape[1], int(v)), (110, 110, 110), 1)
            cv2.putText(panel, f"{Y}", (3, int(v) - 3), cv2.FONT_HERSHEY_SIMPLEX,
                        0.35, (200, 200, 200), 1)
        for X in range(int(k.perspektif.x_min_cm), int(k.perspektif.x_max_cm) + 1, 10):
            u, _ = per.dunya_to_kus(X, 0)
            cv2.line(panel, (int(u), 0), (int(u), panel.shape[0]), (70, 70, 70), 1)

        if olcum.gecerli:
            for X, Y in olcum.noktalar_cm:
                u, v = per.dunya_to_kus(X, Y)
                cv2.circle(panel, (int(u), int(v)), 3, (60, 220, 235), -1)
            cv2.putText(panel, f"yanal {olcum.yanal_hata_cm:+.1f}cm  "
                               f"yon {np.degrees(olcum.yon_hatasi_rad):+.1f}d  "
                               f"guven {olcum.guven:.2f}",
                        (4, panel.shape[0] - 8), cv2.FONT_HERSHEY_SIMPLEX,
                        0.4, (60, 220, 60), 1)

        h = max(islem.shape[0], panel.shape[0])
        sol = cv2.resize(islem, (int(islem.shape[1] * h / islem.shape[0]), h))
        sag = cv2.resize(panel, (int(panel.shape[1] * h / panel.shape[0]), h))
        cv2.imshow(pencere, np.hstack([sol, sag]))

        t = cv2.waitKey(1) & 0xFF
        if t == ord("q"):
            break
        if t == ord("s"):
            yol = k.kaydet(args.konfig)
            print(f"[KAYDEDILDI] {yol}")
            print(f"  yukseklik={k.perspektif.kamera_yuksekligi_cm:.0f}cm  "
                  f"egim={k.perspektif.egim_derece:.0f}d  "
                  f"FOV={k.perspektif.yatay_fov_derece:.0f}d  "
                  f"kontrast={k.serit.kontrast_esigi}  "
                  f"yerel={k.serit.yerel_pencere_cm:.0f}cm")

    kam.kapat()
    cv2.destroyAllWindows()
    return 0


if __name__ == "__main__":
    sys.exit(main())
