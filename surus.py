#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RoboVizyon ana surus programi.

    python3 surus.py                    # normal surus (pencereli)
    python3 surus.py --headless         # SSH / servis
    python3 surus.py --kuru             # motor komutu GITMEZ, sadece algilama
    python3 surus.py --kayit kosu1      # ham video + telemetri kaydet
    python3 surus.py --video kosu1.avi  # kayitli videodan calistir (offline)

Cikis: 'q' veya Ctrl+C. Her kosulda motorlar notre iner.
"""

import argparse
import atexit
import csv
import os
import sys
import time

import cv2

from robovizyon import (Konfig, Perspektif, SeritDedektoru, PurePursuit,
                        MotorLink, QROkuyucu, Gorev, Kamera)
from robovizyon import gorsel


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--konfig", default="konfig.json")
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--kuru", action="store_true",
                    help="motorlara komut gonderme (algilama testi)")
    ap.add_argument("--kayit", default=None, metavar="AD",
                    help="ham video + telemetri kaydet")
    ap.add_argument("--video", default=None, help="kayitli videodan besle")
    args = ap.parse_args()

    k = Konfig.yukle(args.konfig)
    goster = not args.headless
    kuru = args.kuru or args.video is not None

    per = Perspektif(k.kamera, k.perspektif)
    print(per.gorus_alani_bilgisi())

    kam = Kamera(k.kamera, kaynak=args.video)
    dedektor = SeritDedektoru(k, per)
    kontrolcu = PurePursuit(k)
    motor = MotorLink(k.motor, k.kontrol, kuru=kuru)
    atexit.register(motor.kapat)
    qr = QROkuyucu(k.qr)
    gorev = Gorev(k, dedektor, kontrolcu, motor, qr)

    if kuru:
        print("[SISTEM] KURU MOD: motorlara komut gonderilmiyor.")
    else:
        print(f"[SISTEM] Arduino: {getattr(motor, 'port', '?')}  YON={k.motor.yon:+d}")

    # --- Kayit ---
    yazici = telemetri_dosya = telemetri_csv = None
    if args.kayit:
        os.makedirs("kayitlar", exist_ok=True)
        vid_yol = f"kayitlar/{args.kayit}.avi"
        yazici = cv2.VideoWriter(vid_yol, cv2.VideoWriter_fourcc(*"MJPG"),
                                 20.0, (k.kamera.genislik, k.kamera.yukseklik))
        telemetri_dosya = open(f"kayitlar/{args.kayit}.csv", "w", newline="", encoding="utf-8")
        telemetri_csv = csv.writer(telemetri_dosya)
        telemetri_csv.writerow(["t", "durum", "gecerli", "guven", "yanal_cm",
                                "yon_derece", "egrilik", "bitis_cm", "kose",
                                "kose_cm", "hiz_cm_s", "sol_cm_s", "sag_cm_s"])
        print(f"[SISTEM] Kayit: {vid_yol}")

    son_t = time.monotonic()
    fps = 0.0
    print("[SISTEM] Basladi. Cikis: 'q'")

    try:
        while True:
            ok, ham, islem = kam.oku()
            if not ok:
                print("[SISTEM] Goruntu akisi bitti.")
                motor.dur()
                break

            if goster and (cv2.waitKey(1) & 0xFF) == ord("q"):
                print("[SISTEM] Kullanici durdurdu.")
                break

            simdi = time.monotonic()
            dt = min(max(simdi - son_t, 1e-3), 0.2)
            son_t = simdi
            fps += 0.1 * (1.0 / dt - fps)

            motor.dinle()

            kus = per.warp(islem)
            olcum = dedektor.isle(kus)
            tele = gorev.adim(olcum, islem, dt, simdi)
            komut = gorev.telemetri.get("komut")

            if yazici is not None:
                yazici.write(ham)
                telemetri_csv.writerow([
                    f"{simdi:.3f}", tele["durum"], int(tele["gecerli"]), tele["guven"],
                    tele["yanal_cm"], tele["yon_derece"], tele["egrilik"],
                    tele["bitis_cm"], tele["kose"], tele["kose_cm"],
                    f"{komut.hiz_cm_s:.1f}" if komut else "",
                    f"{komut.sol_cm_s:.1f}" if komut else "",
                    f"{komut.sag_cm_s:.1f}" if komut else "",
                ])

            if goster:
                ana = gorsel.ana_panel(islem, olcum, per, tele, komut, fps)
                kus_p = gorsel.kus_panel(kus, olcum, per, komut)
                cv2.imshow("RoboVizyon  |  kamera + kusbakisi", gorsel.yan_yana(ana, kus_p))

    except KeyboardInterrupt:
        print("\n[SISTEM] Ctrl+C")
    finally:
        motor.kapat()
        kam.kapat()
        if yazici is not None:
            yazici.release()
        if telemetri_dosya is not None:
            telemetri_dosya.close()
        if goster:
            cv2.destroyAllWindows()
        print("[SISTEM] Motorlar notrde, cikildi.")


if __name__ == "__main__":
    sys.exit(main())
