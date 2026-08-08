#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RoboVizyon TEŞHİS -- "düz giderken kayıp çizgiyi kaybediyor" sorunu için.

Bu belirti POZİTİF GERİ BESLEME demek: araç çizgiden UZAĞA direksiyon kırıyor.
Kontrol matematiği doğruysa (simülasyonda 1.5 mm sapma ile doğrulandı) geriye
üç fiziksel olasılık kalır:

  A) SOL/SAĞ motorlar takas  -> 0x60 fiziksel sağa, 0x61 sola bağlı olabilir.
     "İki teker de ileri" testi bunu GÖSTERMEZ; ayrı ayrı test şart.
  B) KAMERA AYNA görüntü verir -> çizgi sağdayken kod "solda" görür.
  C) Kamera ters monte (180 dönük) -> hem sağ/sol hem ileri/geri ters.

Bu betik üçünü de ayırt eder. Motorlara komut GÖNDERMEZ (Adım 2'de sen izin
vermeden). Tekerlekleri havada tut.

    python3 teshis.py
"""

import sys
import time

import cv2
import numpy as np

try:
    import serial
except ImportError:
    serial = None

PORT = '/dev/ttyUSB0'
NOTR = 2048
YON = -1              # cizgi_takip.py ile AYNI olmalı
ISL_W, ISL_H = 160, 120


def ileri(ofset):
    return int(np.clip(NOTR + YON * ofset, 0, 4095))


def geri(ofset):
    return int(np.clip(NOTR - YON * ofset, 0, 4095))


def baslik(s):
    print(f"\n{'=' * 68}\n {s}\n{'=' * 68}")


def sor(soru, secenekler):
    while True:
        c = input(f"{soru} [{'/'.join(secenekler)}]: ").strip().lower()
        if c in secenekler:
            return c


# ============================================================================
baslik("ADIM 1 -- MOTOR KİMLİĞİ  (tekerlekler HAVADA olsun!)")

if serial is None:
    print("pyserial yok, motor testi atlanıyor.")
    ard = None
else:
    try:
        ard = serial.Serial(PORT, 115200, timeout=0.1)
        time.sleep(2)
        print(f"Arduino bağlandı: {PORT}")
    except Exception as e:
        print(f"[HATA] Seri port: {e}")
        ard = None

motor_takas = False
kamera_ayna = False

if ard is not None:
    input("\nTekerlekler havada mı? Emin ol, sonra ENTER'a bas...")

    def gonder(sol, sag, saniye):
        t = time.time()
        while time.time() - t < saniye:
            ard.write(f"<{sol},{sag}>\n".encode())
            time.sleep(0.03)
        ard.write(f"<{NOTR},{NOTR}>\n".encode())

    print(f"\n>>> SADECE 'sol' kanala ileri komutu ({ileri(450)}), diğeri nötr ({NOTR})")
    print("    3 saniye dönecek, hangi tekerin döndüğüne bak.")
    input("    ENTER...")
    gonder(ileri(450), NOTR, 3.0)

    c = sor("\n    Hangi teker döndü?", ["sol", "sag", "hicbiri"])
    if c == "hicbiri":
        print("\n    ⚠  Hiçbiri dönmediyse: DAC adresleri (0x60/0x61), sürücü")
        print("       enable hattı veya acil stop kontrol edilmeli.")
        sys.exit(1)
    motor_takas = (c == "sag")

    print(f"\n>>> Şimdi ileri/geri: iki kanal da ileri ({ileri(450)})")
    input("    ENTER...")
    gonder(ileri(450), ileri(450), 2.5)
    c = sor("\n    Tekerler hangi yöne döndü?", ["ileri", "geri"])
    yon_dogru = (c == "ileri")

    print("\n  --- ADIM 1 SONUCU ---")
    print(f"    MOTOR_TAKAS = {motor_takas}"
          f"   {'<<< SOL/SAĞ TAKAS! Bu senin sorunun olabilir.' if motor_takas else '(sol/sağ doğru)'}")
    print(f"    YON = {YON if yon_dogru else -YON}"
          f"   {'(doğru)' if yon_dogru else '<<< YON DEĞİŞTİRİLMELİ'}")

# ============================================================================
baslik("ADIM 2 -- KAMERA YÖNÜ ve ALGILAMA İŞARETİ  (motor komutu GİTMEZ)")

cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
if not cap.isOpened():
    cap = cv2.VideoCapture(0)
if not cap.isOpened():
    print("[HATA] Kamera açılamadı")
    sys.exit(1)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)
cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

print("""
  Şimdi çizgiyi (veya siyah bir bandı) kameranın önünde tut.

  Ekranda:
    - Sarı noktalar = algılanan çizgi
    - Büyük ok      = kodun kırmak İSTEDİĞİ yön
    - Alt satır     = motorlara gidecek DAC değerleri

  YAPACAĞIN TEST:
    Çizgiyi kameranın SAĞ tarafına götür.
      -> Ok SAĞA bakmalı
      -> "SOL" DAC değeri, "SAG"dan daha İLERİ olmalı
         (YON=-1 olduğu için İLERİ = küçük sayı)

    Ok TERS tarafa bakıyorsa: kamera AYNA görüntü veriyor.
    'a' tuşuna basıp aynayı aç, tekrar dene.

  Tuşlar:  a = ayna aç/kapa    q = çık
""")

_k3 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
_k5 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))

while True:
    cap.grab()
    ok, frame = cap.retrieve()
    if not ok:
        break
    if kamera_ayna:
        frame = cv2.flip(frame, 1)

    kucuk = cv2.resize(frame, (ISL_W, ISL_H), interpolation=cv2.INTER_AREA)
    gri = cv2.cvtColor(kucuk, cv2.COLOR_BGR2GRAY)
    yum = cv2.GaussianBlur(gri, (5, 5), 0)
    yerel = cv2.blur(yum, (25, 25))
    _, maske = cv2.threshold(cv2.subtract(yerel, yum), 16, 255, cv2.THRESH_BINARY)
    maske = cv2.morphologyEx(maske, cv2.MORPH_CLOSE, _k5)
    maske = cv2.morphologyEx(maske, cv2.MORPH_OPEN, _k3)

    alt = maske[int(ISL_H * 0.78):, :]
    hist = alt.sum(axis=0).astype(np.float32)
    g = frame.copy()
    hata = None

    if hist.max() > 255 * 2:
        cx = int(np.argmax(hist))
        # basit kayan pencere (teşhis için 4 pencere yeter)
        pts, x = [], cx
        for i in range(4):
            y1 = ISL_H - i * (ISL_H // 4)
            y0 = max(0, y1 - ISL_H // 4)
            xs, xe = max(0, x - 26), min(ISL_W, x + 26)
            pen = maske[y0:y1, xs:xe]
            nz = cv2.findNonZero(pen)
            if nz is not None and len(nz) >= 18:
                x = int(np.asarray(nz).reshape(-1, 2)[:, 0].mean()) + xs
                pts.append((x, (y0 + y1) * 0.5))
        if pts:
            hata = (pts[0][0] - ISL_W / 2.0) / (ISL_W / 2.0)
            for (px, py) in pts:
                cv2.circle(g, (int(px * 2), int(py * 2)), 5, (0, 220, 235), -1)

    cv2.line(g, (160, 0), (160, 240), (255, 0, 0), 1)

    if hata is not None:
        d = float(np.clip(0.95 * hata, -1, 1))
        sol_dac = ileri(np.clip(500 + d * 900, -320, 900))
        sag_dac = ileri(np.clip(500 - d * 900, -320, 900))
        if motor_takas:
            sol_dac, sag_dac = sag_dac, sol_dac

        uc = int(160 + d * 110)
        cv2.arrowedLine(g, (160, 210), (uc, 210), (60, 220, 60), 5, tipLength=0.4)
        yon_yazi = "SAGA KIR" if d > 0.03 else ("SOLA KIR" if d < -0.03 else "DUZ")
        cv2.putText(g, yon_yazi, (110, 200), cv2.FONT_HERSHEY_SIMPLEX,
                    0.6, (60, 220, 60), 2)
        cv2.putText(g, f"hata {hata:+.2f}   cizgi {'SAGDA' if hata > 0 else 'SOLDA'}",
                    (5, 18), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1)
        cv2.putText(g, f"SOL {sol_dac}   SAG {sag_dac}   (ileri = kucuk)",
                    (5, 236), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1)
    else:
        cv2.putText(g, "CIZGI YOK", (5, 18), cv2.FONT_HERSHEY_SIMPLEX,
                    0.5, (60, 60, 235), 2)

    cv2.putText(g, f"ayna: {'ACIK' if kamera_ayna else 'kapali'}  (a)",
                (200, 18), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (200, 200, 200), 1)
    cv2.imshow("TESHIS  -  a: ayna   q: cik", g)
    cv2.imshow("maske", cv2.resize(maske, (320, 240), interpolation=cv2.INTER_NEAREST))

    t = cv2.waitKey(1) & 0xFF
    if t == ord('q'):
        break
    if t == ord('a'):
        kamera_ayna = not kamera_ayna
        print(f"  ayna -> {'ACIK' if kamera_ayna else 'kapali'}")

cap.release()
cv2.destroyAllWindows()
if ard is not None:
    ard.write(f"<{NOTR},{NOTR}>\n".encode())
    ard.close()

baslik("SONUÇ -- cizgi_takip.py'de ayarlanacaklar")
print(f"    MOTOR_TAKAS  = {motor_takas}")
print(f"    KAMERA_AYNA  = {kamera_ayna}")
print("""
  Bu iki değeri cizgi_takip.py'nin başındaki aynı isimli satırlara yaz.
  İkisi de False çıktıysa ve araç hâlâ kayıyorsa: kameranın 180 derece ters
  monte olma ihtimali var (KAMERA_TERS = True dene).
""")
