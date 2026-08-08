# -*- coding: utf-8 -*-
"""KARA KUTU -- "köşede çizgiyi kaybediyor" sorununu TEK KOŞUDA çözer.

Neden buna ihtiyaç var:
    Uzaktan ayar değeri tahmin etmek gün yakar. Bu modül, aracın kaybettiği
    ANIN öncesindeki 2 saniyeyi kaydeder: kamera görüntüsü, maske, kontur
    ölçüleri ve KÖŞE KOŞULLARININ HER BİRİNİN doğru mu yanlış mı olduğu.
    Çıkan klasörü paylaşınca hangi eşiğin tutmadığı ölçülerek görülür.

Davranışı DEĞİŞTİRMEZ. Sadece dosya yazar. İstemezsen ACIK = False yap.

Çıktı (kara_kutu/kayip_001/ gibi bir klasör):
    00_kare.png ... 45_kare.png    kayıptan önceki kareler (görüntü + maske)
    olcumler.csv                   her karenin sayısal ölçüleri
    ozet.txt                       hangi koşul kaç karede sağlandı

Ayrıca tüm koşu boyunca kara_kutu/surekli.csv yazılır -- köşeye yaklaşırken
alan/genişlik nasıl değişiyor, eğilim oradan görülür.
"""

import csv
import os
import time
from collections import deque

import cv2
import numpy as np

ACIK = True
SANIYE = 2.0                 # kayıp anından geriye kaç saniye saklansın
KLASOR = "kara_kutu"


class KaraKutu:
    def __init__(self, klasor=KLASOR, saniye=SANIYE, acik=ACIK):
        self.acik = acik
        if not self.acik:
            return
        self.klasor = klasor
        os.makedirs(klasor, exist_ok=True)
        self.tampon = deque(maxlen=int(saniye * 40))     # 40 fps varsayımı
        self.dokum_sayisi = 0
        self.baslangic = time.monotonic()
        self.surekli = open(os.path.join(klasor, "surekli.csv"), "w",
                            newline="", encoding="utf-8")
        self.yazici = csv.writer(self.surekli)
        self.yazici.writerow(["zaman_s", "durum", "alan", "x", "y", "w", "h",
                              "cx", "sol_kosul", "sag_kosul", "alan600",
                              "w65", "sol_kenar", "sag_kenar"])

    # ------------------------------------------------------------------ kayıt
    def kare(self, durum, goruntu, maske, c=None):
        """Her karede çağır. c = en büyük kontur (yoksa None)."""
        if not self.acik:
            return
        t = time.monotonic() - self.baslangic

        if c is not None and len(c):
            alan = float(cv2.contourArea(c))
            x, y, w, h = cv2.boundingRect(c)
            M = cv2.moments(c)
            cx = int(M["m10"] / M["m00"]) if M["m00"] else (x + w // 2)
        else:
            alan = 0.0
            x = y = w = h = 0
            cx = -1

        # Kodun köşe koşullarının BİREBİR aynısı (cizgi_takip_stabil.py:433/439)
        alan600 = alan > 600
        w65 = w > 65
        sol_kenar = x < 15
        sag_kenar = (x + w) > 145
        sol_kosul = alan600 and ((sol_kenar and w65) or (0 <= cx <= 15))
        sag_kosul = alan600 and ((sag_kenar and w65) or cx >= 145)

        satir = [round(t, 3), durum, int(alan), x, y, w, h, cx,
                 int(sol_kosul), int(sag_kosul), int(alan600), int(w65),
                 int(sol_kenar), int(sag_kenar)]
        self.yazici.writerow(satir)
        self.surekli.flush()
        self.tampon.append((satir, goruntu.copy(), maske.copy()))

    # ------------------------------------------------------------------ döküm
    def dok(self, sebep="kayip"):
        """Çizgi kaybedildiğinde çağır. Son 2 saniyeyi diske yazar."""
        if not self.acik or not self.tampon:
            return
        self.dokum_sayisi += 1
        yol = os.path.join(self.klasor, f"{sebep}_{self.dokum_sayisi:03d}")
        os.makedirs(yol, exist_ok=True)

        with open(os.path.join(yol, "olcumler.csv"), "w", newline="",
                  encoding="utf-8") as f:
            y = csv.writer(f)
            y.writerow(["zaman_s", "durum", "alan", "x", "y", "w", "h", "cx",
                        "sol_kosul", "sag_kosul", "alan600", "w65",
                        "sol_kenar", "sag_kenar"])
            for satir, _, _ in self.tampon:
                y.writerow(satir)

        for i, (satir, goruntu, maske) in enumerate(self.tampon):
            self._kare_yaz(os.path.join(yol, f"{i:02d}_kare.png"),
                           goruntu, maske, satir)

        self._ozet(yol)
        print(f"[KARA KUTU] {len(self.tampon)} kare yazildi -> {yol}")

    def _kare_yaz(self, yol, goruntu, maske, s):
        """Görüntü + maske yan yana, ölçüler ve koşullar üzerine yazılı."""
        g = cv2.resize(goruntu, (320, 240))
        m = cv2.cvtColor(cv2.resize(maske, (320, 240)), cv2.COLOR_GRAY2BGR)

        # Sütun sırası: 0 zaman 1 durum 2 alan 3 x 4 y 5 w 6 h 7 cx
        _, _, alan, x, y, w, h, cx = s[0:8]
        # Konturun sınır kutusunu maske üzerine çiz (160x120 -> 320x240 = x2)
        if w or h:
            cv2.rectangle(m, (x * 2, y * 2), ((x + w) * 2, (y + h) * 2),
                          (0, 200, 255), 2)
        if cx >= 0:
            cv2.line(m, (cx * 2, 0), (cx * 2, 240), (255, 120, 0), 1)
        # Eşik çizgileri: x=15 ve x=145 (160 px genişlikte)
        cv2.line(m, (30, 0), (30, 240), (80, 80, 80), 1)
        cv2.line(m, (290, 0), (290, 240), (80, 80, 80), 1)

        tuval = np.zeros((240 + 92, 640, 3), np.uint8)
        tuval[0:240, 0:320] = g
        tuval[0:240, 320:640] = m

        def yaz(satir_no, metin, renk=(235, 235, 235)):
            cv2.putText(tuval, metin, (8, 258 + satir_no * 20),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.42, renk, 1, cv2.LINE_AA)

        yaz(0, f"t={s[0]:.2f}s  DURUM={s[1]}")
        yaz(1, f"alan={alan}  x={x} y={y} w={w} h={h}  cx={cx}")
        ok = (110, 230, 120)
        yok = (90, 90, 240)
        yaz(2, f"alan>600: {'EVET' if s[10] else 'HAYIR'}    "
               f"w>65: {'EVET' if s[11] else 'HAYIR'}    "
               f"x<15: {'EVET' if s[12] else 'HAYIR'}    "
               f"x+w>145: {'EVET' if s[13] else 'HAYIR'}",
            ok if (s[10] and s[11]) else yok)
        yaz(3, f"SOL KOSE: {'TETIKLENDI' if s[8] else 'hayir'}     "
               f"SAG KOSE: {'TETIKLENDI' if s[9] else 'hayir'}",
            ok if (s[8] or s[9]) else yok)
        cv2.imwrite(yol, tuval)

    def _ozet(self, yol):
        """Hangi koşulun tutmadığını doğrudan söyler."""
        satirlar = [s for s, _, _ in self.tampon]
        n = len(satirlar)
        if not n:
            return
        say = lambda i: sum(1 for s in satirlar if s[i])   # noqa: E731
        en_buyuk_alan = max(s[2] for s in satirlar)     # sutun 2 = alan
        en_buyuk_w = max(s[5] for s in satirlar)        # sutun 5 = w (6 = h!)

        L = [
            f"KARA KUTU OZETI  --  kayiptan onceki {n} kare",
            "=" * 62,
            f"  alan > 600 saglandi     : {say(10):3d}/{n}   (en buyuk alan {en_buyuk_alan})",
            f"  w > 65 saglandi         : {say(11):3d}/{n}   (en buyuk w {en_buyuk_w})",
            f"  x < 15 (sol kenar)      : {say(12):3d}/{n}",
            f"  x+w > 145 (sag kenar)   : {say(13):3d}/{n}",
            f"  SOL KOSE tetiklendi     : {say(8):3d}/{n}",
            f"  SAG KOSE tetiklendi     : {say(9):3d}/{n}",
            "",
        ]
        if say(8) == 0 and say(9) == 0:
            L.append("TESHIS: Kose HIC tetiklenmedi -> ALGILAMA sorunu.")
            if en_buyuk_alan <= 600:
                L.append(f"  Sebep: alan hic 600'u gecmedi (en buyuk {en_buyuk_alan}).")
                L.append(f"  Denenecek: alan esigini {int(en_buyuk_alan * 0.6)} yap.")
            elif en_buyuk_w <= 65:
                L.append(f"  Sebep: kontur genisligi hic 65'i gecmedi (en buyuk {en_buyuk_w}).")
                L.append(f"  Denenecek: w esigini {int(en_buyuk_w * 0.7)} yap.")
            else:
                L.append("  alan ve w yeterli ama kenar sarti tutmuyor ->")
                L.append("  x<15 / x+w>145 esiklerini gevset (orn. 25 / 135).")
        else:
            L.append("TESHIS: Kose TETIKLENDI -> algilama calisiyor.")
            L.append("  Sorun ilerleme suresi (VIRAJ_ILERI_SURESI) ya da pivotta.")
            L.append("  Kayip anindaki DURUM sutununa bak.")
        L.append("")
        L.append("Bu klasoru oldugu gibi paylas.")

        metin = "\n".join(L)
        with open(os.path.join(yol, "ozet.txt"), "w", encoding="utf-8") as f:
            f.write(metin)
        print("\n" + metin + "\n")

    def kapat(self):
        if self.acik:
            try:
                self.surekli.close()
            except Exception:
                pass
