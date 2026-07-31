# -*- coding: utf-8 -*-
"""Kusbakisi (Inverse Perspective Mapping) donusumu.

Neden sart:
  Normal kamera goruntusunde 1 piksel, araca yakinken 2 mm, uzaktayken 3 cm
  demek. Bu yuzden "cx - 80" gibi bir piksel hatasi fiziksel bir anlam tasimaz
  ve PID ayari hizla/egimle birlikte kayar. Kusbakisina cevirince:
    - Cizgi gercekten duz gorunur, viraj gercek yariçapiyla egilir
    - Hata SANTIMETRE cinsinden olculur, ayarlar fiziksel anlam kazanir
    - 90 derecelik kose, goruntude de gercekten 90 derecedir
"""

import numpy as np
import cv2


class Perspektif:
    def __init__(self, kam_ayar, per_ayar):
        self.kam = kam_ayar
        self.per = per_ayar
        self.gorunur_yakin_cm, self.gorunur_uzak_cm = self._gorunur_aralik()
        self._aralik_dogrula()
        self.genislik_px = int(round((per_ayar.x_max_cm - per_ayar.x_min_cm) * per_ayar.piksel_cm))
        self.yukseklik_px = int(round((per_ayar.y_max_cm - per_ayar.y_min_cm) * per_ayar.piksel_cm))
        self.M, self.M_ters = self._homografi_kur()
        self.gecerli_maske = self._gecerli_maske_kur()

    def _gecerli_maske_kur(self):
        """Kusbakisinda GERCEK kamera pikselinden gelen bolge.

        Kusbakisi dikdortgeninin koseleri kameranin gorus alani disinda kalir ve
        warp bunlari sabit renkle doldurur. Bu yapay dolgunun KENARI, yerel
        ortalama cikarma yonteminde sahte bir "cizgi" uretir ve kayan pencere
        ona yapisir. Bu yuzden gecersiz bolgeyi acikca disarida birakiyoruz.
        """
        kaynak = np.full((self.kam.islem_yukseklik, self.kam.islem_genislik),
                         255, np.uint8)
        m = cv2.warpPerspective(kaynak, self.M, (self.genislik_px, self.yukseklik_px),
                                flags=cv2.INTER_NEAREST,
                                borderMode=cv2.BORDER_CONSTANT, borderValue=0)
        # Kenardaki yerel-ortalama halesini de disarida birak
        pay = max(3, int(round(2.0 * self.per.piksel_cm)) | 1)
        cekirdek = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (pay, pay))
        return cv2.erode(m, cekirdek)

    def _gorunur_aralik(self):
        """Kameranin GERCEKTEN gordugu en yakin ve en uzak Y mesafesi (cm).

        Kritik: kamera, oz gorus geometrisi geregi burnunun dibini goremez.
        h=22 cm / egim=32 derece bir kamera ancak ~15 cm'den itibaren goruyor.
        y_min_cm bunun altinda kalirsa polinom GORULMEYEN bolgede ekstrapole
        edilir; yanal hata kazanc hatasi alir, yon acisi tamamen bozulur.
        """
        w, h = self.kam.islem_genislik, self.kam.islem_yukseklik
        f = (w / 2.0) / np.tan(np.radians(self.per.yatay_fov_derece) / 2.0)
        cv_ = h / 2.0
        t = np.radians(self.per.egim_derece)
        yuk = self.per.kamera_yuksekligi_cm

        def Y_of_v(v):
            # v = cv + f * (-Y sin t + yuk cos t) / (Y cos t + yuk sin t)
            a = (v - cv_) / f
            pay = yuk * (np.cos(t) - a * np.sin(t))
            payda = a * np.cos(t) + np.sin(t)
            if payda <= 1e-9:
                return np.inf          # ufkun ustu
            return float(pay / payda)

        yakin = Y_of_v(h - 1)          # goruntunun alt kenari
        uzak = Y_of_v(0)               # ust kenari (ufka yakinsa inf)
        return yakin, min(uzak, 1e4)

    def _aralik_dogrula(self):
        """y_min/y_max gorulebilir aralikta mi? Degilse duzelt ve uyar."""
        pay = 1.5
        if self.per.y_min_cm < self.gorunur_yakin_cm + pay:
            yeni = round(self.gorunur_yakin_cm + pay, 1)
            print(f"[PERSPEKTIF UYARI] y_min_cm={self.per.y_min_cm:.1f} cm kameranin "
                  f"KOR NOKTASINDA (en yakin gorulen {self.gorunur_yakin_cm:.1f} cm). "
                  f"{yeni} cm'ye cekildi.")
            print( "                   Daha yakini gormek icin: kamerayi alcalt "
                   "(kamera_yuksekligi_cm) veya egimi artir (egim_derece).")
            self.per.y_min_cm = yeni
        if self.per.y_max_cm > self.gorunur_uzak_cm:
            yeni = round(min(self.gorunur_uzak_cm - 1.0,
                             self.per.y_min_cm + 20.0), 1)
            print(f"[PERSPEKTIF UYARI] y_max_cm={self.per.y_max_cm:.1f} cm gorus "
                  f"disinda (en uzak {self.gorunur_uzak_cm:.1f} cm). {yeni} cm'ye cekildi.")
            self.per.y_max_cm = max(yeni, self.per.y_min_cm + 10.0)

    # ---------------------------------------------------------------- yardimci
    def dunya_to_kus(self, X_cm, Y_cm):
        """Yer duzlemi (cm) -> kusbakisi piksel. X sag, Y ileri.

        Kusbakisi goruntusunde: sol ust = (x_min, y_max), alt = araca yakin.
        """
        u = (X_cm - self.per.x_min_cm) * self.per.piksel_cm
        v = (self.per.y_max_cm - Y_cm) * self.per.piksel_cm
        return u, v

    def kus_to_dunya(self, u, v):
        """Kusbakisi piksel -> yer duzlemi (cm)."""
        X = u / self.per.piksel_cm + self.per.x_min_cm
        Y = self.per.y_max_cm - v / self.per.piksel_cm
        return X, Y

    # ------------------------------------------------------------- homografi
    def _homografi_kur(self):
        if self.per.kaynak_noktalar and self.per.hedef_noktalar_cm:
            kaynak = np.array(self.per.kaynak_noktalar, np.float32)
            hedef = np.array([self.dunya_to_kus(X, Y)
                              for X, Y in self.per.hedef_noktalar_cm], np.float32)
        else:
            kaynak, hedef = self._geometrik_noktalar()

        M = cv2.getPerspectiveTransform(kaynak, hedef)
        return M, np.linalg.inv(M)

    def _geometrik_noktalar(self):
        """Kamera yuksekligi + egim + FOV'dan homografi noktalari uret.

        4 nokta tiklamadan calisan pratik yol: sadece mezura ve acilolcer yeter.
        """
        w, h = self.kam.islem_genislik, self.kam.islem_yukseklik
        # Odak uzunlugu (piksel), yatay FOV'dan
        f = (w / 2.0) / np.tan(np.radians(self.per.yatay_fov_derece) / 2.0)
        cu, cv_ = w / 2.0, h / 2.0
        teta = np.radians(self.per.egim_derece)
        yukseklik = self.per.kamera_yuksekligi_cm

        def yer_to_goruntu(X, Y):
            """Yerdeki (X,Y) cm noktasinin goruntudeki pikseli.

            Kamera (0,0,yukseklik)'te, optik eksen ileri ve teta kadar asagi.
            Dunya: X sag, Y ileri, Z yukari.
            """
            # Noktanin kamera cercevesindeki konumu
            dx = X
            dy = Y
            dz = -yukseklik
            # Kamera eksenleri (dunya cinsinden)
            #   x_cam = (1, 0, 0)
            #   z_cam = (0,  cos t, -sin t)
            #   y_cam = (0, -sin t, -cos t)
            xc = dx
            yc = -dy * np.sin(teta) - dz * np.cos(teta)
            zc = dy * np.cos(teta) - dz * np.sin(teta)
            if zc <= 1e-6:
                return None
            return cu + f * xc / zc, cv_ + f * yc / zc

        # Yerde bir yamuk sec: yakin kenar dar, uzak kenar genis olsun ki
        # goruntudeki 4 nokta iyi yayilsin.
        Y_yakin = self.per.y_min_cm
        Y_uzak = self.per.y_max_cm
        X_k = min(abs(self.per.x_min_cm), self.per.x_max_cm) * 0.9
        X_u = X_k

        dunya = [(-X_k, Y_yakin), (X_k, Y_yakin), (X_u, Y_uzak), (-X_u, Y_uzak)]
        goruntu = []
        for X, Y in dunya:
            p = yer_to_goruntu(X, Y)
            if p is None:
                raise ValueError(
                    "Kamera geometrisi gecersiz: egim_derece ve y_min_cm degerlerini kontrol et "
                    "(kamera o kadar uzagi goremiyor)."
                )
            goruntu.append(p)

        kaynak = np.array(goruntu, np.float32)
        hedef = np.array([self.dunya_to_kus(X, Y) for X, Y in dunya], np.float32)
        return kaynak, hedef

    # ----------------------------------------------------------------- kullanim
    def warp(self, kare):
        """Isleme boyutundaki kareyi kusbakisina cevirir."""
        return cv2.warpPerspective(
            kare, self.M, (self.genislik_px, self.yukseklik_px),
            # REPLICATE: gorus alani disi, en yakin gecerli pikselin degeriyle
            # doldurulur. Sabit renk kullanmak orada YAPAY BIR KENAR yaratiyor,
            # yerel ortalama cikarma da o kenari "cizgi" sayiyordu.
            flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_REPLICATE
        )

    def ters_warp_noktalar(self, noktalar_kus):
        """Kusbakisi noktalarini orijinal goruntuye geri tasi (cizim icin)."""
        if len(noktalar_kus) == 0:
            return np.empty((0, 2), np.float32)
        p = np.array(noktalar_kus, np.float32).reshape(-1, 1, 2)
        return cv2.perspectiveTransform(p, self.M_ters).reshape(-1, 2)

    def gorus_alani_bilgisi(self):
        return (f"Kusbakisi: {self.genislik_px}x{self.yukseklik_px} px  |  "
                f"X {self.per.x_min_cm:+.0f}..{self.per.x_max_cm:+.0f} cm, "
                f"Y {self.per.y_min_cm:.0f}..{self.per.y_max_cm:.0f} cm  |  "
                f"{self.per.piksel_cm:.1f} px/cm")
