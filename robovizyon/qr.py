# -*- coding: utf-8 -*-
"""QR okuma: ROI + cok kareli onay.

Eski koddaki iki sorun:
  1) Her karede tam cozunurlukte pyzbar cagriliyordu -> Pi 5'te ~15 ms, FPS yariya
  2) TEK karelik okuma manevra tetikliyordu -> yanlis okuma = yanlis donus

Burada: dar bir ROI'de tarama, okunamazsa buyutup tekrar deneme, ve N kare
ust uste AYNI icerik okunmadan manevra tetiklenmiyor.
"""

import cv2
import numpy as np

try:
    from pyzbar.pyzbar import decode as _pyzbar_decode
except ImportError:
    _pyzbar_decode = None


class QROkuyucu:
    def __init__(self, qr_ayar):
        self.a = qr_ayar
        self._gecmis = []
        self._kare = 0
        self._cv_dedektor = cv2.QRCodeDetector()
        self.son_kutu = None            # cizim icin (x, y, w, h)

    def _coz(self, gri):
        """Once pyzbar (daha toleransli), yoksa OpenCV'ye dus."""
        sonuc = []
        if _pyzbar_decode is not None:
            try:
                sonuc = [o.data.decode("utf-8", errors="ignore") for o in _pyzbar_decode(gri)]
            except Exception:               # noqa: BLE001
                sonuc = []
        if not sonuc:
            try:
                veri, nokta, _ = self._cv_dedektor.detectAndDecode(gri)
                if veri:
                    sonuc = [veri]
                    if nokta is not None:
                        p = nokta.reshape(-1, 2)
                        self.son_kutu = (int(p[:, 0].min()), int(p[:, 1].min()),
                                         int(p[:, 0].ptp()), int(p[:, 1].ptp()))
            except Exception:               # noqa: BLE001
                pass
        return sonuc

    def tara(self, kare_bgr):
        """Kareyi tarar. Onaylanmis icerik varsa string, yoksa None doner."""
        if not self.a.aktif:
            return None

        self._kare += 1
        if self._kare % max(1, self.a.tarama_arasi):
            return None

        h, w = kare_bgr.shape[:2]
        y0 = int(h * self.a.roi_ust)
        y1 = int(h * self.a.roi_alt)
        roi = kare_bgr[y0:y1, :]
        gri = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY) if roi.ndim == 3 else roi

        # Kontrasti ac: salon isigi parlamasi QR modullerini yutuyor
        gri = cv2.normalize(gri, None, 0, 255, cv2.NORM_MINMAX)

        icerikler = self._coz(gri)
        if not icerikler and self.a.buyutme > 1.0:
            # Uzaktaki/kucuk QR icin bir de buyutup dene
            buyuk = cv2.resize(gri, None, fx=self.a.buyutme, fy=self.a.buyutme,
                               interpolation=cv2.INTER_CUBIC)
            icerikler = self._coz(buyuk)

        okunan = self.a.hedef_icerik if self.a.hedef_icerik in icerikler else None

        # --- Cok kareli onay ---
        self._gecmis.append(okunan)
        if len(self._gecmis) > self.a.onay_kare:
            self._gecmis.pop(0)

        if (len(self._gecmis) >= self.a.onay_kare
                and all(g == self.a.hedef_icerik for g in self._gecmis)):
            self._gecmis.clear()
            return self.a.hedef_icerik
        return None

    def sifirla(self):
        self._gecmis.clear()
        self.son_kutu = None
