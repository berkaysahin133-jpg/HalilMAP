# -*- coding: utf-8 -*-
"""Kamera acma ve taze kare alma. Video dosyasindan da beslenebilir (offline ayar)."""

import cv2


class Kamera:
    def __init__(self, ayar, kaynak=None):
        """kaynak: None -> gercek kamera | str -> video dosyasi (replay)"""
        self.a = ayar
        self.video_mu = isinstance(kaynak, str)

        if self.video_mu:
            self.cap = cv2.VideoCapture(kaynak)
            if not self.cap.isOpened():
                raise RuntimeError(f"Video acilamadi: {kaynak}")
            return

        self.cap = cv2.VideoCapture(ayar.indeks, cv2.CAP_V4L2)
        if not self.cap.isOpened():
            self.cap = cv2.VideoCapture(ayar.indeks)
        if not self.cap.isOpened():
            raise RuntimeError("Kamera acilamadi")

        self.cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, ayar.genislik)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, ayar.yukseklik)
        self.cap.set(cv2.CAP_PROP_FPS, ayar.fps)

        # V4L2 varsayilani 4 kare biriktirir -> ~100 ms olu zaman -> kontrol salinir
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

        if ayar.manuel_pozlama:
            try:
                self.cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)   # V4L2 manuel
                self.cap.set(cv2.CAP_PROP_EXPOSURE, ayar.pozlama)
                self.cap.set(cv2.CAP_PROP_GAIN, ayar.kazanc)
                self.cap.set(cv2.CAP_PROP_AUTO_WB, 0)
            except Exception:                                    # noqa: BLE001
                pass

    def oku(self):
        """(ok, ham_kare, islem_karesi) -- islem karesi kucultulmus haldedir."""
        if self.video_mu:
            ok, kare = self.cap.read()
        else:
            self.cap.grab()                                      # arabellegi tuket
            ok, kare = self.cap.retrieve()
        if not ok or kare is None:
            return False, None, None

        islem = cv2.resize(kare, (self.a.islem_genislik, self.a.islem_yukseklik),
                           interpolation=cv2.INTER_AREA)
        return True, kare, islem

    def kapat(self):
        if self.cap is not None:
            self.cap.release()
            self.cap = None
