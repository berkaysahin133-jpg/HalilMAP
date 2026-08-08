# -*- coding: utf-8 -*-
"""Arduino/MCP4725 baglantisi. cm/s -> DAC cevrimi tek yerde."""

import glob
import time

import numpy as np

try:
    import serial
except ImportError:
    serial = None


class MotorLink:
    PORT_ADAYLARI = ("/dev/ttyUSB*", "/dev/ttyACM*")

    def __init__(self, motor_ayar, kontrol_ayar, kuru=False):
        self.m = motor_ayar
        self.c = kontrol_ayar
        self.kuru = kuru
        self.ser = None
        self._son_paket = None
        self._son_gonderim = 0.0
        self.son_heartbeat = time.monotonic()
        self.gecmis = []                      # kuru modda test icin

        if kuru:
            return
        if serial is None:
            raise RuntimeError("pyserial kurulu degil:  pip install pyserial")

        port = self.m.port or self._port_bul()
        if port is None:
            raise RuntimeError("Arduino bulunamadi (/dev/ttyUSB* veya /dev/ttyACM*)")
        self.ser = serial.Serial(port, self.m.baud, timeout=0, write_timeout=0.05)
        time.sleep(2.0)                        # DTR reset
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()
        self.port = port

    @classmethod
    def _port_bul(cls):
        for kalip in cls.PORT_ADAYLARI:
            b = sorted(glob.glob(kalip))
            if b:
                return b[0]
        return None

    # ------------------------------------------------------------------ cevrim
    def hiz_to_dac(self, cm_s):
        """cm/s -> DAC. hiz_max_cm_s, tam_gaz_ofset'e karsilik gelir."""
        oran = float(np.clip(cm_s / self.c.hiz_max_cm_s, -1.0, 1.0))
        ham = self.m.notr + self.m.yon * self.m.tam_gaz_ofset * oran
        return int(np.clip(round(ham), 0, 4095))

    def pivot_dac(self, yon):
        """yon: +1 saga, -1 sola. (sol_dac, sag_dac)"""
        o = self.m.pivot_ofset * (1 if yon > 0 else -1)
        return (int(np.clip(self.m.notr + self.m.yon * o, 0, 4095)),
                int(np.clip(self.m.notr - self.m.yon * o, 0, 4095)))

    # ------------------------------------------------------------------ gonder
    def _yaz(self, sol_dac, sag_dac, zorla=False):
        paket = (int(sol_dac), int(sag_dac))
        simdi = time.monotonic()
        periyot = 1.0 / max(1.0, self.m.komut_hz)
        if not zorla and paket == self._son_paket and (simdi - self._son_gonderim) < periyot:
            return
        self._son_paket, self._son_gonderim = paket, simdi
        self.gecmis.append(paket)
        if self.kuru or self.ser is None:
            return
        try:
            self.ser.write(f"<{paket[0]},{paket[1]}>\n".encode("ascii"))
        except Exception as e:                 # noqa: BLE001
            print(f"[HATA] Seri yazma: {e}")

    def sur(self, sol_cm_s, sag_cm_s):
        self._yaz(self.hiz_to_dac(sol_cm_s), self.hiz_to_dac(sag_cm_s))

    def pivot(self, yon):
        s, g = self.pivot_dac(yon)
        self._yaz(s, g)

    def dur(self):
        self._yaz(self.m.notr, self.m.notr, zorla=True)

    def dinle(self):
        """Firmware heartbeat'ini yut, RX birikmesin."""
        if self.kuru or self.ser is None:
            return
        try:
            if self.ser.in_waiting:
                self.ser.read(self.ser.in_waiting)
                self.son_heartbeat = time.monotonic()
        except Exception:                      # noqa: BLE001
            pass

    def kapat(self):
        try:
            self.dur()
            time.sleep(0.05)
            self.dur()
        finally:
            if self.ser is not None and self.ser.is_open:
                self.ser.close()
                self.ser = None
