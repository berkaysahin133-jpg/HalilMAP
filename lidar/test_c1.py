#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RPLIDAR C1 surucu testi -- LIDAR TAKILI OLMADAN calisir.

Sentetik bayt akisi uretip surucunun dogru cozdugunu dogrular.
Gercek cihaza takmadan once bunu calistir:  python3 test_c1.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c1

GECTI = BASARISIZ = 0


def kontrol(ad, sart, detay=""):
    global GECTI, BASARISIZ
    if sart:
        GECTI += 1
        print(f"  OK   {ad}  {detay}")
    else:
        BASARISIZ += 1
        print(f"  FAIL {ad}  {detay}")


def olcum_kodla(yeni_tur, kalite, aci_derece, mesafe_mm):
    """Surucunun cozdugu formatta 5 baytlik olcum uretir (protokole gore)."""
    s = 1 if yeni_tur else 0
    b0 = (kalite << 2) | ((1 - s) << 1) | s
    aci_q6 = int(round(aci_derece * 64.0)) & 0x7FFF
    b1 = ((aci_q6 & 0x7F) << 1) | 1          # bit0 = kontrol biti = 1
    b2 = (aci_q6 >> 7) & 0xFF
    mes_q2 = int(round(mesafe_mm * 4.0)) & 0xFFFF
    b3 = mes_q2 & 0xFF
    b4 = (mes_q2 >> 8) & 0xFF
    return bytes([b0, b1, b2, b3, b4])


print("=" * 62)
print(" 1. OLCUM COZUCU  --  kodla/coz gidis-donus")
print("=" * 62)
for yeni, kal, aci, mes in [(True, 47, 0.0, 1000.0),
                            (False, 15, 90.0, 250.5),
                            (False, 63, 180.0, 6000.0),
                            (False, 0, 359.28, 12000.0),
                            (True, 32, 45.75, 55.25)]:
    ham = olcum_kodla(yeni, kal, aci, mes)
    y2, k2, a2, m2 = c1.olcum_coz(ham)
    ok = (y2 == yeni and k2 == kal
          and abs(a2 - aci) < 0.02 and abs(m2 - mes) < 0.3)
    kontrol(f"aci={aci:7.2f} mesafe={mes:8.1f} kalite={kal:2d}", ok,
            f"-> aci={a2:.2f} mesafe={m2:.1f} kalite={k2} yeni={y2}")

print("\n  Acisal cozunurluk kontrolu (C1: 0.72 derece):")
a = c1.olcum_coz(olcum_kodla(False, 20, 0.72, 500))[2]
kontrol("0.72 derece temsil edilebiliyor", abs(a - 0.72) < 0.02, f"-> {a:.4f}")

print("\n" + "=" * 62)
print(" 2. BOZUK VERI REDDI")
print("=" * 62)
gecerli = olcum_kodla(False, 20, 100.0, 1234.0)

kotu = bytearray(gecerli); kotu[0] = (kotu[0] & 0xFC) | 0b11   # S == !S
try:
    c1.olcum_coz(bytes(kotu)); kontrol("bayrak tutarsizligi yakalandi", False)
except c1.LidarHatasi:
    kontrol("bayrak tutarsizligi yakalandi", True)

kotu = bytearray(gecerli); kotu[1] &= 0xFE                      # kontrol biti 0
try:
    c1.olcum_coz(bytes(kotu)); kontrol("kontrol biti hatasi yakalandi", False)
except c1.LidarHatasi:
    kontrol("kontrol biti hatasi yakalandi", True)

print("\n" + "=" * 62)
print(" 3. AKIS AYRISTIRMA + YENIDEN HIZALANMA")
print("=" * 62)


class SahteSeri:
    """Seri portu taklit eder. 'kayma' kadar cop bayt basa eklenir."""
    def __init__(self, veri, kayma=0):
        self.veri = bytes([0xAB] * kayma) + veri
        self.i = 0
        self.dtr = False
        self.is_open = True
        self.yazilan = bytearray()

    @property
    def in_waiting(self):
        return len(self.veri) - self.i

    def read(self, n=1):
        d = self.veri[self.i:self.i + n]
        self.i += len(d)
        return d

    def write(self, b):
        self.yazilan.extend(b); return len(b)

    def reset_input_buffer(self): pass
    def close(self): self.is_open = False


def akis_uret(nokta_sayisi, tur_basi=0):
    """tur_basi indeksinde yeni-tur bayragi olan bir olcum dizisi."""
    ham = bytearray()
    beklenen = []
    for i in range(nokta_sayisi):
        yeni = (i == tur_basi)
        aci = (i * 0.72) % 360.0
        mes = 500.0 + i * 3.0
        ham += olcum_kodla(yeni, 40, aci, mes)
        beklenen.append((yeni, 40, aci, mes))
    return bytes(ham), beklenen


for kayma in (0, 1, 3):
    ham, beklenen = akis_uret(60)
    lid = c1.RPLidarC1.__new__(c1.RPLidarC1)      # __init__ atla (port yok)
    lid.ser = SahteSeri(ham, kayma=kayma)
    lid._tarama_acik = True

    okunan = []
    ureteci = lid.olcumler()
    try:
        for _ in range(len(beklenen) - 1):        # kayma birkac olcumu yer
            okunan.append(next(ureteci))
    except (c1.LidarHatasi, StopIteration):
        pass

    # Kaymali durumda basta birkac olcum kaybolabilir; kalanlar DOGRU olmali
    hatali = 0
    for (y, k, a, m) in okunan:
        if not any(abs(a - ba) < 0.02 and abs(m - bm) < 0.3
                   for (_, _, ba, bm) in beklenen):
            hatali += 1
    kontrol(f"{kayma} bayt kayma -> yeniden hizalandi",
            hatali == 0 and len(okunan) > len(beklenen) - 5,
            f"{len(okunan)}/{len(beklenen)} olcum, {hatali} hatali")

print("\n" + "=" * 62)
print(" 4. TAM TUR AYIRMA")
print("=" * 62)
ham = bytearray()
for tur in range(3):
    for i in range(120):
        ham += olcum_kodla(i == 0, 40, i * 3.0, 1000.0 + tur * 100)
lid = c1.RPLidarC1.__new__(c1.RPLidarC1)
lid.ser = SahteSeri(bytes(ham))
lid._tarama_acik = True

turlar = []
try:
    for t in lid.taramalar(min_nokta=100):
        turlar.append(t)
        if len(turlar) >= 2:
            break
except c1.LidarHatasi:
    pass
kontrol("tam turlar ayrildi", len(turlar) >= 2, f"{len(turlar)} tur")
if turlar:
    kontrol("tur basina nokta sayisi dogru", len(turlar[0]) == 120,
            f"{len(turlar[0])} nokta")
    mesafeler = {round(m) for _, m, _ in turlar[0]}
    kontrol("ilk tur tek mesafede", len(mesafeler) == 1, f"{mesafeler}")

print("\n" + "=" * 62)
print(" 5. KOMUT BAYTLARI")
print("=" * 62)
lid = c1.RPLidarC1.__new__(c1.RPLidarC1)
lid.ser = SahteSeri(b"")
lid._tarama_acik = False
lid._komut(c1.KOMUT_SCAN)
kontrol("SCAN komutu A5 20", bytes(lid.ser.yazilan) == b"\xA5\x20",
        lid.ser.yazilan.hex().upper())
lid.ser.yazilan.clear()
lid._komut(c1.KOMUT_STOP)
kontrol("STOP komutu A5 25", bytes(lid.ser.yazilan) == b"\xA5\x25",
        lid.ser.yazilan.hex().upper())

print("\n" + "=" * 62)
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print("=" * 62)
sys.exit(1 if BASARISIZ else 0)
