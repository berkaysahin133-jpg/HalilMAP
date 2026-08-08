#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RPLIDAR C1 surucu testi -- LIDAR TAKILI OLMADAN calisir.

Sentetik bayt akisi uretip surucunun dogru cozdugunu dogrular.
Gercek cihaza takmadan once bunu calistir:  python3 test_c1.py
"""

import os
import sys
import time

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
        self.rts = True
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
    lid._on_tampon = bytearray()

    okunan = []
    ureteci = lid.olcumler(sessizlik=0.05)
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
lid._on_tampon = bytearray()

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
lid._on_tampon = bytearray()
lid._komut(c1.KOMUT_SCAN)
kontrol("SCAN komutu A5 20", bytes(lid.ser.yazilan) == b"\xA5\x20",
        lid.ser.yazilan.hex().upper())
lid.ser.yazilan.clear()
lid._komut(c1.KOMUT_STOP)
kontrol("STOP komutu A5 25", bytes(lid.ser.yazilan) == b"\xA5\x25",
        lid.ser.yazilan.hex().upper())

print("\n" + "=" * 62)
print(" 6. TARAMA BASLATMA  --  'kabul etti ama veri yok' yakalaniyor mu")
print("=" * 62)
c1.HAT_OTURMA_S = 0.0            # testte hat oturma beklemesi gereksiz


class SahteCihaz:
    """Komutlara cevap veren sahte C1.

    calisan_hat: olcum gonderdigi (dtr, rts) ikilisi. None = her zaman gonderir,
                 (-1,-1) gibi eslesmeyen bir deger = HIC gondermez (motor donmuyor).
    scan_tanim : SCAN'e tanimlayici verilsin mi.
    """
    def __init__(self, calisan_hat=None, scan_tanim=True):
        self.calisan_hat = calisan_hat
        self.scan_tanim = scan_tanim
        self.dtr = True
        self.rts = True
        self.is_open = True
        self.cikti = bytearray()
        self.tarama = False
        self.sayac = 0
        self.stop_sayisi = 0
        self.scan_sayisi = 0

    # -- cihaz tarafi ------------------------------------------------------
    def _uretir_mi(self):
        return self.tarama and (self.calisan_hat is None
                                or (self.dtr, self.rts) == self.calisan_hat)

    def _besle(self):
        if self._uretir_mi() and len(self.cikti) < 400:
            for _ in range(80):
                self.cikti += olcum_kodla(self.sayac % 500 == 0, 40,
                                          (self.sayac * 0.72) % 360.0, 1500.0)
                self.sayac += 1

    # -- pyserial arayuzu --------------------------------------------------
    @property
    def in_waiting(self):
        self._besle()
        return len(self.cikti)

    def read(self, n=1):
        self._besle()
        d = bytes(self.cikti[:n])
        del self.cikti[:len(d)]
        return d

    def write(self, b):
        if b == c1.BAYRAK + c1.KOMUT_SCAN:
            self.scan_sayisi += 1
            self.tarama = True
            if self.scan_tanim:
                self.cikti += b"\xA5\x5A\x05\x00\x00\x40\x81"
        elif b == c1.BAYRAK + c1.KOMUT_STOP:
            self.stop_sayisi += 1
            self.tarama = False
            self.cikti.clear()
        return len(b)

    def reset_input_buffer(self):
        self.cikti.clear()

    def close(self):
        self.is_open = False


def lidar_kur(cihaz):
    lid = c1.RPLidarC1.__new__(c1.RPLidarC1)
    lid.ser = cihaz
    lid._tarama_acik = False
    lid._on_tampon = bytearray()
    lid.motor_hatti = (False, True)
    return lid


# --- 6a: motor hic donmuyor -> tanimlayici gelir ama olcum gelmez ---
cihaz = SahteCihaz(calisan_hat=(None, None))       # hicbir hatta veri yok
lid = lidar_kur(cihaz)
try:
    lid.tarama_baslat(bekleme=0.1)
    kontrol("veri yokken hata veriliyor", False, "sessizce gecti")
except c1.VeriYokHatasi as e:
    metin = str(e)
    kontrol("veri yokken VeriYokHatasi", True)
    kontrol("hata mesaji motoru/beslemeyi isaret ediyor",
            "MOTOR DONMUYOR" in metin and "USB" in metin)
except c1.LidarHatasi as e:
    kontrol("veri yokken VeriYokHatasi", False, f"yanlis tur: {e}")
kontrol("tum motor hatti kombinasyonlari denendi",
        cihaz.scan_sayisi >= len(c1.MOTOR_HATTI_DENEMELERI),
        f"{cihaz.scan_sayisi} SCAN denemesi")

# --- 6b: sadece 3. kombinasyonda veri var -> onu bulmali ---
hedef = c1.MOTOR_HATTI_DENEMELERI[2]
cihaz = SahteCihaz(calisan_hat=hedef)
lid = lidar_kur(cihaz)
try:
    lid.tarama_baslat(bekleme=0.1)
    kontrol("dogru motor hatti bulundu", lid.motor_hatti == hedef,
            f"DTR={lid.motor_hatti[0]} RTS={lid.motor_hatti[1]}")
    kontrol("tarama acik isaretlendi", lid._tarama_acik)
except c1.LidarHatasi as e:
    kontrol("dogru motor hatti bulundu", False, str(e).splitlines()[0])

# --- 6c: on tampondaki baytlar kaybolmuyor ---
cihaz = SahteCihaz(calisan_hat=None)
lid = lidar_kur(cihaz)
lid.tarama_baslat(bekleme=0.1)
on = len(lid._on_tampon)
okunan = [x for _, x in zip(range(40), lid.olcumler(sessizlik=0.2))]
kontrol("SCAN sonrasi ilk baytlar tampona alindi", on > 0, f"{on} bayt")
kontrol("on tampondan olcum cozuluyor", len(okunan) == 40,
        f"{len(okunan)} olcum")
kontrol("mesafeler dogru cozuldu",
        all(abs(m - 1500.0) < 0.3 for _, _, _, m in okunan))

print("\n" + "=" * 62)
print(" 7. KISA SESSIZLIKTE PES ETMEME")
print("=" * 62)


class KesintiliSeri(SahteSeri):
    """Ilk N okumada bos doner (motor hizlanirken olan sey), sonra veri verir."""
    def __init__(self, veri, bos_okuma=8):
        super().__init__(veri)
        self.kalan_bos = bos_okuma
        self.bos_sayisi = 0

    def read(self, n=1):
        if self.kalan_bos > 0:
            self.kalan_bos -= 1
            self.bos_sayisi += 1
            return b""
        return super().read(n)


ham, beklenen = akis_uret(30)
lid = c1.RPLidarC1.__new__(c1.RPLidarC1)
lid.ser = KesintiliSeri(ham, bos_okuma=8)
lid._tarama_acik = True
lid._on_tampon = bytearray()
try:
    okunan = [x for _, x in zip(range(20), lid.olcumler(sessizlik=5.0))]
    kontrol("bos okumalar hata saymiyor", len(okunan) == 20,
            f"{lid.ser.bos_sayisi} bos okuma atlatildi, {len(okunan)} olcum")
except c1.LidarHatasi as e:
    kontrol("bos okumalar hata saymiyor", False, str(e).splitlines()[0])

# Sessizlik suresi asilirsa hata VERMELI (sonsuz beklemek de yanlis)
lid = c1.RPLidarC1.__new__(c1.RPLidarC1)
lid.ser = SahteSeri(b"")
lid._tarama_acik = True
lid._on_tampon = bytearray()
t0 = time.monotonic()
try:
    next(lid.olcumler(sessizlik=0.3))
    kontrol("sessizlik asilinca hata veriliyor", False, "hata gelmedi")
except c1.VeriYokHatasi:
    gecen = time.monotonic() - t0
    kontrol("sessizlik asilinca hata veriliyor", 0.25 < gecen < 2.0,
            f"{gecen:.2f} sn sonra")

print("\n" + "=" * 62)
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print("=" * 62)
sys.exit(1 if BASARISIZ else 0)
