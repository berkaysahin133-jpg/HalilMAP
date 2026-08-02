# -*- coding: utf-8 -*-
"""Slamtec RPLIDAR C1 - bagimsiz surucu (sadece pyserial gerekir).

Neden kendi surucumuz:
  ROS 2 kurulumu bir saat alabilir. Bu dosya, LiDAR'in calistigini ve veri
  aktigini 5 dakikada dogrulamani saglar. ROS'a sonra gecersin.

C1 ozellikleri (uretici verisi):
  menzil 0.05-12 m (beyaz yuzey) / 0.05-6 m (siyah)
  tarama 8-12 Hz (tipik 10)      ornekleme 5 kHz
  acisal cozunurluk 0.72 derece  arayuz TTL UART, 460800 baud
  mesafe cozunurlugu 30 mm       dogruluk 15 mm

DIKKAT -- en sik yapilan hata: C1'in baud hizi 460800'dur.
A1/A2 icin yazilmis ornekler 115200 kullanir; o hizla C1'den hicbir sey
okuyamazsin (port acilir ama veri gelmez).

Protokol (Slamtec standart SCAN, 5 bayt/olcum):
    bayt0: bit0 = yeni tur bayragi (S)
           bit1 = S'nin DEGILI (dogrulama)
           bit2-7 = kalite
    bayt1: bit0 = kontrol biti (1 olmali)
           bit1-7 = aci_q6'nin dusuk 7 biti
    bayt2: aci_q6'nin yuksek 8 biti
    bayt3-4: mesafe_q2 (little endian)
    aci_derece = ((bayt1>>1) | (bayt2<<7)) / 64
    mesafe_mm  = (bayt3 | (bayt4<<8)) / 4
"""

import time

try:
    import serial
except ImportError:
    serial = None

# ---------------------------------------------------------------- komutlar
BAYRAK = b"\xA5"
KOMUT_STOP = b"\x25"
KOMUT_RESET = b"\x40"
KOMUT_SCAN = b"\x20"
KOMUT_BILGI = b"\x50"
KOMUT_SAGLIK = b"\x52"

YANIT_BASI = b"\xA5\x5A"

SAGLIK_METIN = {0: "iyi", 1: "uyari", 2: "hata"}

# USB adaptorunde motoru/enable'i hangi el sikisma hattinin surdugu karta gore
# degisir. A serisi adaptorde DTR=False motoru CALISTIRIR; C1 ile gelen yeni
# adaptorlerde bu hat bagli olmayabilir ya da ters olabilir. Bu yuzden tek bir
# kombinasyona guvenmiyoruz -- sirayla deneyip veri geleni seciyoruz.
MOTOR_HATTI_DENEMELERI = [
    (False, True),      # A serisi adaptorun bilinen "motor calis" hali
    (False, False),
    (True, True),
    (True, False),
]

# DTR/RTS degistirmek bazi USB adaptorlerinde LiDAR'i resetler; bu kadar bekle.
HAT_OTURMA_S = 0.6


class LidarHatasi(Exception):
    pass


class VeriYokHatasi(LidarHatasi):
    """SCAN kabul edildi ama olcum gelmedi -- neredeyse her zaman motor/besleme."""


def olcum_coz(bes_bayt):
    """5 baytlik olcumu (yeni_tur, kalite, aci_derece, mesafe_mm) yapar.

    Gecersizse LidarHatasi firlatir -- cagiran taraf 1 bayt kaydirip
    yeniden hizalanir.
    """
    b0, b1, b2, b3, b4 = bes_bayt
    yeni = bool(b0 & 0b1)
    yeni_degil = bool((b0 >> 1) & 0b1)
    if yeni == yeni_degil:
        raise LidarHatasi("yeni tur bayragi tutarsiz")
    if (b1 & 0b1) != 1:
        raise LidarHatasi("kontrol biti 1 degil")
    kalite = b0 >> 2
    aci = ((b1 >> 1) | (b2 << 7)) / 64.0
    mesafe = (b3 | (b4 << 8)) / 4.0
    return yeni, kalite, aci, mesafe


class RPLidarC1:
    def __init__(self, port="/dev/ttyUSB0", baud=460800, zaman_asimi=1.0):
        if serial is None:
            raise RuntimeError("pyserial kurulu degil:  pip install pyserial")
        self.port_adi = port
        self.baud = baud
        self.ser = serial.Serial(port, baud, timeout=zaman_asimi,
                                 parity=serial.PARITY_NONE,
                                 stopbits=serial.STOPBITS_ONE)
        # A1'de DTR=False motoru calistirir. C1 adaptorunde bagli olmayabilir;
        # veri gelmezse tarama_baslat() diger kombinasyonlari da dener.
        self.motor_hatti = (False, True)
        self._hat_ayarla(*self.motor_hatti)
        self._tarama_acik = False
        self._on_tampon = bytearray()
        time.sleep(0.1)
        self.ser.reset_input_buffer()

    # -------------------------------------------------------------- dusuk seviye
    def _komut(self, kod):
        self.ser.write(BAYRAK + kod)

    def _hat_ayarla(self, dtr, rts):
        """DTR/RTS el sikisma hatlarini surer. Bazi suruculer destelemez -- yut."""
        degisti = False
        for ad, deger in (("dtr", dtr), ("rts", rts)):
            try:
                if getattr(self.ser, ad) != deger:
                    setattr(self.ser, ad, deger)
                    degisti = True
            except Exception:
                pass
        if degisti:
            time.sleep(HAT_OTURMA_S)

    def _veri_bekle(self, sure=3.0, yeter=20):
        """En fazla `sure` saniye ham bayt toplar. `yeter` bayt gelince erken doner.

        Bloklayan read() yerine in_waiting ile bekliyoruz ki sure kesin olsun.
        """
        bitis = time.monotonic() + sure
        toplam = bytearray()
        while time.monotonic() < bitis:
            n = self.ser.in_waiting
            if n:
                toplam.extend(self.ser.read(n))
                if len(toplam) >= yeter:
                    break
            else:
                time.sleep(0.02)
        return bytes(toplam)

    def _temiz_baslat(self):
        """STOP gonder, cihazin sakinlesmesini bekle, tamponu bosalt."""
        try:
            self._komut(KOMUT_STOP)
        except Exception:
            pass
        self._tarama_acik = False
        time.sleep(0.1)
        try:
            self.ser.reset_input_buffer()
        except Exception:
            pass

    def _tanimlayici_oku(self):
        """7 baytlik yanit tanimlayicisi. (uzunluk, mod, tip) doner."""
        d = self.ser.read(7)
        if len(d) != 7:
            raise LidarHatasi(
                f"tanimlayici okunamadi ({len(d)} bayt geldi). "
                f"Baud hizi dogru mu? C1 icin 460800 olmali.")
        if d[0:2] != YANIT_BASI:
            raise LidarHatasi(f"gecersiz yanit basligi: {d[0:2].hex()}")
        uzunluk = d[2] | (d[3] << 8) | (d[4] << 16) | ((d[5] & 0x3F) << 24)
        mod = d[5] >> 6
        return uzunluk, mod, d[6]

    # ------------------------------------------------------------------ bilgi
    def bilgi(self):
        self.ser.reset_input_buffer()
        self._komut(KOMUT_BILGI)
        uzunluk, _, tip = self._tanimlayici_oku()
        d = self.ser.read(uzunluk)
        if len(d) != uzunluk:
            raise LidarHatasi("bilgi paketi eksik")
        return {
            "model": d[0],
            "yazilim": f"{d[2]}.{d[1]}",
            "donanim": d[3],
            "seri_no": d[4:20][::-1].hex().upper(),
        }

    def saglik(self):
        self.ser.reset_input_buffer()
        self._komut(KOMUT_SAGLIK)
        uzunluk, _, _ = self._tanimlayici_oku()
        d = self.ser.read(uzunluk)
        if len(d) != uzunluk:
            raise LidarHatasi("saglik paketi eksik")
        durum = d[0]
        hata_kodu = d[1] | (d[2] << 8)
        return {"durum": durum, "metin": SAGLIK_METIN.get(durum, "?"),
                "hata_kodu": hata_kodu}

    # ------------------------------------------------------------------ tarama
    def _scan_dene(self, bekleme):
        """Bir kez SCAN gonderir, tanimlayiciyi okur, GERCEKTEN bayt geldigini olcer.

        Doner: gelen ham baytlar (bos ise veri akmiyor demektir).
        """
        self._temiz_baslat()
        self._komut(KOMUT_SCAN)
        uzunluk, mod, tip = self._tanimlayici_oku()
        if uzunluk != 5:
            raise LidarHatasi(f"beklenmeyen olcum boyu: {uzunluk}")
        return self._veri_bekle(bekleme)

    def tarama_baslat(self, bekleme=3.0, motor_dene=True):
        """SCAN baslatir ve olcumlerin GERCEKTEN aktigini dogrular.

        Eski surum sadece tanimlayiciya bakiyordu: cihaz "tamam, 5 baytlik
        olcumler gonderecegim" der, motor donmedigi icin tek bayt bile
        gondermez, hata ancak ilk okumada ve yanlis isimle ("zaman asimi")
        patlardi. Artik burada yakaliyoruz ve motor hatlarini da deniyoruz.
        """
        self._on_tampon = bytearray()
        denemeler = [tuple(self.motor_hatti)]
        if motor_dene:
            for k in MOTOR_HATTI_DENEMELERI:
                if k not in denemeler:
                    denemeler.append(k)

        for dtr, rts in denemeler:
            try:
                # Ilk denemede de uygula: aksi halde port acilirken kalan hat
                # durumu ile calisip yanlis kombinasyonu "calisan" diye kaydederiz.
                self._hat_ayarla(dtr, rts)
                ham = self._scan_dene(bekleme)
            except LidarHatasi:
                ham = b""
            if ham:
                self._on_tampon = bytearray(ham)
                self.motor_hatti = (dtr, rts)
                self._tarama_acik = True
                return
            self._temiz_baslat()

        # Hicbir kombinasyonda tek bayt gelmedi -> yazilim sorunu degil.
        self._hat_ayarla(*MOTOR_HATTI_DENEMELERI[0])
        raise VeriYokHatasi(
            "LiDAR komutu kabul ediyor ama OLCUM GONDERMIYOR.\n"
            "  Cihaz konusuyor (model/saglik okundu), demek ki port ve baud DOGRU.\n"
            "  Olcum gelmemesinin tek sebebi neredeyse her zaman MOTOR DONMUYOR:\n"
            "    1. LiDAR'in kafasi eline yaklastirinca donuyor mu? Ses geliyor mu?\n"
            "       Donmuyorsa USB yeterli akim vermiyor.\n"
            "    2. BASKA BIR USB PORTA TAK. Masaustunde ARKA paneldeki portlar,\n"
            "       dizustunde sarj takiliyken denenmeli. USB hub kullanma.\n"
            "    3. Kablo: veri kablosu oldugundan emin ol (bazi kablolar sadece sarj).\n"
            "    4. Adaptorde ayri 5V girisi varsa oradan besle.\n"
            "  Detayli test icin:  python tanila.py")

    def olcumler(self, max_kotu=1000, sessizlik=2.5):
        """Sonsuz olcum ureteci: (yeni_tur, kalite, aci, mesafe).

        Bozuk bayt gelirse 1 bayt kaydirip yeniden hizalanir -- gercek
        kullanimda seri hattinda tek bayt kaymasi olur ve sabit boyutlu
        okuma yapan kod bir daha ASLA duzelemez.

        sessizlik: bu kadar saniye HIC bayt gelmezse hata verir. Tek bir bos
        read()'te patlamiyoruz; motor yavaslamasi/USB gecikmesi normaldir.
        """
        if not self._tarama_acik:
            self.tarama_baslat()
        tampon = bytearray(self._on_tampon)
        self._on_tampon = bytearray()
        kotu = 0
        son_veri = time.monotonic()
        while True:
            gerek = 5 - len(tampon)
            if gerek > 0:
                yeni = self.ser.read(max(gerek, self.ser.in_waiting or gerek))
                if yeni:
                    tampon.extend(yeni)
                    son_veri = time.monotonic()
                elif time.monotonic() - son_veri > sessizlik:
                    raise VeriYokHatasi(
                        "veri kesildi -- LiDAR sustu.\n"
                        "  Kafa donmeyi birakti (besleme dusuk) ya da USB kablosu oynadi.\n"
                        "  Baska bir USB porta tak, sonra tekrar dene.")
                else:
                    continue
            while len(tampon) >= 5:
                try:
                    sonuc = olcum_coz(tampon[:5])
                except LidarHatasi:
                    del tampon[0]            # 1 bayt kaydir, yeniden dene
                    kotu += 1
                    if kotu > max_kotu:
                        raise LidarHatasi("surekli bozuk veri -- baud hizi yanlis olabilir")
                    continue
                del tampon[:5]
                kotu = 0
                yield sonuc

    def taramalar(self, min_nokta=90):
        """Tam turlari uretir: [(aci, mesafe, kalite), ...]

        min_nokta: bundan az noktali turlar atlanir (baslangicta yarim tur gelir).
        """
        tur = []
        for yeni, kalite, aci, mesafe in self.olcumler():
            if yeni and tur:
                if len(tur) >= min_nokta:
                    yield tur
                tur = []
            if mesafe > 0:                   # 0 = olcum yok (cok yakin/uzak/siyah)
                tur.append((aci, mesafe, kalite))

    # ------------------------------------------------------------------ kapat
    def durdur(self):
        self._komut(KOMUT_STOP)
        self._tarama_acik = False
        self._on_tampon = bytearray()
        time.sleep(0.01)
        self.ser.reset_input_buffer()

    def sifirla(self):
        self._komut(KOMUT_RESET)
        time.sleep(0.5)
        self.ser.reset_input_buffer()

    def kapat(self):
        try:
            self.durdur()
        except Exception:
            pass
        if self.ser and self.ser.is_open:
            self.ser.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.kapat()


def port_bul():
    """Bagli ilk USB seri portu bulur (Linux + Windows).

    glob("COM*") Windows'ta CALISMAZ -- COM portlari dosya sistemi girdisi
    degildir. pyserial'in port listeleyicisi kullanilir.
    """
    try:
        from serial.tools import list_ports
        adaylar = list(list_ports.comports())
        # USB-seri kopruleri once (CP210x / CH340 / FTDI / Silicon Labs)
        anahtar = ("cp210", "ch340", "ch910", "ftdi", "silicon", "usb")
        adaylar.sort(key=lambda p: 0 if any(
            a in (str(p.description) + str(p.manufacturer)).lower()
            for a in anahtar) else 1)
        for p in adaylar:
            return p.device
    except Exception:
        pass
    import glob
    for kalip in ("/dev/ttyUSB*", "/dev/ttyACM*"):
        b = sorted(glob.glob(kalip))
        if b:
            return b[0]
    return None


def portlari_listele():
    """Bagli tum seri portlari yazdirir -- hangisi oldugunu bulmak icin."""
    try:
        from serial.tools import list_ports
        p = list(list_ports.comports())
        if not p:
            print("  (hic seri port yok)")
        for x in p:
            print(f"  {x.device:20s} {x.description}")
        return [x.device for x in p]
    except Exception as e:
        print(f"  liste alinamadi: {e}")
        return []
