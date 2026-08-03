# -*- coding: utf-8 -*-
"""JK (JiKong) BMS surucusu -- BLE veya seri port, harici bagimlilik yok.

ONEMLI -- yaygin bir yanlis anlama:
    Telefondaki JK BMS uygulamasindan veri "cekilmez". O uygulama da senin
    gibi BMS'e baglanan bir istemcidir; arada paylasilan bir sunucu yoktur.
    Dogru yol: BMS'e DOGRUDAN baglanip ayni verileri okumak. Bu dosya onu yapar.

PROTOKOL (yazilim surumu >= 6.0 olan JK BMS'ler)
    Istek  (20 bayt):  AA 55 90 EB <adres> <uzunluk> <deger:4> ...00... <CRC>
    Yanit (300 bayt):  55 AA EB 90 <tip> ... <CRC>
    CRC   : tum baytlarin toplaminin dusuk 8 biti (checksum)
    Tipler: 0x01 ayarlar, 0x02 HUCRE BILGISI, 0x03 cihaz bilgisi, 0x05 kayit

    BLE  : servis 0xFFE0, karakteristik 0xFFE1 (bildirimle 20'ser bayt gelir,
           300 bayta ulasana kadar birlestirilir)
    Seri : 115200 baud TTL (RS485 soketi aslinda 3.3 V TTL'dir)

CERCEVE SURUMU
    "24S" -> eski donanim, 24 hucreye kadar
    "32S" -> donanim surumu 11.0+ , 32 hucreye kadar (alanlar kaymistir)
    Yanlis surum secilirse gerilim/SOC sacma cikar. surum_tahmin_et() bunu
    otomatik bulur.

Kaynak: protokol alan konumlari syssi/esphome-jk-bms projesinden dogrulanmis
ve gercek cihaz cerceveleriyle test edilmistir (bkz. test_jk_bms.py).
"""

import struct
import threading
import time

BASLIK_YANIT = b"\x55\xAA\xEB\x90"
BASLIK_ISTEK = b"\xAA\x55\x90\xEB"

KOMUT_CIHAZ_BILGISI = 0x97
KOMUT_HUCRE_BILGISI = 0x96

CERCEVE_BOYU = 300

TIP_AYARLAR = 0x01
TIP_HUCRE = 0x02
TIP_CIHAZ = 0x03
TIP_KAYIT = 0x05

BLE_SERVIS = "0000ffe0-0000-1000-8000-00805f9b34fb"
BLE_KARAKTERISTIK = "0000ffe1-0000-1000-8000-00805f9b34fb"


class BmsHatasi(Exception):
    pass


# ---------------------------------------------------------------- yardimcilar
def crc(veri):
    """JK BMS saglama: baytlarin toplaminin dusuk 8 biti."""
    return sum(veri) & 0xFF


def komut_cercevesi(adres, deger=0, uzunluk=0):
    """20 baytlik istek cercevesi uretir."""
    c = bytearray(20)
    c[0:4] = BASLIK_ISTEK
    c[4] = adres
    c[5] = uzunluk
    c[6:10] = struct.pack("<I", deger & 0xFFFFFFFF)
    c[19] = crc(c[:19])
    return bytes(c)


def _u16(d, i):
    return d[i] | (d[i + 1] << 8)


def _i16(d, i):
    v = _u16(d, i)
    return v - 0x10000 if v & 0x8000 else v


def _u32(d, i):
    return d[i] | (d[i + 1] << 8) | (d[i + 2] << 16) | (d[i + 3] << 24)


def _i32(d, i):
    v = _u32(d, i)
    return v - 0x100000000 if v & 0x80000000 else v


def _sure_metni(saniye):
    g, kalan = divmod(int(saniye), 86400)
    s, kalan = divmod(kalan, 3600)
    d = kalan // 60
    return f"{g}g {s}sa {d}dk"


# ------------------------------------------------------------ cerceve toplama
class CerceveToplayici:
    """BLE bildirimleri 20'ser bayt gelir; 300 baytlik cerceveyi burada kurariz.

    Onbellek her onek (55 AA EB 90) gorulunde sifirlanir -- boylece yarim kalmis
    bir cerceve sonrakini bozmaz. CRC her zaman 300. baytta olur; cerceve daha
    uzun gelse bile (320 bayt) fazlasi yok sayilir.
    """

    def __init__(self):
        self.tampon = bytearray()
        self.bozuk_crc = 0

    def besle(self, parca):
        """Gelen baytlari ekler; tamamlanan her cerceveyi listeler."""
        cerceveler = []
        if parca[:4] == BASLIK_YANIT:
            self.tampon.clear()
        self.tampon.extend(parca)
        while len(self.tampon) >= CERCEVE_BOYU:
            ham = bytes(self.tampon[:CERCEVE_BOYU])
            del self.tampon[:CERCEVE_BOYU]
            if ham[:4] != BASLIK_YANIT:
                continue
            if crc(ham[:CERCEVE_BOYU - 1]) != ham[CERCEVE_BOYU - 1]:
                self.bozuk_crc += 1
                continue
            cerceveler.append(ham)
        return cerceveler


def surum_tahmin_et(veri):
    """Cerceveden '24S' mi '32S' mi oldugunu bulur.

    Ayirt edici olcut: toplam paket gerilimi. Yanlis surumle okunursa deger
    fiziksel olarak imkansiz cikar (0 V ya da yuzlerce volt). Hucre
    gerilimlerinin toplamiyla karsilastirip tutarli olani seciyoruz.
    """
    en_iyi, en_iyi_fark = "24S", None
    for surum in ("24S", "32S"):
        try:
            d = hucre_bilgisi_coz(veri, surum)
        except Exception:
            continue
        toplam_hucre = sum(v for v in d["hucre_gerilimleri"] if v > 0)
        if toplam_hucre <= 0:
            continue
        fark = abs(d["toplam_gerilim_v"] - toplam_hucre)
        if not (0 <= d["soc_yuzde"] <= 100):
            fark += 1000.0
        if en_iyi_fark is None or fark < en_iyi_fark:
            en_iyi, en_iyi_fark = surum, fark
    return en_iyi


# ------------------------------------------------------------------- cozucu
def hucre_bilgisi_coz(veri, surum="32S"):
    """0x02 (hucre bilgisi) cercevesini sozluge cevirir.

    Alan konumlari: ofs = 0 (24S) / 16 (32S) hucre direnci ve maske bolumunde;
    ondan sonraki tum alanlarda ofs iki katina cikar (0 / 32).
    """
    if len(veri) < CERCEVE_BOYU:
        raise BmsHatasi(f"cerceve kisa: {len(veri)} bayt")
    if veri[:4] != BASLIK_YANIT:
        raise BmsHatasi("gecersiz cerceve basligi")
    if veri[4] != TIP_HUCRE:
        raise BmsHatasi(f"bu bir hucre bilgisi cercevesi degil (tip 0x{veri[4]:02X})")

    ofs = 16 if surum == "32S" else 0
    hucre_sayisi = 24 + ofs // 2
    o = ofs * 2                                   # ikinci bolumun kaymasi

    gerilimler = [_u16(veri, 6 + 2 * i) * 0.001 for i in range(hucre_sayisi)]
    dirençler = [_u16(veri, 64 + ofs + 2 * i) * 0.001 for i in range(hucre_sayisi)]

    dolu = [(i + 1, v) for i, v in enumerate(gerilimler) if v > 0]
    if dolu:
        min_no, min_v = min(dolu, key=lambda t: t[1])
        max_no, max_v = max(dolu, key=lambda t: t[1])
        ortalama = sum(v for _, v in dolu) / len(dolu)
    else:
        min_no = max_no = 0
        min_v = max_v = ortalama = 0.0

    toplam_v = _u32(veri, 118 + o) * 0.001
    akim = _i32(veri, 126 + o) * 0.001             # + sarj, - desarj
    guc = toplam_v * akim

    d = {
        "hucre_sayisi": len(dolu),
        "hucre_gerilimleri": gerilimler,
        "hucre_dirençleri": dirençler,
        "etkin_hucre_maskesi": _u32(veri, 54 + ofs),
        "min_hucre_v": round(min_v, 3),
        "max_hucre_v": round(max_v, 3),
        "min_hucre_no": min_no,
        "max_hucre_no": max_no,
        "delta_hucre_v": round(max_v - min_v, 3),
        "ortalama_hucre_v": round(ortalama, 3),

        "toplam_gerilim_v": round(toplam_v, 3),
        "akim_a": round(akim, 3),
        "guc_w": round(guc, 1),
        "sarj_gucu_w": round(max(0.0, guc), 1),
        "desarj_gucu_w": round(abs(min(0.0, guc)), 1),

        "sicaklik_1_c": _i16(veri, 130 + o) * 0.1,
        "sicaklik_2_c": _i16(veri, 132 + o) * 0.1,
        "denge_akimi_a": round(_i16(veri, 138 + o) * 0.001, 3),
        "dengeleme": veri[140 + o] != 0x00,

        "soc_yuzde": veri[141 + o],
        "kalan_kapasite_ah": round(_u32(veri, 142 + o) * 0.001, 3),
        "tam_kapasite_ah": round(_u32(veri, 146 + o) * 0.001, 3),
        "dongu_sayisi": _u32(veri, 150 + o),
        "toplam_dongu_kapasitesi_ah": round(_u32(veri, 154 + o) * 0.001, 3),
        "soh_yuzde": veri[158 + o],

        "toplam_calisma_s": _u32(veri, 162 + o),
        "sarj_mosfet_acik": bool(veri[166 + o]),
        "desarj_mosfet_acik": bool(veri[167 + o]),
        "on_sarj_acik": bool(veri[168 + o]),
        "isitma_acik": bool(veri[183 + o]),
        "sarj_fisi_takili": bool(veri[213 + o]),
        "cerceve_surumu": surum,
    }
    d["calisma_suresi"] = _sure_metni(d["toplam_calisma_s"])

    # MOSFET sicakligi ve hata maskesi surume gore farkli yerde
    if surum == "32S":
        d["mosfet_sicaklik_c"] = _i16(veri, 112 + o) * 0.1
        d["hata_maskesi"] = _u32(veri, 134 + o)
        d["sicaklik_3_c"] = _i16(veri, 222 + o) * 0.1
        d["sicaklik_4_c"] = _i16(veri, 224 + o) * 0.1
        d["sicaklik_5_c"] = _i16(veri, 226 + o) * 0.1
    else:
        d["mosfet_sicaklik_c"] = _i16(veri, 134 + o) * 0.1
        d["hata_maskesi"] = _u16(veri, 136 + o)

    d["hatalar"] = hata_metinleri(d["hata_maskesi"])
    d["durum"] = ("SARJ" if akim > 0.05 else
                  "DESARJ" if akim < -0.05 else "BEKLEME")
    # Kalan sure tahmini: mevcut akimla ne kadar dayanir / ne kadarda dolar
    if akim < -0.05:
        d["kalan_sure_sa"] = round(d["kalan_kapasite_ah"] / abs(akim), 2)
    elif akim > 0.05:
        eksik = max(0.0, d["tam_kapasite_ah"] - d["kalan_kapasite_ah"])
        d["kalan_sure_sa"] = round(eksik / akim, 2)
    else:
        d["kalan_sure_sa"] = None
    return d


HATA_BITLERI = [
    "Hucre asiri gerilim", "Hucre dusuk gerilim", "Paket asiri gerilim",
    "Paket dusuk gerilim", "Sarj asiri sicaklik", "Sarj dusuk sicaklik",
    "Desarj asiri sicaklik", "Desarj dusuk sicaklik", "Sarj asiri akim",
    "Desarj asiri akim", "Hucre farki cok buyuk", "MOSFET asiri sicaklik",
    "Hucre sayisi hatali", "Akim sensoru hatasi", "Kisa devre",
    "Ic sicaklik hatasi",
]


def hata_metinleri(maske):
    return [ad for i, ad in enumerate(HATA_BITLERI) if maske & (1 << i)]


def cihaz_bilgisi_coz(veri):
    """0x03 (cihaz bilgisi) cercevesi: model, surum, seri no."""
    if len(veri) < CERCEVE_BOYU or veri[4] != TIP_CIHAZ:
        raise BmsHatasi("cihaz bilgisi cercevesi degil")

    def metin(bas, boy):
        return veri[bas:bas + boy].split(b"\x00")[0].decode("ascii", "ignore").strip()

    return {
        "model": metin(6, 16),
        "donanim_surumu": metin(22, 8),
        "yazilim_surumu": metin(30, 8),
        "calisma_suresi_s": _u32(veri, 38),
        "guc_cevrim_sayisi": _u32(veri, 42),
        "cihaz_adi": metin(46, 16),
        "cihaz_parolasi": metin(62, 16),
        "uretim_tarihi": metin(78, 8),
        "seri_no": metin(86, 11),
    }


# ============================================================================
#  Okuyucular -- hepsi ayni arayuz: .durum() son olcumu doner
# ============================================================================
class _TemelOkuyucu:
    def __init__(self, surum="oto", bayat_s=10.0):
        self.surum = surum
        self.bayat_s = bayat_s
        self._son = None
        self._zaman = 0.0
        self._cihaz = None
        self._kilit = threading.Lock()
        self._calis = True
        self.hata = None
        self.cerceve_sayisi = 0

    def _isle(self, ham):
        if ham[4] == TIP_CIHAZ:
            try:
                with self._kilit:
                    self._cihaz = cihaz_bilgisi_coz(ham)
            except BmsHatasi:
                pass
            return
        if ham[4] != TIP_HUCRE:
            return
        if self.surum == "oto":
            self.surum = surum_tahmin_et(ham)
        d = hucre_bilgisi_coz(ham, self.surum)
        with self._kilit:
            self._son = d
            self._zaman = time.monotonic()
            self.cerceve_sayisi += 1

    def durum(self):
        """Son olcum + tazelik bilgisi. Veri yoksa None doner."""
        with self._kilit:
            d = dict(self._son) if self._son else None
            cihaz = dict(self._cihaz) if self._cihaz else None
            yas = time.monotonic() - self._zaman if self._zaman else None
        if d is None:
            return {"bagli": False, "hata": self.hata,
                    "cihaz": cihaz, "veri": None}
        d.pop("hucre_dirençleri", None)
        return {
            "bagli": yas is not None and yas <= self.bayat_s,
            "veri_yasi_s": round(yas, 1) if yas is not None else None,
            "hata": self.hata,
            "cihaz": cihaz,
            "cerceve_sayisi": self.cerceve_sayisi,
            "veri": d,
        }

    def kapat(self):
        self._calis = False


class SeriOkuyucu(_TemelOkuyucu):
    """RS485/TTL soketinden okur. Robotta BLE'den daha guvenilirdir:
    motor gurultusu ve hareket BLE baglantisini dusurur."""

    def __init__(self, port, baud=115200, **kw):
        super().__init__(**kw)
        import serial
        self.ser = serial.Serial(port, baud, timeout=1.0)
        self._is = threading.Thread(target=self._dongu, daemon=True)
        self._is.start()

    def _dongu(self):
        toplayici = CerceveToplayici()
        son_istek = 0.0
        while self._calis:
            try:
                if time.monotonic() - son_istek > 1.0:
                    son_istek = time.monotonic()
                    if self._cihaz is None:
                        self.ser.write(komut_cercevesi(KOMUT_CIHAZ_BILGISI))
                        time.sleep(0.2)
                    self.ser.write(komut_cercevesi(KOMUT_HUCRE_BILGISI))
                gelen = self.ser.read(max(1, self.ser.in_waiting))
                if gelen:
                    for ham in toplayici.besle(gelen):
                        self._isle(ham)
                self.hata = None
            except Exception as e:
                self.hata = str(e)
                time.sleep(1.0)

    def kapat(self):
        super().kapat()
        try:
            self.ser.close()
        except Exception:
            pass


def ble_tara(sure=8.0):
    """Yakindaki BLE cihazlarini listeler; JK BMS'leri basa alir.

    MAC adresi zaten BMS'in ETIKETINDE yazar (MAC:C8:47:80:...). Bu islev
    etiket okunamadiginda ya da dogrulamak icindir.
    """
    import asyncio
    try:
        from bleak import BleakScanner
    except ImportError:
        raise BmsHatasi("bleak kurulu degil:  pip install bleak")

    cihazlar = asyncio.run(BleakScanner.discover(timeout=sure))
    bulunan = [(d.address, d.name or "?") for d in cihazlar]
    bulunan.sort(key=lambda t: 0 if (t[1] or "").upper().startswith("JK") else 1)
    return bulunan


class BleOkuyucu(_TemelOkuyucu):
    """Telefon uygulamasinin kullandigi yol. `pip install bleak` gerekir.

    ONEMLI: JK BMS ayni anda TEK BLE baglantisi kabul eder. Telefondaki
    uygulama bagliyken buradan baglanamazsin -- once uygulamayi kapat
    (arka planda birakmak da yetmez, baglantiyi dusur).
    """

    def __init__(self, adres, **kw):
        super().__init__(**kw)
        self.adres = adres
        self._is = threading.Thread(target=self._dongu, daemon=True)
        self._is.start()

    def _dongu(self):
        import asyncio
        try:
            from bleak import BleakClient
        except ImportError:
            self.hata = "bleak kurulu degil:  pip install bleak"
            return

        toplayici = CerceveToplayici()

        async def calis():
            while self._calis:
                try:
                    async with BleakClient(self.adres) as istemci:
                        def bildirim(_, veri):
                            for ham in toplayici.besle(bytes(veri)):
                                try:
                                    self._isle(ham)
                                except BmsHatasi:
                                    pass

                        await istemci.start_notify(BLE_KARAKTERISTIK, bildirim)
                        # El sikisma: once cihaz bilgisi, sonra hucre bilgisi
                        await istemci.write_gatt_char(
                            BLE_KARAKTERISTIK, komut_cercevesi(KOMUT_CIHAZ_BILGISI),
                            response=False)
                        await asyncio.sleep(0.5)
                        self.hata = None
                        while self._calis and istemci.is_connected:
                            await istemci.write_gatt_char(
                                BLE_KARAKTERISTIK,
                                komut_cercevesi(KOMUT_HUCRE_BILGISI), response=False)
                            await asyncio.sleep(1.0)
                except Exception as e:
                    self.hata = str(e)
                    await asyncio.sleep(2.0)

        asyncio.new_event_loop().run_until_complete(calis())


class SahteOkuyucu(_TemelOkuyucu):
    """Donanim YOKKEN web arayuzunu gelistirmek icin.

    Gercek cihazdan alinmis cerceveleri oynatir, uzerine yavas degisen bir
    SOC/akim benzetimi bindirir. Batarya elinde olmadan arayuzu bitirebilirsin.
    """

    def __init__(self, cerceveler=None, **kw):
        kw.setdefault("surum", "24S")
        super().__init__(**kw)
        self.cerceveler = cerceveler or [_ORNEK_CERCEVE]
        self._is = threading.Thread(target=self._dongu, daemon=True)
        self._is.start()

    def _dongu(self):
        i = 0
        t0 = time.monotonic()
        while self._calis:
            try:
                self._isle(self.cerceveler[i % len(self.cerceveler)])
                i += 1
                gecen = time.monotonic() - t0
                with self._kilit:
                    if self._son:
                        # 60 sn'lik sarj/desarj dongusu benzetimi
                        faz = (gecen % 60.0) / 60.0
                        akim = 12.0 if faz < 0.5 else -18.0
                        soc = 40 + int(50 * faz)
                        v = self._son["toplam_gerilim_v"]
                        self._son.update(
                            akim_a=akim, soc_yuzde=soc,
                            guc_w=round(v * akim, 1),
                            sarj_gucu_w=round(max(0.0, v * akim), 1),
                            desarj_gucu_w=round(abs(min(0.0, v * akim)), 1),
                            durum="SARJ" if akim > 0 else "DESARJ",
                            sarj_fisi_takili=akim > 0,
                            kalan_kapasite_ah=round(
                                self._son["tam_kapasite_ah"] * soc / 100.0, 3))
                        self._son["kalan_sure_sa"] = round(
                            self._son["kalan_kapasite_ah"] / abs(akim), 2)
                    self._cihaz = {"model": "JK-BD6A24S10P (SAHTE)",
                                   "yazilim_surumu": "11.XW",
                                   "donanim_surumu": "11.0",
                                   "seri_no": "SAHTE-DEMO"}
            except Exception as e:
                self.hata = str(e)
            time.sleep(1.0)


# Gercek cihazdan alinmis 0x02 cercevesi (24S). test_jk_bms.py bunu dogrular.
_ORNEK_CERCEVE = bytes.fromhex(
    "55aaeb90028cff0c010d010dff0c010d010dff0c010d010d010d010dff0c010d010d010d010d"
    "00000000000000000000000000000000ffff0000000d000000009d0196018c01870184018401"
    "8301840185018101830186018201820183018501000000000000000000000000000000000000"
    "0000000003d000000000000000000000be00bf00d2000000000000548e0b0100683c01000000"
    "00003d04000064007904ca0310000101aa06000000000000000000000000070001000000d502"
    "00000000aed63b400000000058aafdff0000000100020000ece64f0000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000000000000cd")
