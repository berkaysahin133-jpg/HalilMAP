#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RoboVizyon - Cizgi Takip + QR Gorev Protokolu   (Raspberry Pi 5)
TEK DOSYA surum -- kalibrasyon gerektirmez, direkt calisir.

v3: Algilama cekirdegi yeniden yazildi. Onceki "esikle -> en buyuk kontur ->
centroid" yaklasimi yerine:

  1) YEREL ORTALAMA CIKARMA binarizasyon
     Sabit inRange(0,85) esigi salon isigi degisince cokuyordu. Artik her
     piksel KENDI KOMSULUGUYLA kiyaslaniyor: mutlak parlaklik onemsiz, sadece
     "cevresinden ne kadar koyu" onemli. Karanlik kose de, pencere alti da
     ayni sekilde calisir.

  2) KAYAN PENCERE takibi
     Tek centroid cizginin SEKLINI bilmez; golgeye/kavsaga atlar. Burada cizgi
     alttan yukari 8 pencereyle takip ediliyor, cikan nokta bulutuna dogru
     oturtuluyor. Boylece hem YANAL HATA hem YON ACISI elde ediliyor.

  3) EGRILIGE GORE OTOMATIK YAVASLAMA
     Viraj sertlestikce hiz kendiliginden duser -- sabit "duzeltme hizi" degil.

  4) SAGLAM PID
     Filtreli turev (dt jitter'i Kd ile buyumez) + kosullu integrasyon
     (windup yok, cizgi kaybinda sifirlanir).

  5) KOSE TESPITI: cizgi biter + yatay kosu olculur (2 kanit), N kare onay.

YON KONVANSIYONU: bench testinde araç TERS yonde donduğu icin YON = -1.
Tum hizlar notre gore ofset olarak yazili; YON tek basina hepsini cevirir.
"""

import time

import cv2
import numpy as np
from pyzbar.pyzbar import decode

# =============================================================================
# 1. SERİ PORT
# =============================================================================
try:
    arduino = serial_port = None
    import serial
    arduino = serial.Serial('/dev/ttyUSB0', 115200, timeout=0.05, write_timeout=0.05)
    print("[SİSTEM] Arduino bağlantısı başarılı.")
    time.sleep(2)
    arduino.reset_input_buffer()
    arduino.reset_output_buffer()
except Exception as e:
    print(f"[HATA] Seri port açılamadı: {e}")
    raise SystemExit(1)

_son_gonderim = 0.0
_son_paket = None


def motor_sur(sol_dac, sag_dac, zorla=False):
    """Arduino'ya <Sol,Sag> DAC paketi. 50 Hz sinirli (firmware watchdog 250 ms)."""
    global _son_gonderim, _son_paket
    paket = (int(np.clip(sol_dac, 0, 4095)), int(np.clip(sag_dac, 0, 4095)))
    simdi = time.monotonic()
    if not zorla and paket == _son_paket and (simdi - _son_gonderim) < 0.02:
        return
    _son_paket, _son_gonderim = paket, simdi
    try:
        arduino.write(f"<{paket[0]},{paket[1]}>\n".encode('utf-8'))
    except Exception as e:
        print(f"[HATA] Seri yazma: {e}")


def arduino_dinle():
    """Firmware heartbeat'ini yut, RX birikmesin."""
    try:
        if arduino.in_waiting:
            arduino.read(arduino.in_waiting)
    except Exception:
        pass


# =============================================================================
# 2. AYARLAR
# =============================================================================
NOTR = 2048

# --- YÖN --------------------------------------------------------------------
# Bench testi: motor_sur(ileri(500), ileri(500)) ile araç İLERİ gitmeli.
#   +1 -> DAC > 2048 ileri     |     -1 -> DAC < 2048 ileri
YON = -1        # <<< araç ters gittiği için çevrildi
# ----------------------------------------------------------------------------

# Nötre göre ofsetler (YON bunları otomatik doğru tarafa koyar)
OFS_SEYIR    = 500    # düz yolda seyir gücü
OFS_YAVAS    = 380    # köşe/QR yaklaşımı
OFS_MIN      = 240    # en düşük sürüş gücü
OFS_MAX      = 900    # PID'in çıkabileceği tavan
OFS_TERS     = 320    # iç tekerleğe izin verilen ters tork (fren etkisi)
OFS_PIVOT    = 700    # yerinde dönüş
OFS_ARAMA    = 380    # çizgi ararken yavaş tarama

# --- PID (hata birimi: normalize, -1.0 .. +1.0) ---
Kp        = 0.95
Ki        = 0.10
Kd        = 0.055
D_FILTRE  = 0.35      # türev alçak geçiren (0=kapalı, 1=çok ağır)
I_SINIR   = 0.30      # integral katkı tavanı
K_ACI     = 0.08      # yön açısı ağırlığı. SİMÜLASYONDA SÜPÜRÜLDÜ.
                      # Yüksek değer (0.4+) virajda 'hata + K_ACI*egim = 0'
                      # sahte dengesi yaratıp aracı çizgiye paralel ama
                      # yanında kilitliyor. 0.08 hem düz hem virajda en iyi,
                      # 400 ms sistem gecikmesinde bile salınım yapmıyor.
K_EGRI    = 0.0       # eğrilik ön-beslemesi KAPALI: K_ACI terimi virajın
                      # gerektirdiği direksiyonu zaten üretiyor, üstüne
                      # eklemek ÇİFT SAYIM olup aracı virajın içine kestiriyor.
YAVASLAMA = 0.70      # |direksiyon| başına hız kesme oranı

# --- Görüntü işleme ---
ISL_W, ISL_H     = 160, 120     # analiz çözünürlüğü
YEREL_PENCERE    = 25           # yerel ortalama penceresi (px, tek sayı)
KONTRAST_ESIGI   = 16           # yerel ortalamadan bu kadar koyu = çizgi
PENCERE_SAYISI   = 8            # kayan pencere adedi
PENCERE_YARI     = 26           # kayan pencere yarı genişliği (px)
PENCERE_MIN_PX   = 18           # bu sayının altında pencere "boş"
MAX_BOS_PENCERE  = 2
MIN_PENCERE      = 3            # fit için gereken en az dolu pencere
KOYU_ORAN_MIN    = 0.005
KOYU_ORAN_MAX    = 0.55

# --- Köşe (L-viraj) ---
ACI_REF_DERECE   = 30.0         # bu açı egim = 1.0 demek (normalizasyon)
KOSE_KOSU_PX     = 52           # köşeyi kanıtlayan yatay uzantı (px, 160 genişlikte)
KOSE_MAX_ARTIK   = 3.5          # çizgi bu kadar düz değilse köşe SAYILMAZ (yay koruması)
KOSE_ONAY_KARE   = 3            # bu kadar üst üste görülmeden manevra yok
# Köşeye yaklaşma: SABİT SÜRE DEĞİL, kapalı çevrim.
# Dikey çizginin bittiği satır (bitis_y) kadraj tabanına inince köşe artık
# kameranın kör bölgesindedir; oradan sonra yalnızca kör bölge kadar
# ilerlenir. Sabit süre kullanmak, köşenin ne kadar uzakta görüldüğüne göre
# aracı ya erken ya geç durduruyordu.
KOSE_TABAN_ORANI = 0.72         # bitis_y bu orana inince köşe kör bölgede
KOR_BOLGE_SURESI = 0.80         # kör bölgeyi katetme süresi (YAVAS hızda)
VIRAJ_MAX_SURE   = 9.0          # yalnızca güvenlik ağı. Asıl bitirici yukarıdaki
                                # bitis_y şartıdır; bu süre kısa olursa araç
                                # köşeye VARMADAN durur ve pivot boş zemine bakar.
PIVOT_CIKIS_HATA = 0.16         # pivot çıkışı: |yanal| bu değerin altına insin
PIVOT_CIKIS_ACI  = 0.22         # pivot çıkışı: |eğim| bu değerin altına insin
# 90 derecelik yerinde dönüşün SÜRESİ. Araçta bir kez ölç:
#   motor_sur(*PIVOT_SAG) ile döndür, 90 dereceyi kaç saniyede aldığını say.
# Pivot çıkışı SADECE hizalanmaya bırakılamaz: araç yanlışlıkla 180 dönerse
# GELDİĞİ çizgiyi görüp "hizalandım" der ve geri geri o çizgiyi takip eder.
# (Testte tam bu oldu: 1.93 sn'de 175 derece dönüp geri döndü.)
PIVOT_90_SURE    = 0.95
PIVOT_MIN_SURE   = 0.55 * PIVOT_90_SURE
PIVOT_MAX_SURE   = 1.80 * PIVOT_90_SURE

# --- QR ---
QR_ICERIK        = "11"
QR_TARAMA_ARASI  = 2            # her N karede bir tara
QR_ONAY_KARE     = 2            # bu kadar üst üste aynı içerik okunmadan manevra yok
QR_SOGUMA        = 4.0
# (QR pivotu da PIVOT_MAX_SURE ile sınırlanır -- ayrı süre tutmuyoruz)

# --- Güvenlik ---
CIZGI_KAYIP_SURE = 0.9
ARAMA_SURE       = 2.0

GOSTER = True                   # SSH'tan çalıştırıyorsan False yap


def ileri(ofset):
    return int(np.clip(NOTR + YON * ofset, 0, 4095))


def geri(ofset):
    return int(np.clip(NOTR - YON * ofset, 0, 4095))


SEYIR = ileri(OFS_SEYIR)
YAVAS = ileri(OFS_YAVAS)
PIVOT_SAG = (ileri(OFS_PIVOT), geri(OFS_PIVOT))    # sol ileri, sağ geri
PIVOT_SOL = (geri(OFS_PIVOT), ileri(OFS_PIVOT))
ARAMA_SAG = (ileri(OFS_ARAMA), geri(OFS_ARAMA))
ARAMA_SOL = (geri(OFS_ARAMA), ileri(OFS_ARAMA))


# =============================================================================
# 3. GÖRÜNTÜ İŞLEME
# =============================================================================
_kernel3 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
_kernel5 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))
_yerel_px = YEREL_PENCERE | 1


def cizgi_maskesi(frame_bgr):
    """Aydınlatmadan bağımsız binarizasyon: yerel ortalama çıkarma.

    Sabit eşik neden yetersiz: salon ışığı tek tip değil. Pencerenin altında
    zemin 190, köşede 90 olabilir; tek eşik ya köşede zemini "çizgi" sayar ya
    pencere altında çizgiyi kaçırır. Yerel ortalama çıkarma mutlak parlaklığı
    önemsizleştirir.
    """
    kucuk = cv2.resize(frame_bgr, (ISL_W, ISL_H), interpolation=cv2.INTER_AREA)
    gri = cv2.cvtColor(kucuk, cv2.COLOR_BGR2GRAY)
    yumusak = cv2.GaussianBlur(gri, (5, 5), 0)
    yerel = cv2.blur(yumusak, (_yerel_px, _yerel_px))

    fark = cv2.subtract(yerel, yumusak)          # çizgi çevresinden koyu
    _, maske = cv2.threshold(fark, KONTRAST_ESIGI, 255, cv2.THRESH_BINARY)
    maske = cv2.morphologyEx(maske, cv2.MORPH_CLOSE, _kernel5)
    maske = cv2.morphologyEx(maske, cv2.MORPH_OPEN, _kernel3)

    # Makullük: kare tamamen koyu (gölge/kapalı kamera) veya bomboşsa güvenme
    oran = float(np.count_nonzero(maske)) / maske.size
    if not (KOYU_ORAN_MIN <= oran <= KOYU_ORAN_MAX):
        return np.zeros_like(maske)
    return maske


class Olcum:
    __slots__ = ("gecerli", "guven", "hata", "egim", "kose_yonu", "kosu_px",
                 "noktalar", "bitis_y", "maske", "duzluk", "egrilik")

    def __init__(self):
        self.gecerli = False
        self.guven = 0.0
        self.hata = 0.0        # -1..+1  (+ ise çizgi sağda)
        self.egim = 0.0        # -1..+1  (+ ise çizgi sağa doğru gidiyor)
        self.kose_yonu = 0
        self.kosu_px = 0.0
        self.noktalar = []
        self.bitis_y = ISL_H
        self.duzluk = 99.0     # dogruya gore artik (px) -- kucukse cizgi DUZ
        self.egrilik = 0.0     # -1..+1  (+ = cizgi saga kivriliyor)
        self.maske = None


class Dedektor:
    """Kayan pencere ile çizgi takibi."""

    def __init__(self):
        self.pencere_h = max(4, ISL_H // PENCERE_SAYISI)
        self._son_taban = None
        self._kose_gecmis = []

    def sifirla(self):
        self._son_taban = None
        self._kose_gecmis.clear()

    def _taban_bul(self, maske):
        alt = maske[int(ISL_H * 0.78):, :]
        hist = alt.sum(axis=0).astype(np.float32)
        if hist.max() < 255 * 2:
            return None
        # Önceki kareyi biliyorsak yakınını tercih et: titremeyi keser,
        # yandaki paralel çizgiye/gölgeye atlamayı engeller.
        if self._son_taban is not None:
            w = np.exp(-0.5 * ((np.arange(ISL_W) - self._son_taban) / 26.0) ** 2)
            hist = hist * (0.35 + 0.65 * w)
        return int(np.argmax(hist))

    def _kayan_pencere(self, maske, taban):
        merkezler = []
        x = taban
        bos = 0
        for i in range(PENCERE_SAYISI):
            y1 = ISL_H - i * self.pencere_h
            y0 = max(0, y1 - self.pencere_h)
            if y0 >= y1:
                break
            xs = max(0, x - PENCERE_YARI)
            xe = min(ISL_W, x + PENCERE_YARI)
            pen = maske[y0:y1, xs:xe]
            if pen.size == 0:
                break
            nz = cv2.findNonZero(pen)
            if nz is not None:
                nz = np.asarray(nz).reshape(-1, 2)
            if nz is not None and len(nz) >= PENCERE_MIN_PX:
                yeni = int(nz[:, 0].mean()) + xs
                x = int(0.7 * yeni + 0.3 * x)
                merkezler.append((x, (y0 + y1) * 0.5, len(nz)))
                bos = 0
            else:
                bos += 1
                if bos >= MAX_BOS_PENCERE:
                    break
        return merkezler

    def _kose_analiz(self, maske, merkezler):
        """Çizgi takibi bittiği yerde yatay uzantı var mı? (köşenin 2. kanıtı)"""
        if not merkezler:
            return 0, 0.0
        sx, sy, _ = merkezler[-1]
        y0 = int(max(0, sy - 5))
        y1 = int(min(ISL_H, sy + 5))
        band = maske[y0:y1, :]
        if band.size == 0:
            return 0, 0.0
        sut = (band.max(axis=0) > 0).astype(np.uint8)
        x0 = int(np.clip(sx, 0, ISL_W - 1))
        if sut[x0] == 0:
            dolu = np.flatnonzero(sut)
            if dolu.size == 0:
                return 0, 0.0
            x0 = int(dolu[np.argmin(np.abs(dolu - x0))])
        sol = x0
        while sol > 0 and sut[sol - 1]:
            sol -= 1
        sag = x0
        while sag < ISL_W - 1 and sut[sag + 1]:
            sag += 1
        sol_u, sag_u = x0 - sol, sag - x0
        if sag_u >= KOSE_KOSU_PX and sag_u > sol_u * 1.5:
            return +1, float(sag_u)
        if sol_u >= KOSE_KOSU_PX and sol_u > sag_u * 1.5:
            return -1, float(sol_u)
        return 0, float(max(sol_u, sag_u))

    def isle(self, frame_bgr):
        o = Olcum()
        maske = cizgi_maskesi(frame_bgr)
        o.maske = maske

        taban = self._taban_bul(maske)
        if taban is None:
            self._kose_gecmis.clear()
            return o

        merkezler = self._kayan_pencere(maske, taban)
        if len(merkezler) < MIN_PENCERE:
            self._kose_gecmis.clear()
            return o

        self._son_taban = merkezler[0][0]
        o.noktalar = [(m[0], m[1]) for m in merkezler]
        o.bitis_y = merkezler[-1][1]

        X = np.array([m[0] for m in merkezler], float)
        Y = np.array([m[1] for m in merkezler], float)
        w = np.array([m[2] for m in merkezler], float)
        w = w / (w.max() + 1e-9)

        # x = a*y + b  (görüntüde y aşağı doğru artar; alt = araca yakın)
        try:
            egim_px, kesme = np.polyfit(Y, X, 1, w=w)
        except (np.linalg.LinAlgError, ValueError):
            return o

        y_alt = float(Y.max())                       # araca en yakın bant
        x_alt = egim_px * y_alt + kesme
        artik_px = float(np.sqrt(np.mean((egim_px * Y + kesme - X) ** 2)))

        o.gecerli = True
        o.hata = float(np.clip((x_alt - ISL_W / 2.0) / (ISL_W / 2.0), -1, 1))

        # Eğim: GERÇEK AÇIDAN normalize. Önceki "-egim_px * 4.0" ölçeklemesi
        # 14 dereceden dik her çizgiyi doyuma sokuyordu; bu da
        # "hata + K_ACI*egim = 0" SAHTE DENGESİ yaratıp aracı çizgiye
        # paralel ama 8 cm yanında kilitliyordu. Artık ACI_REF derece = 1.0.
        aci = float(np.arctan(-egim_px))                 # radyan, + = sağa
        o.egim = float(np.clip(aci / np.radians(ACI_REF_DERECE), -1, 1))
        o.duzluk = artik_px

        # --- EĞRİLİK: iki parçalı yön farkı ---
        # Neden gerekli: piksel uzayında P+açı kontrolü, virajda
        # "hata + K_ACI*egim = 0" dengesine oturur ve virajla KAVGA eder --
        # oysa virajda kalıcı bir direksiyon açısı GEREKLİDİR. Çizginin yakın
        # ve uzak yarısının yönleri arasındaki fark, bu gerekli direksiyonu
        # doğrudan verir (işareti yapısı gereği doğrudur).
        if len(merkezler) >= 4:
            orta = len(merkezler) // 2
            try:
                e_yakin = np.polyfit(Y[:orta + 1], X[:orta + 1], 1)[0]
                e_uzak = np.polyfit(Y[orta:], X[orta:], 1)[0]
                d_aci = float(np.arctan(-e_uzak) - np.arctan(-e_yakin))
                o.egrilik = float(np.clip(d_aci / np.radians(ACI_REF_DERECE), -1, 1))
            except (np.linalg.LinAlgError, ValueError):
                o.egrilik = 0.0

        kapsam = len(merkezler) / float(PENCERE_SAYISI)
        uyum = float(np.exp(-artik_px / 6.0))
        o.guven = float(np.clip(0.45 * kapsam + 0.55 * uyum, 0, 1))

        yon, kosu = self._kose_analiz(maske, merkezler)
        o.kosu_px = kosu
        # 3. KANIT: gerçek 90 köşede çizgi köşeye kadar DÜZDÜR, sonra aniden
        # yana kırılır. Yumuşak yayda ise noktalar zaten eğridir. Doğruya göre
        # artık büyükse (= yay) köşe kabul etmiyoruz -- yayda sahte 90 dönüş
        # yapmak görevi bitirir.
        if artik_px > KOSE_MAX_ARTIK:
            yon = 0
        self._kose_gecmis.append(yon)
        if len(self._kose_gecmis) > KOSE_ONAY_KARE:
            self._kose_gecmis.pop(0)
        if (len(self._kose_gecmis) >= KOSE_ONAY_KARE and yon != 0
                and all(g == yon for g in self._kose_gecmis)):
            o.kose_yonu = yon
        return o


# =============================================================================
# 4. PID
# =============================================================================
class PID:
    def __init__(self):
        self.sifirla()

    def sifirla(self):
        self.integral = 0.0
        self.onceki = 0.0
        self.turev_f = 0.0

    def hesapla(self, hata, dt):
        p = Kp * hata
        ham = (hata - self.onceki) / dt if dt > 1e-4 else 0.0
        self.turev_f += D_FILTRE * (ham - self.turev_f)      # filtreli türev
        d = Kd * self.turev_f
        self.onceki = hata
        # Koşullu integrasyon (anti-windup)
        aday = self.integral + hata * dt
        if abs(Ki * aday) < I_SINIR or (Ki * aday * hata) < 0:
            self.integral = aday
        i = float(np.clip(Ki * self.integral, -I_SINIR, I_SINIR))
        return p + i + d


# =============================================================================
# 5. QR
# =============================================================================
_qr_gecmis = []
_qr_kare = 0


def qr_tara(frame_bgr):
    """N kare üst üste aynı içerik okunmadan True dönmez (yanlış dönüş koruması)."""
    global _qr_kare
    _qr_kare += 1
    if _qr_kare % QR_TARAMA_ARASI:
        return False
    gri = cv2.cvtColor(frame_bgr, cv2.COLOR_BGR2GRAY)
    gri = cv2.normalize(gri, None, 0, 255, cv2.NORM_MINMAX)
    try:
        icerikler = [o.data.decode('utf-8', errors='ignore') for o in decode(gri)]
    except Exception:
        icerikler = []
    okunan = QR_ICERIK if QR_ICERIK in icerikler else None
    _qr_gecmis.append(okunan)
    if len(_qr_gecmis) > QR_ONAY_KARE:
        _qr_gecmis.pop(0)
    if len(_qr_gecmis) >= QR_ONAY_KARE and all(g == QR_ICERIK for g in _qr_gecmis):
        _qr_gecmis.clear()
        return True
    return False


# =============================================================================
# 6. KAMERA
# =============================================================================
cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
if not cap.isOpened():
    cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)
cap.set(cv2.CAP_PROP_FPS, 60)
cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)   # V4L2 4 kare biriktirir -> ~100 ms ölü zaman
try:
    cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)
    cap.set(cv2.CAP_PROP_EXPOSURE, 70)
    cap.set(cv2.CAP_PROP_GAIN, 0)
except Exception:
    pass


def taze_kare():
    cap.grab()
    return cap.retrieve()


# =============================================================================
# 7. ANA DÖNGÜ
# =============================================================================
dedektor = Dedektor()
pid = PID()

DURUM = "CIZGI_TAKIP"
t_durum = time.monotonic()
son_zaman = time.monotonic()
son_gecerli = time.monotonic()
qr_soguma = 0.0
pivot_yon = 0
kose_taban_t = None
arama_yonu = +1
fps = 0.0

print(f"[SİSTEM] YON={YON:+d} | seyir={SEYIR} | pivot sağ={PIVOT_SAG} sol={PIVOT_SOL}")
print("[SİSTEM] Kayan pencere algılama + eğriliğe göre hız. Çıkış: 'q'")


def gec(yeni, not_=""):
    global DURUM, t_durum
    if yeni != DURUM:
        print(f"[DURUM] {DURUM} -> {yeni}  {not_}")
        DURUM = yeni
        t_durum = time.monotonic()


try:
    while True:
        ok, frame = taze_kare()
        if not ok or frame is None:
            print("[HATA] Kameradan görüntü alınamadı!")
            motor_sur(NOTR, NOTR, zorla=True)
            break

        # waitKey döngü BAŞINDA: pivot sırasında da 'q' çalışır
        if GOSTER and (cv2.waitKey(1) & 0xFF) == ord('q'):
            print("[SİSTEM] Kullanıcı durdurdu.")
            break

        arduino_dinle()
        simdi = time.monotonic()
        dt = min(max(simdi - son_zaman, 1e-3), 0.2)
        son_zaman = simdi
        fps += 0.1 * (1.0 / dt - fps)

        o = dedektor.isle(frame)
        if o.gecerli:
            son_gecerli = simdi

        sure = simdi - t_durum

        # ---------------------------------------------------------- CIZGI_TAKIP
        if DURUM == "CIZGI_TAKIP":
            if not o.gecerli:
                if simdi - son_gecerli > CIZGI_KAYIP_SURE:
                    motor_sur(NOTR, NOTR)
                    pid.sifirla()
                    gec("ARAMA", "çizgi kayboldu")
                else:
                    motor_sur(ileri(OFS_MIN), ileri(OFS_MIN))
            else:
                if simdi > qr_soguma and qr_tara(frame):
                    motor_sur(NOTR, NOTR)
                    gec("QR_FREN", f"QR '{QR_ICERIK}' onaylandı")

                elif o.kose_yonu != 0:
                    pivot_yon = o.kose_yonu
                    kose_taban_t = None
                    gec("VIRAJ_ILERI", f"{'sağ' if pivot_yon > 0 else 'sol'} L-viraj")

                else:
                    # Konum + yön açısı birleşik hata (Stanley benzeri)
                    hata = o.hata + K_ACI * o.egim
                    direksiyon = pid.hesapla(hata, dt)
                    # Eğrilik ön-beslemesi: virajın gerektirdiği kalıcı
                    # direksiyonu PID'in hata biriktirmesini beklemeden ver.
                    direksiyon += K_EGRI * o.egrilik
                    direksiyon = float(np.clip(direksiyon, -1.0, 1.0))

                    # Eğrilik arttıkça yavaşla -- "jilet gibi viraj"ın sırrı
                    egrilik = max(abs(direksiyon), abs(o.egim), abs(o.egrilik))
                    ofs = OFS_SEYIR * (1.0 - YAVASLAMA * min(1.0, egrilik))
                    if o.guven < 0.55:
                        ofs *= 0.6
                    ofs = max(OFS_MIN, ofs)

                    d_ofs = direksiyon * OFS_MAX
                    sol = np.clip(ofs + d_ofs, -OFS_TERS, OFS_MAX)
                    sag = np.clip(ofs - d_ofs, -OFS_TERS, OFS_MAX)
                    motor_sur(ileri(sol), ileri(sag))

        # --------------------------------------------------------- VIRAJ_ILERI
        elif DURUM == "VIRAJ_ILERI":
            # Tekerlekler köşeye varana kadar düz ilerle. Hareket algılamaya
            # BAĞLI DEĞİL (köşeye yaklaşınca çizgi kısalır, algılama düşer;
            # burada durursak pivot boş zemine bakar ve 90 yerine ~180 döner).
            motor_sur(YAVAS, YAVAS)

            if kose_taban_t is None:
                # Köşe henüz kadrajda: tabana inmesini bekle
                if (not o.gecerli) or o.bitis_y > ISL_H * KOSE_TABAN_ORANI:
                    kose_taban_t = simdi
            elif simdi - kose_taban_t >= KOR_BOLGE_SURESI:
                motor_sur(NOTR, NOTR)
                dedektor.sifirla()
                pid.sifirla()
                gec("PIVOT", f"apex, {pivot_yon:+d} yöne pivot")

            if sure >= VIRAJ_MAX_SURE:
                motor_sur(NOTR, NOTR)
                dedektor.sifirla()
                pid.sifirla()
                gec("PIVOT", "viraj zaman aşımı, yine de pivot")

        # --------------------------------------------------------------- PIVOT
        elif DURUM == "PIVOT":
            p = PIVOT_SAG if pivot_yon > 0 else PIVOT_SOL
            motor_sur(p[0], p[1])
            hizali = (o.gecerli and abs(o.hata) < PIVOT_CIKIS_HATA
                      and abs(o.egim) < PIVOT_CIKIS_ACI)
            if sure > PIVOT_MIN_SURE and hizali:
                motor_sur(NOTR, NOTR)
                pid.sifirla()
                qr_soguma = simdi + QR_SOGUMA
                gec("CIZGI_TAKIP", f"hizalandı ({sure:.2f} sn)")
            elif sure > PIVOT_MAX_SURE:
                motor_sur(NOTR, NOTR)
                arama_yonu = pivot_yon
                gec("ARAMA", f"pivot zaman aşımı ({sure:.2f} sn)")

        # ------------------------------------------------------------- QR akışı
        elif DURUM == "QR_FREN":
            motor_sur(NOTR, NOTR)
            if sure > 0.3:
                pivot_yon = +1              # görev tanımı: sağa 90
                dedektor.sifirla()
                gec("QR_PIVOT")

        elif DURUM == "QR_PIVOT":
            motor_sur(PIVOT_SAG[0], PIVOT_SAG[1])
            hizali = (o.gecerli and abs(o.hata) < PIVOT_CIKIS_HATA
                      and abs(o.egim) < PIVOT_CIKIS_ACI)
            if sure > PIVOT_MIN_SURE and hizali:
                motor_sur(NOTR, NOTR)
                pid.sifirla()
                qr_soguma = simdi + QR_SOGUMA
                gec("CIZGI_TAKIP", f"QR dönüşü tamam ({sure:.2f} sn)")
            elif sure > PIVOT_MAX_SURE:
                motor_sur(NOTR, NOTR)
                arama_yonu = +1
                qr_soguma = simdi + QR_SOGUMA
                gec("ARAMA", f"QR pivot zaman aşımı ({sure:.2f} sn)")

        # --------------------------------------------------------------- ARAMA
        elif DURUM == "ARAMA":
            if o.gecerli and o.guven > 0.5:
                motor_sur(NOTR, NOTR)
                pid.sifirla()
                gec("CIZGI_TAKIP", "çizgi tekrar bulundu")
            elif sure < ARAMA_SURE:
                p = ARAMA_SAG if arama_yonu > 0 else ARAMA_SOL
                motor_sur(p[0], p[1])
            else:
                motor_sur(NOTR, NOTR)
                gec("GUVENLI_DURUS", "arama sonuçsuz")

        elif DURUM == "GUVENLI_DURUS":
            motor_sur(NOTR, NOTR)
            if o.gecerli and o.guven > 0.6:
                pid.sifirla()
                gec("CIZGI_TAKIP", "çizgi geri geldi")

        # ------------------------------------------------------ görselleştirme
        if GOSTER:
            g = frame.copy()
            olcek = 320.0 / ISL_W
            cv2.line(g, (160, 0), (160, 240), (255, 0, 0), 1)
            for (px, py) in o.noktalar:
                cv2.circle(g, (int(px * olcek), int(py * olcek)), 4, (0, 220, 235), -1)
            if o.gecerli:
                renk = (60, 220, 60)
                cv2.putText(g, f"hata {o.hata:+.2f}  egim {o.egim:+.2f}", (5, 32),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.45, renk, 1)
            else:
                renk = (60, 60, 235)
            cv2.putText(g, f"{DURUM}  guven {o.guven:.2f}  {fps:.0f}fps", (5, 16),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, renk, 1)
            if o.kose_yonu:
                cv2.putText(g, f"KOSE {'SAG' if o.kose_yonu > 0 else 'SOL'}", (5, 50),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.5, (220, 80, 200), 2)
            cv2.imshow("RoboVizyon - kamera", g)
            if o.maske is not None:
                cv2.imshow("maske", cv2.resize(o.maske, (320, 240),
                                               interpolation=cv2.INTER_NEAREST))

except KeyboardInterrupt:
    print("\n[SİSTEM] Ctrl+C")

finally:
    print("[SİSTEM] Motorlar nötre alınıyor...")
    motor_sur(NOTR, NOTR, zorla=True)
    time.sleep(0.1)
    motor_sur(NOTR, NOTR, zorla=True)
    cap.release()
    if GOSTER:
        cv2.destroyAllWindows()
    try:
        arduino.close()
    except Exception:
        pass
    print("[SİSTEM] Güvenli çıkış yapıldı.")
