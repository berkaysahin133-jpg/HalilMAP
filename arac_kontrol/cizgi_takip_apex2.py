#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RoboVizyon — Çapraz Tahrikli AGV  |  SADE SÜRÜM
Siyah çizgi takibi + 90° L-viraj (sağ/sol) + ani fren & ortalama.

Jetson Orin Nano · 320x240 @30 FPS · Arduino + 2x MCP4725 DAC · "<sol,sag>\\n"

KUTUPLAMA — DEĞİŞTİRME (kablolar çapraz bağlı, sahada doğrulandı):
    sol_dac = temel + u        (u > 0  =>  araç SAĞA döner)
    sag_dac = temel - u
    SOLA_PIVOT = (1320, 2745)      SAGA_PIVOT = (2745, 1320)

WATCHDOG: Arduino 500 ms paket görmezse durur. Seri gönderim ayrı iplikte
sabit 50 Hz akar; ana döngü takılsa bile akış kesilmez.

    python3 cizgi_takip_apex2.py --kuru --gui
    python3 cizgi_takip_apex2.py --gui
    python3 cizgi_takip_apex2.py
"""

import argparse
import math
import sys
import threading
import time

import cv2
import numpy as np

try:
    import serial
except ImportError:
    serial = None

ap = argparse.ArgumentParser()
ap.add_argument("--port", default=None)
ap.add_argument("--kamera", type=int, default=0)
ap.add_argument("--kuru", action="store_true", help="motora komut gönderme")
ap.add_argument("--gui", action="store_true", help="nokta görüntüsünü aç")
ARG = ap.parse_args()


# =============================================================================
# AYARLAR
# =============================================================================
PORT_ADAYLARI = ["/dev/ttyUSB0", "/dev/ttyACM0", "/dev/ttyUSB1", "/dev/ttyACM1"]
BAUD = 115200
KOMUT_PERIYODU = 0.020        # gönderici iplik: 50 Hz
KOMUT_TAZELIK = 0.30          # ana döngü bu kadar susarsa NOTR

KAM_W, KAM_H, KAM_FPS = 320, 240, 30
KAMERA_TIMEOUT = 0.50

ISLEME_W, ISLEME_H = 160, 120
ORTA = 80.0
YAKIN_Y0, YAKIN_Y1 = 78, 120  # aracın önü  -> konum hatası
UZAK_Y0, UZAK_Y1 = 28, 68     # ileri görüş -> açı hatası

# --- satır taraması ---
SATIR_ADIM = 4
MIN_KOSU_GEN = 2              # px, bundan ince koşu = gürültü
MAKS_SICRAMA = 16             # px, ardışık satırlar arası izin verilen kayma
ILK_PENCERE = 50              # px, en alt satırda arama penceresi
MAKS_KOPUK = 2                # kaç satır boş geçilebilir
MIN_PROFIL = 3                # bundan az satır = çizgi yok

# --- eşik ---
OTSU_KATSAYI = 0.80
ESIK_ALT, ESIK_UST = 40, 115
ESIK_EMA = 0.25
ESIK_HER_N = 4                # Otsu her karede gereksiz

# --- motor ---
NOTR = 2048
DAC_ILERI_LIMIT = 1080
DAC_GERI_LIMIT = 2800
# İki kanalın kazanç farkı (sağ/sol asimetrisi). Düz komutta araç sağa
# kayıyorsa KANAL_SOL'u 1.02-1.06 yap; sola kayıyorsa KANAL_SAG'ı.
KANAL_SOL = 1.00
KANAL_SAG = 1.00

# --- hızlar (DAC küçüldükçe ileri hız artar) ---
SEYIR = 1560
DUZELTME_HIZ = 1620
KALKIS = 1520
RAMPA = 1710
YAKLASIM_HIZ = 1650
APEX_HIZ = 1560
KOR_HIZ = 1780
KALKIS_SN, RAMPA_SN = 0.25, 0.55
TORK_TABANI = 1900            # yavaşlayan teker bunun altına düşmez

# --- PID ---
Kp = 5.8
Kd = Kp * 0.09
Ki = Kp / 2.20
K_ACI = 0.80
TUREV_LPF_HZ = 5.0
D_LIMIT, I_LIMIT, U_LIMIT = 55.0, 35.0, 150.0
I_BANDI = 20.0
OLU_BANT = 1.5                # px, bu sapmada düzeltme yok (titreme önler)
MIN_BOOST = 26                # çapraz şasi sürtünmesini yenen asgari itiş
MIN_BOOST_ESIGI = 4.0
HATA_ESIGI = 12.0

# --- köşe tespiti (kadraja değil, ÇİZGİYE göre) ---
L_GEN_KAT = 2.6               # çizgi genişliğinin kaç katı = köşe kolu
L_MIN_GEN = 22                # px, mutlak alt sınır
L_TASMA = 6                   # px, sol/sağ taşma farkı
L_UST_MAKS = 2                # geniş satırın üstünde bu kadardan fazla normal
                              # satır varsa bu köşe değil, YAN DALDIR
KOSE_ONAY = 2                 # kaç kare üst üste
KOSE_TETIK_Y = 78             # köşe bu satıra inince apex başlar
YAKLASIM_TIMEOUT = 2.20
KOSE_KILIT_SN = 1.60          # dönüş sonrası yeni köşe tetiklenmez
GEN_ALT, GEN_UST = 4.0, 20.0  # beklenen çizgi genişliği sınırları

# --- apex / pivot (yöne göre ayrı: tahrik FL+RR çapraz) ---
APEX_SN_SOL, APEX_SN_SAG = 0.52, 0.78
HIZALA_SOL, HIZALA_SAG = (1650, 2450), (2450, 1650)
HIZALA_SN_SOL, HIZALA_SN_SAG = 0.12, 0.16
SOLA_PIVOT = (1320, 2745)     # DEĞİŞTİRME
SAGA_PIVOT = (2745, 1320)
PIVOT_MIN_SOL, PIVOT_MIN_SAG = 0.55, 0.55
PIVOT_TIMEOUT = 3.20
PIVOT_YAVAS_BANT = (42.0, 52.0)   # (sol, sağ) px — bu banda girince güç düşer
PIVOT_YAVAS_ORAN = (0.58, 0.55)
PIVOT_CIKIS = 14.0            # px, |cx_yakin-80| bunun altı = ortalandı
PIVOT_DIKLIK = 26.0           # px, |cx_uzak-cx_yakin| bunun altı = dik

# --- ani fren + ortalama ---
FREN_DARBE = 190              # ters darbe (plug braking)
FREN_DARBE_SN, FREN_NOTR_SN = 0.10, 0.09
ORTALA_KP = 9.0
ORTALA_KD = ORTALA_KP * 0.06
ORTALA_K_ACI = 0.75
ORTALA_MIN, ORTALA_MAKS = 250, 520   # yerinde dönüş gücü
ORTALA_TOL = 5.0
ORTALA_KARE = 4
ORTALA_TIMEOUT = 1.80

KAYIP_KOR_KARE = 3            # kısa gölgede son direksiyonla devam

KERNEL3 = cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3))
SATIRLAR = np.arange(118, 24, -SATIR_ADIM, dtype=np.int32)
cv2.setNumThreads(2)


# =============================================================================
# MOTOR — 50 Hz gönderici iplik
# =============================================================================
class Motor(threading.Thread):
    def __init__(self, port=None, kuru=False):
        super().__init__(daemon=True)
        self.kuru = kuru
        self.ser = None
        self.kilit = threading.Lock()
        self.hedef = (NOTR, NOTR)
        self.taze = time.time()
        self.calisiyor = True
        self.paket = 0
        self.hata = 0
        if kuru:
            print("[KURU] Motora komut gönderilmeyecek.")
            return
        if serial is None:
            sys.exit("[HATA] pyserial yok:  pip3 install pyserial")
        for p in ([port] if port else PORT_ADAYLARI):
            try:
                self.ser = serial.Serial(p, BAUD, timeout=0.05, write_timeout=0.05)
                print(f"[SİSTEM] Arduino: {p}")
                break
            except Exception:
                continue
        if self.ser is None:
            sys.exit("[HATA] Arduino bulunamadı. --kuru ile algı testi yapabilirsin.")
        time.sleep(2.0)

    def sur(self, sol, sag):
        sol = NOTR + (sol - NOTR) * KANAL_SOL
        sag = NOTR + (sag - NOTR) * KANAL_SAG
        sol = int(min(max(sol, DAC_ILERI_LIMIT), DAC_GERI_LIMIT))
        sag = int(min(max(sag, DAC_ILERI_LIMIT), DAC_GERI_LIMIT))
        with self.kilit:
            self.hedef = (sol, sag)
            self.taze = time.time()
        return sol, sag

    def dur(self):
        return self.sur(NOTR, NOTR)

    def run(self):
        while self.calisiyor:
            t0 = time.time()
            with self.kilit:
                sol, sag = self.hedef
                yas = t0 - self.taze
            if yas > KOMUT_TAZELIK:
                sol = sag = NOTR
            self._yaz(sol, sag)
            kalan = KOMUT_PERIYODU - (time.time() - t0)
            if kalan > 0:
                time.sleep(kalan)

    def _yaz(self, sol, sag):
        if self.kuru or self.ser is None:
            return
        try:
            self.ser.write(b"<%d,%d>\n" % (sol, sag))
            self.paket += 1
        except Exception:
            self.hata += 1

    def kapat(self):
        self.calisiyor = False
        if self.is_alive():
            self.join(timeout=1.0)
        for _ in range(6):
            self._yaz(NOTR, NOTR)
            time.sleep(0.02)
        if self.ser is not None:
            try:
                self.ser.close()
            except Exception:
                pass


# =============================================================================
# KAMERA — kopyasız devir, sadece yeni kare işlenir
# =============================================================================
class Kamera(threading.Thread):
    def __init__(self, index=0):
        super().__init__(daemon=True)
        self.cap = cv2.VideoCapture(index, cv2.CAP_V4L2)
        self.cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
        self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, KAM_W)
        self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, KAM_H)
        self.cap.set(cv2.CAP_PROP_FPS, KAM_FPS)
        self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        for a, d in ((cv2.CAP_PROP_AUTO_EXPOSURE, 0.25),
                     (cv2.CAP_PROP_EXPOSURE, 120)):
            try:
                self.cap.set(a, d)
            except Exception:
                pass
        if not self.cap.isOpened():
            sys.exit("[HATA] Kamera açılamadı.")
        self.kilit = threading.Lock()
        self.kare = None
        self.sayac = 0
        self.zaman = 0.0
        self.calisiyor = True
        ok, ilk = self.cap.read()
        if ok:
            self.kare, self.sayac, self.zaman = ilk, 1, time.time()

    def run(self):
        while self.calisiyor:
            ok, k = self.cap.read()
            if not ok:
                time.sleep(0.005)
                continue
            t = time.time()
            with self.kilit:
                self.kare, self.zaman = k, t
                self.sayac += 1

    def yeni(self, son_sayac):
        with self.kilit:
            if self.kare is None or self.sayac == son_sayac:
                return None
            return self.kare, self.sayac, self.zaman

    def kapat(self):
        self.calisiyor = False
        if self.is_alive():
            self.join(timeout=1.0)
        self.cap.release()


# =============================================================================
# ALGI — satır taraması (findContours yok)
# =============================================================================
class Algi:
    def __init__(self):
        self.esik = 85.0
        self.n = 0
        self.taban_cx = ORTA

    def _esik_hesapla(self, gri):
        self.n += 1
        if self.n % ESIK_HER_N == 0:
            otsu, _ = cv2.threshold(gri[ISLEME_H // 3:, :], 0, 255,
                                    cv2.THRESH_BINARY | cv2.THRESH_OTSU)
            ham = min(max(otsu * OTSU_KATSAYI, ESIK_ALT), ESIK_UST)
            self.esik = (1.0 - ESIK_EMA) * self.esik + ESIK_EMA * ham
        return int(self.esik)

    def _profil(self, maske):
        """
        Alttan yukarı: her satırda bir önceki satırın DEVAMI olan koşu seçilir.
        Süreklilik testi koşunun merkezine değil, önceki merkezi içerip
        içermediğine bakar — köşenin geniş yatay kolu böylece kopmaz.
        Döndürür: [(y, cx, genislik, bas, bit), ...] alttan üste.
        """
        alt = maske[SATIRLAR, :] > 0
        d = np.diff(alt.astype(np.int8), axis=1)
        ilk, son = alt[:, 0], alt[:, -1]

        profil = []
        ref = self.taban_cx
        kopuk = 0
        for i in range(SATIRLAR.shape[0]):
            bas = np.flatnonzero(d[i] == 1) + 1
            bit = np.flatnonzero(d[i] == -1) + 1
            if ilk[i]:
                bas = np.concatenate(([0], bas))
            if son[i]:
                bit = np.concatenate((bit, [ISLEME_W]))
            if bas.size:
                gen = bit - bas
                ok = gen >= MIN_KOSU_GEN
            else:
                ok = np.zeros(0, bool)
            if not ok.any():
                kopuk += 1
                if profil and kopuk > MAKS_KOPUK:
                    break
                continue

            bas, bit, gen = bas[ok], bit[ok], gen[ok]
            merkez = (bas + bit) * 0.5
            mesafe = np.maximum(np.maximum(bas - ref, ref - bit), 0.0)
            j = int(np.argmin(mesafe * 100.0 + np.abs(merkez - ref)))
            if mesafe[j] > (ILK_PENCERE if not profil else MAKS_SICRAMA):
                if profil:
                    break                      # çizgi bitti
                kopuk += 1
                if kopuk > MAKS_KOPUK + 2:
                    break
                continue

            kopuk = 0
            # Geniş koşuda referansı merkeze kaydırma; yanal konumu koru.
            ref = (float(min(max(ref, bas[j]), bit[j])) if gen[j] > L_MIN_GEN
                   else float(merkez[j]))
            profil.append((int(SATIRLAR[i]), float(merkez[j]), float(gen[j]),
                           float(bas[j]), float(bit[j])))
        return profil

    def isle(self, frame):
        # INTER_AREA küçültme zaten alçak geçiren filtre: ayrı blur gerekmez.
        kucuk = cv2.resize(frame, (ISLEME_W, ISLEME_H), interpolation=cv2.INTER_AREA)
        gri = cv2.cvtColor(kucuk, cv2.COLOR_BGR2GRAY)
        esik = self._esik_hesapla(gri)
        maske = cv2.morphologyEx(cv2.inRange(gri, 0, esik), cv2.MORPH_OPEN, KERNEL3)

        s = {"esik": esik, "bulundu": False, "profil": [], "cx_yakin": None,
             "cx_uzak": None, "cizgi_gen": 8.0, "kose_yon": None,
             "kose_y": None, "kose_i": None, "hata": 0.0}

        profil = self._profil(maske)
        s["profil"] = profil
        if len(profil) < MIN_PROFIL:
            return s

        yakin_gen = [g for (y, c, g, b, e) in profil if y >= YAKIN_Y0] or \
                    [g for (y, c, g, b, e) in profil]
        beklenen = min(max(float(np.median(yakin_gen)), GEN_ALT), GEN_UST)
        s["cizgi_gen"] = beklenen
        kose_esigi = max(L_GEN_KAT * beklenen, L_MIN_GEN)

        # Köşe = genişliği patlayan ilk satır. Üstünde çizgi normal genişlikte
        # devam ediyorsa köşe değil, geçilecek yan daldır.
        kose_i = None
        for i, (y, c, g, b, e) in enumerate(profil):
            if g > kose_esigi:
                ust = sum(1 for r in profil[i + 1:] if r[2] <= kose_esigi)
                if ust <= L_UST_MAKS:
                    kose_i = i
                break

        # Bant merkezleri: geniş (köşe kolu) satırlar hariç — yoksa merkez
        # köşeye doğru kayar ve araç viraja girmeden savrulur.
        dar = [(y, c) for (y, c, g, b, e) in profil if g <= kose_esigi]
        yakin = [c for (y, c) in dar if YAKIN_Y0 <= y < YAKIN_Y1]
        uzak = [c for (y, c) in dar if UZAK_Y0 <= y < UZAK_Y1]
        s["cx_yakin"] = (float(np.mean(yakin)) if yakin else
                         float(dar[0][1]) if dar else float(profil[0][1]))
        s["cx_uzak"] = float(np.mean(uzak)) if uzak else None
        self.taban_cx = s["cx_yakin"]

        if kose_i is not None:
            y, c, g, b, e = profil[kose_i]
            taban = profil[kose_i - 1][1] if kose_i else s["cx_yakin"]
            if (taban - b) > (e - taban) + L_TASMA:
                s["kose_yon"] = "SOL"
            elif (e - taban) > (taban - b) + L_TASMA:
                s["kose_yon"] = "SAG"
            s["kose_y"] = y
            s["kose_i"] = kose_i

        s["bulundu"] = True
        s["hata"] = hata_hesapla(s, K_ACI)
        return s


def hata_hesapla(s, k_aci):
    cy, cu = s["cx_yakin"], s["cx_uzak"]
    if cy is None:
        return 0.0
    return (cy - ORTA) + k_aci * (0.0 if cu is None else cu - cy)


# =============================================================================
# PID
# =============================================================================
class Pid:
    def __init__(self):
        self.sifirla()

    def sifirla(self):
        self.son = 0.0
        self.toplam = 0.0
        self.turev = 0.0
        self.ilk = True

    def __call__(self, hata, dt, kp, kd, ki=0.0, olu=OLU_BANT, boost=MIN_BOOST):
        ham = 0.0 if self.ilk else (hata - self.son) / dt
        if self.ilk:
            self.ilk = False
        self.son = hata

        tau = 1.0 / (2.0 * math.pi * TUREV_LPF_HZ)
        self.turev += (dt / (dt + tau)) * (ham - self.turev)
        d = min(max(kd * self.turev, -D_LIMIT), D_LIMIT)

        i = 0.0
        if ki > 0.0:
            self.toplam = (self.toplam + hata * dt if abs(hata) < I_BANDI
                           else self.toplam * 0.90)
            sinir = I_LIMIT / ki
            self.toplam = min(max(self.toplam, -sinir), sinir)
            i = ki * self.toplam

        if abs(hata) <= olu:
            self.toplam *= 0.85
            return 0.0

        u = kp * hata + i + d
        if boost > 0.0 and abs(u) > MIN_BOOST_ESIGI:
            u = math.copysign(abs(u) + boost, u)
        return min(max(u, -U_LIMIT), U_LIMIT)


def tork_dagit(temel, u):
    """sol=temel+u, sag=temel-u; yavaşlayan teker tork tabanının altına düşmez."""
    sol, sag = temel + u, temel - u
    en_yavas = max(sol, sag)
    if en_yavas > TORK_TABANI:
        k = en_yavas - TORK_TABANI
        sol -= k
        sag -= k
    return sol, sag


# =============================================================================
# DURUM MAKİNESİ
# =============================================================================
class Robot:
    def __init__(self, motor):
        self.motor = motor
        self.pid = Pid()
        self.durum = "TAKIP"
        self.faz_t = time.time()
        self.takip_t = time.time()
        self.yon = "SOL"
        self.onay = {"SOL": 0, "SAG": 0}
        self.kilit_bitis = 0.0
        self.apex_sn = APEX_SN_SOL
        self.ortala_sayaci = 0
        self.kayip = 0
        self.son_u = 0.0
        self.dac = (NOTR, NOTR)

    def gec(self, yeni, t, pid_sifirla=True):
        if yeni != self.durum:
            print(f"[{self.durum} -> {yeni}]")
        self.durum = yeni
        self.faz_t = t
        if pid_sifirla:
            self.pid.sifirla()

    def sur(self, sol, sag):
        self.dac = self.motor.sur(sol, sag)

    def adim(self, s, t, dt):
        d = self.durum
        gecen = t - self.faz_t

        # --- Köşe biliniyor: köşeye kadar çizgiyi takip ederek yaklaş -------
        # Robotun yanal konumu tam burada düzeltilir; apex her seferinde aynı
        # noktadan, aynı mesafeden başlar.
        if d == "YAKLASIM":
            if s["bulundu"]:
                self.son_u = self.pid(s["hata"], dt, Kp * 1.1, Kd, Ki)
                self.sur(*tork_dagit(YAKLASIM_HIZ, self.son_u))
            else:
                self.sur(YAKLASIM_HIZ, YAKLASIM_HIZ)
            ky = s["kose_y"] if s["kose_yon"] == self.yon else None
            bitti = (not s["bulundu"]) or len(s["profil"]) < MIN_PROFIL
            if (ky is not None and ky >= KOSE_TETIK_Y) or bitti or \
                    gecen >= YAKLASIM_TIMEOUT:
                self.apex_sn = APEX_SN_SOL if self.yon == "SOL" else APEX_SN_SAG
                print(f"[APEX] {self.yon} {self.apex_sn:.2f} sn (kose_y={ky})")
                self.sur(APEX_HIZ, APEX_HIZ)
                self.gec("APEX", t)
            return

        # --- Dönüş merkezini köşeye getir -----------------------------------
        if d == "APEX":
            self.sur(APEX_HIZ, APEX_HIZ)
            if gecen >= self.apex_sn:
                self.gec("HIZALA", t)
            return

        # --- Sarhoş teker ön savurma darbesi (yöne göre ayrı) ---------------
        if d == "HIZALA":
            sol_mu = self.yon == "SOL"
            hz = HIZALA_SOL if sol_mu else HIZALA_SAG
            self.sur(hz[0], hz[1])
            if gecen >= (HIZALA_SN_SOL if sol_mu else HIZALA_SN_SAG):
                self.gec("PIVOT", t)
            return

        # --- 90° pivot: güç rampalı, duruş ÖLÇÜMLE verilir ------------------
        if d == "PIVOT":
            sol_mu = self.yon == "SOL"
            piv = SOLA_PIVOT if sol_mu else SAGA_PIVOT
            min_sn = PIVOT_MIN_SOL if sol_mu else PIVOT_MIN_SAG
            bant = PIVOT_YAVAS_BANT[0 if sol_mu else 1]
            oran = PIVOT_YAVAS_ORAN[0 if sol_mu else 1]
            k = oran if (s["bulundu"] and abs(s["cx_yakin"] - ORTA) < bant) else 1.0
            self.sur(NOTR + (piv[0] - NOTR) * k, NOTR + (piv[1] - NOTR) * k)

            if gecen > min_sn and s["bulundu"]:
                cy, cu = s["cx_yakin"], s["cx_uzak"]
                if abs(cy - ORTA) <= PIVOT_CIKIS and \
                        (cu is None or abs(cu - cy) <= PIVOT_DIKLIK):
                    print(f"[PIVOT BİTTİ] {gecen:.2f} sn  cx={cy:.1f}")
                    self.sur(NOTR + FREN_DARBE, NOTR + FREN_DARBE)
                    self.gec("FREN", t)
                    return
            if gecen >= PIVOT_TIMEOUT:
                print("[PIVOT TIMEOUT]")
                self.sur(NOTR, NOTR)
                self.gec("KURTARMA", t)
            return

        # --- Ani fren: ters darbe + nötr ------------------------------------
        if d == "FREN":
            if gecen < FREN_DARBE_SN:
                self.sur(NOTR + FREN_DARBE, NOTR + FREN_DARBE)
            else:
                self.sur(NOTR, NOTR)
                if gecen >= FREN_DARBE_SN + FREN_NOTR_SN:
                    self.ortala_sayaci = 0
                    self.gec("ORTALA", t)
            return

        # --- Ortala: İLERİ GİTMEDEN yerinde dönerek çizgiye otur ------------
        if d == "ORTALA":
            if not s["bulundu"]:
                self.sur(NOTR, NOTR)
                if gecen > 0.6:
                    self.gec("KURTARMA", t)
                return
            u = self.pid(hata_hesapla(s, ORTALA_K_ACI), dt, ORTALA_KP, ORTALA_KD,
                         olu=ORTALA_TOL, boost=0.0)
            if u == 0.0:
                self.sur(NOTR, NOTR)
                self.ortala_sayaci += 1
            else:
                u = math.copysign(min(max(abs(u), ORTALA_MIN), ORTALA_MAKS), u)
                self.sur(NOTR + u, NOTR - u)
                self.ortala_sayaci = 0
            self.son_u = u
            if self.ortala_sayaci >= ORTALA_KARE or gecen >= ORTALA_TIMEOUT:
                self._takibe_don(t)
            return

        # --- Çizgi yok: çakılı bekle, görünce ani fren ----------------------
        if d == "KURTARMA":
            self.sur(NOTR, NOTR)
            if s["bulundu"]:
                self.gec("FREN", t)
            return

        # ===================== ANA TAKİP ===================================
        if not s["bulundu"]:
            self.kayip += 1
            if self.kayip <= KAYIP_KOR_KARE:
                self.sur(*tork_dagit(KOR_HIZ, self.son_u))   # kısa gölge
            else:
                print("[ÇİZGİ KAYBOLDU]")
                self.sur(NOTR + FREN_DARBE, NOTR + FREN_DARBE)
                self.gec("FREN", t)
            return
        self.kayip = 0

        yon = s["kose_yon"] if t >= self.kilit_bitis else None
        for k in ("SOL", "SAG"):
            self.onay[k] = self.onay[k] + 1 if yon == k else 0

        hata = s["hata"]
        gt = t - self.takip_t
        if gt < KALKIS_SN:
            hiz, kp = KALKIS, Kp * 0.85
        elif gt < RAMPA_SN:
            hiz, kp = RAMPA, Kp
        elif abs(hata) > HATA_ESIGI:
            hiz, kp = DUZELTME_HIZ, Kp * 1.25
        else:
            hiz, kp = SEYIR, Kp

        if yon and self.onay[yon] >= KOSE_ONAY:
            print(f"[KÖŞE {yon}] y={s['kose_y']} gen={s['cizgi_gen']:.1f}")
            self.yon = yon
            self.onay = {"SOL": 0, "SAG": 0}
            self.son_u = self.pid(hata, dt, Kp * 1.1, Kd, Ki)
            self.sur(*tork_dagit(YAKLASIM_HIZ, self.son_u))
            self.gec("YAKLASIM", t, pid_sifirla=False)
            return

        self.son_u = self.pid(hata, dt, kp, Kd, Ki)
        self.sur(*tork_dagit(hiz, self.son_u))

    def _takibe_don(self, t):
        self.gec("TAKIP", t)
        self.takip_t = t
        self.kilit_bitis = t + KOSE_KILIT_SN
        self.onay = {"SOL": 0, "SAG": 0}
        self.kayip = 0
        self.son_u = 0.0


# =============================================================================
# ANA DÖNGÜ
# =============================================================================
def main():
    motor = Motor(port=ARG.port, kuru=ARG.kuru)
    motor.start()
    motor.dur()
    kam = Kamera(index=ARG.kamera)
    kam.start()
    time.sleep(0.4)
    print("[SİSTEM] Hazır." + ("  GUI açık ('q' ile çık)" if ARG.gui else ""))

    algi = Algi()
    robot = Robot(motor)
    son_sayac = -1
    onceki_t = time.time()
    son_taze = time.time()
    kare = 0

    try:
        while True:
            veri = kam.yeni(son_sayac)
            if veri is None:
                if time.time() - son_taze > KAMERA_TIMEOUT:
                    motor.dur()
                    robot.pid.sifirla()
                time.sleep(0.002)
                continue

            frame, son_sayac, kare_t = veri
            son_taze = time.time()
            kare += 1
            dt = min(max(kare_t - onceki_t, 0.005), 0.200)
            onceki_t = kare_t

            s = algi.isle(frame)
            robot.adim(s, kare_t, dt)

            # Sadece çizginin ORTA NOKTALARI çizilir; başka hiçbir şey yok.
            if ARG.gui and kare % 3 == 0:
                for i, (y, c, g, b, e) in enumerate(s["profil"]):
                    renk = (0, 0, 255) if i == s["kose_i"] else (0, 255, 0)
                    cv2.circle(frame, (int(c * 2), int(y * 2)), 2, renk, -1)
                if s["cx_yakin"] is not None:
                    cv2.circle(frame, (int(s["cx_yakin"] * 2), 226), 4,
                               (0, 255, 255), -1)
                cv2.imshow("RoboVizyon", frame)
                if (cv2.waitKey(1) & 0xFF) == ord("q"):
                    break

    except KeyboardInterrupt:
        pass
    finally:
        motor.dur()
        time.sleep(0.10)
        kam.kapat()
        motor.kapat()
        cv2.destroyAllWindows()
        print(f"[ÇIKIŞ] paket:{motor.paket} yazma_hatasi:{motor.hata}")


if __name__ == "__main__":
    main()
