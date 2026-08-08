#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RoboVizyon - Cizgi Takip + QR Gorev Protokolu   (Raspberry Pi 5 + Arduino/MCP4725)

v2 goruntu isleme:
  - Yatay bant (ROI) tabanli centroid: yakin bant direksiyonu surer,
    uzak bant on-gorus (feed-forward) ve hiz azaltma icin kullanilir
  - Otsu ile uyarlanabilir esik (sabit 0-85 esigi kaldirildi) + kararlilik filtresi
  - CAP_PROP_BUFFERSIZE=1 -> kamera gecikmesi (PID'in en buyuk dusmani) yok edildi
  - time.monotonic() -> NTP saat sicramasi PID'i patlatmaz
  - Turev filtresi + kosullu integrasyon (anti-windup)
  - Egrilige gore otomatik yavaslama
  - QR: sadece icerik dogrulanirsa manevra tetiklenir (yanlis 90 donus riski kalkti)
  - Pivot dahil HER karede waitKey -> 'q' her an calisir
  - try/finally + atexit: hangi hatada olursa olsun motorlar notre iner

Kullanim:
    python3 cizgi_takip.py                 # pencereli
    python3 cizgi_takip.py --headless      # SSH/servis
    python3 cizgi_takip.py --kalibre       # esik/ROI ayar modu, motor gonderilmez
"""

import argparse
import atexit
import glob
import sys
import time

import cv2
import numpy as np
import serial

try:
    from pyzbar.pyzbar import decode as qr_decode
except ImportError:
    qr_decode = None


# =============================================================================
#  1. MOTOR KONVANSIYONU  --  ONCE BUNU DOGRULA
# =============================================================================
# Tekerlekleri havaya kaldir, sadece su satiri calistir:
#     link.gonder(0.4, 0.4)
# Ileri donuyorsa YON = +1 birak. Geri donuyorsa YON = -1 yap.
#
# NOT: Eski kodda TEMEL_HIZ=1550 idi. 1550, 2546'nin notre gore tam simetrigi;
# yani arac seyir halinde GERI gidiyordu. Asagidaki normalize sistem bu hatanin
# tekrarlanmasini imkansiz kilar: her sey -1.0..+1.0 arasinda ifade edilir.

NOTR = 2048          # DAC 2048 = 2.5 V = tam durus
SPAN = 900           # notr'dan tam gaza DAC farki (2048 +/- 900 -> 1148..2948)
YON  = +1            # +1: DAC > NOTR ileri    |    -1: DAC < NOTR ileri


# =============================================================================
#  2. AYARLAR
# =============================================================================
SERI_PORT_ADAYLARI = ["/dev/ttyUSB*", "/dev/ttyACM*"]
BAUD               = 115200

KAM_W, KAM_H  = 320, 240
ISLEM_W       = 160          # cizgi analizi bu genislikte yapilir (hiz icin)
ISLEM_H       = 120

# --- Yatay bantlar (ISLEM_H uzerinden, 0 = ust) ---
# yakin bant = direksiyon, uzak bant = on-gorus
BANT_YAKIN = (0.72, 0.98)    # kareye en yakin serit
BANT_ORTA  = (0.46, 0.70)
BANT_UZAK  = (0.20, 0.44)

# --- Hiz (normalize, 0..1) ---
HIZ_SEYIR   = 0.55           # duz yolda
HIZ_MIN     = 0.22           # keskin virajda inilecek taban
HIZ_QR      = 0.28           # QR'a yaklasirken
PIVOT_HIZ   = 0.90           # yerinde donus

# --- PID (normalize hata: -1.0 .. +1.0) ---
Kp        = 0.85
Ki        = 0.12
Kd        = 0.045
D_FILTRE  = 0.35             # turev alcak geciren katsayisi (0=kapali, 1=cok agir)
I_SINIR   = 0.35             # integral katkisinin mutlak tavani
FF_KAZANC = 0.30             # uzak banttan gelen on-gorus katkisi

YAVASLAMA = 0.75             # |direksiyon| basina hiz kesme orani

# --- Kose (L-viraj) tespiti ---
KOSE_CX_ESIK   = 0.34        # yakin bant centroid'i merkezden bu kadar kacarsa
KOSE_EN_BOY    = 2.6         # yakin bant konturu bu kadar yassiysa = yan cizgi
KOSE_CIKIS     = 0.12        # pivot cikisi: cx merkeze bu kadar yaklasinca
KOSE_MAX_SURE  = 2.5         # pivot bu sureyi asarsa guvenli durusa gec

# --- QR ---
QR_ICERIK       = "11"       # sadece bu icerik 90 sag donusu tetikler
QR_TARAMA_ARASI = 3          # her N karede bir pyzbar cagrilir
QR_SOGUMA       = 3.0        # ayni QR'i tekrar okumama suresi (sn)
DONUS_SURESI    = 1.4        # 90 pivot ust siniri (cizgi bulununca erken biter)

# --- Guvenlik ---
KOMUT_PERIYOT   = 0.02       # Arduino'ya en fazla 50 Hz (watchdog 250 ms)
CIZGI_KAYIP_SUR = 0.8        # bu kadar cizgi yoksa dur


# =============================================================================
#  3. MOTOR BAGLANTISI
# =============================================================================
class MotorLink:
    """Arduino'ya <sol,sag> paketi basar. Kapanista her kosulda notre iner."""

    def __init__(self, port=None, kuru=False):
        self.kuru = kuru                 # True -> seri port acilmaz (kalibre modu)
        self.ser = None
        self._son_gonderim = 0.0
        self._son_paket = None
        self.son_heartbeat = time.monotonic()

        if kuru:
            print("[SISTEM] Kalibrasyon modu: motorlara komut gonderilmiyor.")
            return

        port = port or self._port_bul()
        if port is None:
            raise RuntimeError("Arduino bulunamadi (/dev/ttyUSB* veya /dev/ttyACM*)")

        self.ser = serial.Serial(port, BAUD, timeout=0, write_timeout=0.05)
        print(f"[SISTEM] Arduino baglandi: {port}")
        time.sleep(2.0)                  # DTR reset'i bekle
        self.ser.reset_input_buffer()
        self.ser.reset_output_buffer()

    @staticmethod
    def _port_bul():
        for kalip in SERI_PORT_ADAYLARI:
            bulunan = sorted(glob.glob(kalip))
            if bulunan:
                return bulunan[0]
        return None

    @staticmethod
    def _dac(u):
        """u: -1.0 (tam geri) .. +1.0 (tam ileri)  ->  DAC 0..4095"""
        u = float(np.clip(u, -1.0, 1.0))
        return int(round(np.clip(NOTR + YON * SPAN * u, 0, 4095)))

    def gonder(self, u_sol, u_sag, zorla=False):
        """Normalize hizlari yollar. Ayni paket tekrar tekrar spam edilmez."""
        paket = (self._dac(u_sol), self._dac(u_sag))
        simdi = time.monotonic()

        # Degismediyse yine de watchdog'u beslemek icin periyodik tekrar sart
        if not zorla and paket == self._son_paket and \
           (simdi - self._son_gonderim) < KOMUT_PERIYOT:
            return

        self._son_paket = paket
        self._son_gonderim = simdi

        if self.kuru or self.ser is None:
            return
        try:
            self.ser.write(f"<{paket[0]},{paket[1]}>\n".encode("ascii"))
        except serial.SerialException as e:
            print(f"[HATA] Seri yazma: {e}")

    def dur(self):
        self.gonder(0.0, 0.0, zorla=True)

    def heartbeat_oku(self):
        """Arduino'dan gelen OK satirlarini yutar, canlilik zamanini gunceller."""
        if self.kuru or self.ser is None:
            return
        try:
            if self.ser.in_waiting:
                self.ser.read(self.ser.in_waiting)
                self.son_heartbeat = time.monotonic()
        except serial.SerialException:
            pass

    def kapat(self):
        try:
            self.dur()
            time.sleep(0.1)
            self.dur()
        finally:
            if self.ser is not None and self.ser.is_open:
                self.ser.close()
                self.ser = None


# =============================================================================
#  4. PID
# =============================================================================
class PID:
    def __init__(self, kp, ki, kd, i_sinir, d_filtre):
        self.kp, self.ki, self.kd = kp, ki, kd
        self.i_sinir, self.d_filtre = i_sinir, d_filtre
        self.sifirla()

    def sifirla(self):
        self.integral = 0.0
        self.onceki_hata = 0.0
        self.turev_f = 0.0

    def hesapla(self, hata, dt):
        p = self.kp * hata

        # Turev: filtreli (dt jitter'inin Kd ile buyumesini engeller)
        ham_turev = (hata - self.onceki_hata) / dt if dt > 1e-4 else 0.0
        self.turev_f += self.d_filtre * (ham_turev - self.turev_f)
        d = self.kd * self.turev_f
        self.onceki_hata = hata

        # Integral: kosullu (cikis doymussa ve ayni yone itiyorsa biriktirme)
        aday = self.integral + hata * dt
        i = self.ki * aday
        if abs(i) < self.i_sinir or (i * hata) < 0:
            self.integral = aday
        i = float(np.clip(self.ki * self.integral, -self.i_sinir, self.i_sinir))

        return p + i + d


# =============================================================================
#  5. SERIT DEDEKTORU
# =============================================================================
class BantOlcum:
    __slots__ = ("gecerli", "cx", "alan", "en_boy", "maske")

    def __init__(self, gecerli=False, cx=0.0, alan=0.0, en_boy=0.0, maske=None):
        self.gecerli = gecerli
        self.cx = cx              # -1.0 (tam sol) .. +1.0 (tam sag)
        self.alan = alan          # piksel
        self.en_boy = en_boy      # w/h
        self.maske = maske


class SeritDedektoru:
    """Otsu tabanli, bant bant calisan siyah cizgi bulucu."""

    ESIK_TABAN, ESIK_TAVAN = 35, 135     # Otsu'nun kacmasina izin verilen aralik
    KOYU_ORAN_MIN, KOYU_ORAN_MAX = 0.01, 0.55
    MIN_ALAN = 60

    def __init__(self, w, h):
        self.w, self.h = w, h
        self.esik_f = 85.0               # kareler arasi yumusatilmis esik

    def _bant(self, gray, aralik):
        y0 = int(self.h * aralik[0])
        y1 = int(self.h * aralik[1])
        return gray[y0:y1, :], y0

    def _esik_guncelle(self, roi):
        """Otsu esigini hesapla, mantikli araliga kilitle, kareler arasi yumusat."""
        otsu, _ = cv2.threshold(roi, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        otsu = float(np.clip(otsu, self.ESIK_TABAN, self.ESIK_TAVAN))
        self.esik_f += 0.25 * (otsu - self.esik_f)
        return self.esik_f

    def olc(self, gray, aralik, esik=None):
        roi, _ = self._bant(gray, aralik)
        if roi.size == 0:
            return BantOlcum()

        roi = cv2.GaussianBlur(roi, (5, 5), 0)
        if esik is None:
            esik = self._esik_guncelle(roi)

        maske = cv2.inRange(roi, 0, int(esik))
        maske = cv2.morphologyEx(maske, cv2.MORPH_OPEN,
                                 cv2.getStructuringElement(cv2.MORPH_RECT, (3, 3)))

        # Bant tamamen koyu (golge/kapali kamera) veya bombos ise guvenme
        koyu_oran = float(np.count_nonzero(maske)) / maske.size
        if not (self.KOYU_ORAN_MIN <= koyu_oran <= self.KOYU_ORAN_MAX):
            return BantOlcum(maske=maske)

        konturlar, _ = cv2.findContours(maske, cv2.RETR_EXTERNAL,
                                        cv2.CHAIN_APPROX_SIMPLE)
        if not konturlar:
            return BantOlcum(maske=maske)

        c = max(konturlar, key=cv2.contourArea)
        alan = cv2.contourArea(c)
        if alan < self.MIN_ALAN:
            return BantOlcum(maske=maske)

        M = cv2.moments(c)
        if M["m00"] == 0:
            return BantOlcum(maske=maske)

        cx_px = M["m10"] / M["m00"]
        cx_n = (cx_px - self.w / 2.0) / (self.w / 2.0)     # -1..+1

        _, _, bw, bh = cv2.boundingRect(c)
        en_boy = bw / float(bh) if bh > 0 else 99.0

        return BantOlcum(True, float(np.clip(cx_n, -1, 1)), alan, en_boy, maske)


# =============================================================================
#  6. QR
# =============================================================================
def qr_ara(gray_tam):
    """Tam karede QR arar, bulunan icerikleri liste olarak doner."""
    if qr_decode is None:
        return []
    # Kontrasti ac -- salon isigi parlamasi QR pikselini yutuyordu
    net = cv2.normalize(gray_tam, None, 0, 255, cv2.NORM_MINMAX)
    try:
        return [o.data.decode("utf-8", errors="ignore") for o in qr_decode(net)]
    except Exception:
        return []


# =============================================================================
#  7. KAMERA
# =============================================================================
def kamera_ac():
    cap = cv2.VideoCapture(0, cv2.CAP_V4L2)
    if not cap.isOpened():
        cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        raise RuntimeError("Kamera acilamadi")

    # MJPG: USB bant genisligini dusurur, yuksek FPS'i mumkun kilar
    cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))
    cap.set(cv2.CAP_PROP_FRAME_WIDTH, KAM_W)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, KAM_H)
    cap.set(cv2.CAP_PROP_FPS, 60)

    # EN KRITIK SATIR: V4L2 varsayilan 4 kare biriktirir -> ~100 ms olu zaman.
    # PID bunu gorunce salinir. 1 yaparak her zaman en taze kareyi aliriz.
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)

    # Otomatik pozlama QR piksellerini bulandiriyor -> manuel, kisa perde
    try:
        cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)   # V4L2 manuel mod
        cap.set(cv2.CAP_PROP_EXPOSURE, 60)          # birim 100us -> ~6 ms
        cap.set(cv2.CAP_PROP_GAIN, 0)
        cap.set(cv2.CAP_PROP_AUTO_WB, 0)
    except Exception:
        pass

    return cap


# =============================================================================
#  8. ANA DONGU
# =============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--headless", action="store_true", help="pencere acma")
    ap.add_argument("--kalibre", action="store_true", help="motor gonderme, sadece goruntu")
    ap.add_argument("--port", default=None)
    args = ap.parse_args()

    goster = not args.headless

    link = MotorLink(port=args.port, kuru=args.kalibre)
    atexit.register(link.kapat)          # ne olursa olsun motorlar iner

    cap = kamera_ac()
    dedektor = SeritDedektoru(ISLEM_W, ISLEM_H)
    pid = PID(Kp, Ki, Kd, I_SINIR, D_FILTRE)

    durum = "CIZGI_TAKIP"
    t_durum = time.monotonic()
    son_t = time.monotonic()
    qr_soguma_bitis = 0.0
    kare_no = 0
    cizgi_son_gorulme = time.monotonic()
    pivot_yon = 0                        # -1 sol, +1 sag
    fps_f = 0.0

    print("[SISTEM] Cizgi takip aktif. Cikis: 'q'")

    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                print("[HATA] Kare alinamadi")
                link.dur()
                break

            simdi = time.monotonic()
            dt = simdi - son_t
            son_t = simdi
            dt = min(max(dt, 1e-3), 0.2)          # monotonic + guvenli klip
            fps_f += 0.1 * ((1.0 / dt) - fps_f)
            kare_no += 1

            link.heartbeat_oku()

            kucuk = cv2.resize(frame, (ISLEM_W, ISLEM_H), interpolation=cv2.INTER_AREA)
            gray = cv2.cvtColor(kucuk, cv2.COLOR_BGR2GRAY)

            yakin = dedektor.olc(gray, BANT_YAKIN)
            esik  = dedektor.esik_f
            orta  = dedektor.olc(gray, BANT_ORTA, esik)
            uzak  = dedektor.olc(gray, BANT_UZAK, esik)

            if yakin.gecerli:
                cizgi_son_gorulme = simdi

            # ---------------- QR taramasi ----------------
            if durum == "CIZGI_TAKIP" and simdi > qr_soguma_bitis \
                    and kare_no % QR_TARAMA_ARASI == 0:
                gray_tam = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                icerikler = qr_ara(gray_tam)
                # ONEMLI: sadece dogrulanmis icerik manevra tetikler.
                # Eski koddaki "kareye benzeyen kontur" refleksi kaldirildi;
                # golge/bant/kavsak yuzunden yanlis 90 donus yapiyordu.
                if QR_ICERIK in icerikler:
                    print(f"[QR] '{QR_ICERIK}' dogrulandi -> kontrollu yavaslama")
                    durum, t_durum = "QR_YAKLASIM", simdi

            # =================== DURUM MAKINESI ===================
            if durum == "QR_YAKLASIM":
                link.gonder(HIZ_QR, HIZ_QR)
                if simdi - t_durum > 0.25:
                    durum, t_durum = "QR_FREN", simdi

            elif durum == "QR_FREN":
                link.dur()
                if simdi - t_durum > 0.3:
                    print(f"[PROTOKOL] 90 sag pivot (max {DONUS_SURESI} sn)")
                    durum, t_durum = "PIVOT_QR", simdi
                    pivot_yon = +1

            elif durum in ("PIVOT_QR", "PIVOT_SOL", "PIVOT_SAG"):
                link.gonder(PIVOT_HIZ * pivot_yon, -PIVOT_HIZ * pivot_yon)
                gecen = simdi - t_durum
                ust_sinir = DONUS_SURESI if durum == "PIVOT_QR" else KOSE_MAX_SURE

                # Kapali cevrim cikis: cizgi merkeze oturdugunda bitir.
                # (Zamana dayali acik cevrim, aku dustukce aci tutturamiyordu.)
                erken_bitis = (gecen > 0.35 and yakin.gecerli
                               and abs(yakin.cx) < KOSE_CIKIS)
                if erken_bitis or gecen > ust_sinir:
                    link.dur()
                    if erken_bitis:
                        print(f"[PIVOT] Cizgi ortalandi ({gecen:.2f} sn) -> PID takip")
                        durum = "CIZGI_TAKIP"
                        pid.sifirla()
                        qr_soguma_bitis = simdi + QR_SOGUMA
                    else:
                        print("[PIVOT] Sure doldu, cizgi yok -> guvenli durus")
                        durum = "CIZGI_ARA"
                    t_durum = simdi

            elif durum == "CIZGI_ARA":
                link.dur()
                if yakin.gecerli and abs(yakin.cx) < 0.5:
                    print("[KURTARMA] Cizgi bulundu -> takip")
                    durum = "CIZGI_TAKIP"
                    pid.sifirla()
                    qr_soguma_bitis = simdi + QR_SOGUMA

            elif durum == "CIZGI_TAKIP":
                if not yakin.gecerli:
                    if simdi - cizgi_son_gorulme > CIZGI_KAYIP_SUR:
                        print("[UYARI] Cizgi kayboldu -> durduruldu")
                        link.dur()
                        pid.sifirla()
                        durum = "CIZGI_ARA"
                    else:
                        # Kisa kayiplarda son direksiyonu koruyarak yavas ilerle
                        link.gonder(HIZ_MIN, HIZ_MIN)
                else:
                    # --- Kose (L-viraj) tespiti ---
                    # Iki kanit: centroid uca kacti VE kontur yatay uzadi
                    # (yassi kontur = cizgi yana donuyor demektir)
                    kose = (abs(yakin.cx) > KOSE_CX_ESIK
                            and yakin.en_boy > KOSE_EN_BOY
                            and not uzak.gecerli)
                    if kose:
                        pivot_yon = +1 if yakin.cx > 0 else -1
                        durum = "PIVOT_SAG" if pivot_yon > 0 else "PIVOT_SOL"
                        t_durum = simdi
                        print(f"[KESKIN KOSE] 90 {'sag' if pivot_yon>0 else 'sol'} pivot")
                    else:
                        # --- PID + on-gorus ---
                        hata = yakin.cx
                        direksiyon = pid.hesapla(hata, dt)

                        # Uzak bant nereye gidiyorsa oraya hafif on yatirim:
                        # viraja girmeden once tekerlegi cevirmeye baslar
                        if uzak.gecerli:
                            direksiyon += FF_KAZANC * (uzak.cx - hata)

                        direksiyon = float(np.clip(direksiyon, -1.0, 1.0))

                        # Egrilik arttikca yavasla (jilet gibi virajin siri)
                        egrilik = abs(direksiyon)
                        if orta.gecerli and uzak.gecerli:
                            egrilik = max(egrilik, abs(uzak.cx - yakin.cx))
                        hiz = HIZ_SEYIR * (1.0 - YAVASLAMA * min(1.0, egrilik))
                        hiz = max(HIZ_MIN, hiz)

                        u_sol = hiz + direksiyon
                        u_sag = hiz - direksiyon

                        # Diferansiyeli koruyarak normalize et (kirpma yerine olcekle)
                        tepe = max(abs(u_sol), abs(u_sag), 1.0)
                        link.gonder(u_sol / tepe, u_sag / tepe)

            # ---------------- Gorsellestirme ----------------
            if goster:
                ciz = frame.copy()
                olcek = KAM_W / float(ISLEM_W)
                for ad, bant, olcum, renk in (
                        ("YAKIN", BANT_YAKIN, yakin, (0, 0, 255)),
                        ("ORTA",  BANT_ORTA,  orta,  (0, 200, 255)),
                        ("UZAK",  BANT_UZAK,  uzak,  (0, 255, 0))):
                    y0 = int(KAM_H * bant[0])
                    y1 = int(KAM_H * bant[1])
                    cv2.rectangle(ciz, (0, y0), (KAM_W - 1, y1), renk, 1)
                    if olcum.gecerli:
                        cx_px = int((olcum.cx * 0.5 + 0.5) * KAM_W)
                        cv2.circle(ciz, (cx_px, (y0 + y1) // 2), 5, renk, -1)

                cv2.line(ciz, (KAM_W // 2, 0), (KAM_W // 2, KAM_H), (255, 0, 0), 1)
                cv2.putText(ciz, f"{durum}  esik={dedektor.esik_f:.0f}  {fps_f:4.1f}fps",
                            (5, 15), cv2.FONT_HERSHEY_SIMPLEX, 0.42, (255, 255, 255), 1)
                cv2.imshow("RoboVizyon - Cizgi Takip", ciz)
                if yakin.maske is not None:
                    cv2.imshow("Yakin Bant Maskesi", yakin.maske)

                # waitKey HER karede cagriliyor: pivot sirasinda da 'q' calisir.
                # Eski kodda tum manevra durumlari 'continue' ile ciktigi icin
                # 1.4 sn'lik pivot boyunca klavyeden durdurmak mumkun degildi.
                if (cv2.waitKey(1) & 0xFF) == ord("q"):
                    print("[SISTEM] Kullanici durdurdu")
                    break

    except KeyboardInterrupt:
        print("\n[SISTEM] Ctrl+C")
    finally:
        link.kapat()
        cap.release()
        if goster:
            cv2.destroyAllWindows()
        print("[SISTEM] Motorlar notrde, cikildi.")


if __name__ == "__main__":
    sys.exit(main())
