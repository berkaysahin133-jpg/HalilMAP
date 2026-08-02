#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUVENLIK BOLGESI -- LiDAR'in arac uzerindeki asil gorevi.

Aracin ONUNDE koridor seklinde bir bolge tanimlar. O bolgeye bir sey girerse
once YAVASLA, yaklasirsa DUR der. Cekilince kendiliginden serbest birakir.

    python guvenlik.py                 # canli (LiDAR takili)
    python guvenlik.py --sahte         # LiDAR YOKKEN sentetik oda ile dene
    python guvenlik.py --oynat oda.npz # kayittan oynat
    python guvenlik.py --dur 0.5 --yavas 1.0 --genislik 0.5

Cizgi izleme koduna baglamak (cizgi_takip*.py icine):

    from guvenlik import Guvenlik, GuvenlikOkuyucu
    oku = GuvenlikOkuyucu(port="/dev/ttyUSB0")   # arka planda tarar
    ...
    d = oku.durum()
    hiz = int(TABAN_HIZ * d["hiz_carpani"])      # 1.0 / 0.4 / 0.0
    if d["durum"] == "DUR":
        duzeltme = 0                             # dururken direksiyon kirma

Neden nokta SAYISI esigi var: tek bir gurultu noktasi araci durdurmamali.
Neden histerezis var: esigin tam ustunde titreyen bir engel, aracin surekli
dur-kalk yapmasina yol acar. Cikis esigi giris esiginden BUYUK.
"""

import argparse
import os
import sys
import threading
import time

import numpy as np

try:
    import cv2
except ImportError:
    cv2 = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c1

DURUMLAR = ("SERBEST", "YAVAS", "DUR")
HIZ_CARPANI = {"SERBEST": 1.0, "YAVAS": 0.4, "DUR": 0.0}


def tur_xy(tur, kor_acilar=()):
    """[(aci_derece, mesafe_mm, kalite)] -> Nx2 metre dizisi (x=sag, y=ileri).

    LiDAR 0 derece = ileri. kor_acilar: [(bas, son), ...] derece araliklari --
    aracin kendi govdesini goren yonler burada elenir.
    """
    if not tur:
        return np.zeros((0, 2))
    a = np.array([t[0] for t in tur], float)
    m = np.array([t[1] for t in tur], float) / 1000.0
    tut = m > 0
    for bas, son in kor_acilar:
        bas, son = bas % 360.0, son % 360.0
        if bas <= son:
            tut &= ~((a >= bas) & (a <= son))
        else:                                    # 350-10 gibi sarmal aralik
            tut &= ~((a >= bas) | (a <= son))
    a, m = a[tut], m[tut]
    r = np.radians(a)
    return np.stack([m * np.sin(r), m * np.cos(r)], axis=1)


class Guvenlik:
    """Onundeki koridoru izler, SERBEST / YAVAS / DUR uretir."""

    def __init__(self, yari_genislik_m=0.30, dur_m=0.40, yavas_m=0.90,
                 en_yakin_m=0.10, min_nokta=2, histerezis_m=0.12,
                 kor_acilar=()):
        self.yari_genislik = yari_genislik_m
        self.dur = dur_m
        self.yavas = yavas_m
        self.en_yakin = en_yakin_m       # bundan yakin = kendi govdesi/gurultu
        self.min_nokta = min_nokta
        self.histerezis = histerezis_m
        self.kor_acilar = list(kor_acilar)
        self.durum = "SERBEST"

    def degerlendir(self, tur):
        """Bir tarama turunu degerlendirir. dict doner."""
        P = tur_xy(tur, self.kor_acilar)
        if len(P):
            mesafe = np.hypot(P[:, 0], P[:, 1])
            koridor = ((np.abs(P[:, 0]) <= self.yari_genislik)
                       & (P[:, 1] > 0) & (mesafe >= self.en_yakin))
        else:
            mesafe = np.zeros(0)
            koridor = np.zeros(0, bool)

        icerdeki = P[koridor]
        ileri = icerdeki[:, 1] if len(icerdeki) else np.zeros(0)

        # Histerezis: mevcut durumdan CIKMAK icin esik biraz uzakta
        d_esik = self.dur + (self.histerezis if self.durum == "DUR" else 0.0)
        y_esik = self.yavas + (self.histerezis if self.durum != "SERBEST" else 0.0)

        n_dur = int((ileri <= d_esik).sum())
        n_yavas = int((ileri <= y_esik).sum())

        if n_dur >= self.min_nokta:
            self.durum = "DUR"
        elif n_yavas >= self.min_nokta:
            self.durum = "YAVAS"
        else:
            self.durum = "SERBEST"

        # Karara sebep olan noktalar: koridorda VE yavas esigi icinde.
        # Koridorun icinde kalan 3 m'deki duvar karari etkilemez, vurgulanmaz.
        vurgu = np.zeros(len(P), bool)
        if len(P):
            vurgu[koridor] = ileri <= y_esik

        return {
            "durum": self.durum,
            "hiz_carpani": HIZ_CARPANI[self.durum],
            "en_yakin_m": float(ileri.min()) if len(ileri) else float("inf"),
            "koridor_nokta": int(len(icerdeki)),
            "ilgili_nokta": int(vurgu.sum()),
            "noktalar": P,
            "koridor_maske": koridor,
            "vurgu_maske": vurgu,
        }


class GuvenlikOkuyucu:
    """LiDAR'i ARKA PLANDA tarar; ana dongu bloklanmadan son durumu okur.

    Cizgi izleme dongusu 30 Hz doner, LiDAR 10 Hz uretir. Ana dongude
    next(taramalar()) cagirirsan cizgi takibi LiDAR'i beklemeye baslar ve
    direksiyon gecikir. Bu yuzden ayri is parcacigi.
    """

    def __init__(self, port=None, baud=460800, bayat_s=0.7, **guv):
        self.guvenlik = Guvenlik(**guv)
        self.port = port
        self.baud = baud
        self.bayat_s = bayat_s           # bu kadar veri gelmezse guvenli tarafa gec
        self._son = {"durum": "SERBEST", "hiz_carpani": 1.0,
                     "en_yakin_m": float("inf"), "koridor_nokta": 0}
        self._zaman = 0.0
        self._kilit = threading.Lock()
        self._calis = True
        self.hata = None
        self._is = threading.Thread(target=self._dongu, daemon=True)
        self._is.start()

    def _dongu(self):
        lid = None
        while self._calis:
            try:
                if lid is None:
                    p = self.port or c1.port_bul()
                    lid = c1.RPLidarC1(p, self.baud)
                for tur in lid.taramalar():
                    if not self._calis:
                        break
                    d = self.guvenlik.degerlendir(tur)
                    for agir in ("noktalar", "koridor_maske", "vurgu_maske"):
                        d.pop(agir, None)      # is parcaciklari arasi dizi tasima
                    with self._kilit:
                        self._son = d
                        self._zaman = time.monotonic()
            except Exception as e:
                self.hata = str(e)
                try:
                    if lid:
                        lid.kapat()
                except Exception:
                    pass
                lid = None
                time.sleep(1.0)              # baglantiyi yeniden kurmayi dene

    def durum(self):
        """Son durum. Veri bayatlamissa YAVAS'a duser -- sensor susarsa
        tam hizla devam etmek en tehlikeli davranistir."""
        with self._kilit:
            d = dict(self._son)
            yas = time.monotonic() - self._zaman if self._zaman else 1e9
        if yas > self.bayat_s:
            d.update(durum="YAVAS", hiz_carpani=HIZ_CARPANI["YAVAS"],
                     bayat=True, yas_s=yas)
        else:
            d.update(bayat=False, yas_s=yas)
        return d

    def kapat(self):
        self._calis = False


# ============================================================================
#  Gorsel -- videodaki ekran goruntusu bu
# ============================================================================
TUVAL = 720
RENK = {"SERBEST": (110, 220, 120), "YAVAS": (60, 200, 245), "DUR": (60, 60, 240)}


def cizim(sonuc, olcek_m, guv, fps=0.0):
    img = np.full((TUVAL, TUVAL, 3), (18, 18, 20), np.uint8)
    mer = TUVAL // 2
    px = (TUVAL / 2.0) / olcek_m
    durum = sonuc["durum"]
    renk = RENK[durum]

    for r in range(1, int(olcek_m) + 1):
        cv2.circle(img, (mer, mer), int(r * px), (52, 55, 60), 1, cv2.LINE_AA)
    cv2.line(img, (mer, 0), (mer, TUVAL), (52, 55, 60), 1)
    cv2.line(img, (0, mer), (TUVAL, mer), (52, 55, 60), 1)

    # Koridor: dur bolgesi dolu, yavas bolgesi cerceve
    g = int(guv.yari_genislik * px)
    kat = img.copy()
    cv2.rectangle(kat, (mer - g, mer - int(guv.dur * px)), (mer + g, mer),
                  renk, -1)
    cv2.addWeighted(kat, 0.28, img, 0.72, 0, img)
    cv2.rectangle(img, (mer - g, mer - int(guv.yavas * px)), (mer + g, mer),
                  (150, 150, 155), 1, cv2.LINE_AA)
    cv2.rectangle(img, (mer - g, mer - int(guv.dur * px)), (mer + g, mer),
                  renk, 2, cv2.LINE_AA)

    # Noktalar: karari veren noktalar durum renginde, digerleri sonuk
    P, vurgu = sonuc["noktalar"], sonuc["vurgu_maske"]
    for i in range(len(P)):
        x = mer + int(P[i, 0] * px)
        y = mer - int(P[i, 1] * px)
        if 0 <= x < TUVAL and 0 <= y < TUVAL:
            cv2.circle(img, (x, y), 3 if vurgu[i] else 1,
                       renk if vurgu[i] else (95, 150, 105), -1)

    cv2.circle(img, (mer, mer), 7, (240, 200, 80), -1, cv2.LINE_AA)
    cv2.arrowedLine(img, (mer, mer), (mer, mer - 30), (240, 200, 80), 2,
                    tipLength=0.35, line_type=cv2.LINE_AA)

    # Durum afisi
    cv2.rectangle(img, (0, 0), (TUVAL, 62), (28, 28, 32), -1)
    cv2.putText(img, durum, (16, 46), cv2.FONT_HERSHEY_SIMPLEX, 1.4, renk, 3,
                cv2.LINE_AA)
    ey = sonuc["en_yakin_m"]
    ey_s = f"{ey*100:5.0f} cm" if np.isfinite(ey) else "  ---  "
    cv2.putText(img, f"en yakin {ey_s}    hiz x{sonuc['hiz_carpani']:.1f}"
                     f"    {sonuc['ilgili_nokta']:3d} nokta    {fps:4.1f} tur/s",
                (250, 40), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (225, 225, 225), 1,
                cv2.LINE_AA)
    cv2.putText(img, f"koridor {guv.yari_genislik*200:.0f} cm genis   "
                     f"DUR<{guv.dur*100:.0f}cm   YAVAS<{guv.yavas*100:.0f}cm"
                     f"    |    q cikis  +/- olcek",
                (14, TUVAL - 14), cv2.FONT_HERSHEY_SIMPLEX, 0.45,
                (145, 145, 150), 1, cv2.LINE_AA)
    return img


# ============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=460800)
    ap.add_argument("--sahte", action="store_true", help="LiDAR olmadan dene")
    ap.add_argument("--oynat", default=None)
    ap.add_argument("--genislik", type=float, default=0.60,
                    help="koridor TAM genisligi, m (arac genisligi + pay)")
    ap.add_argument("--dur", type=float, default=0.40, help="dur mesafesi, m")
    ap.add_argument("--yavas", type=float, default=0.90, help="yavasla mesafesi, m")
    ap.add_argument("--min-nokta", type=int, default=2)
    ap.add_argument("--kor", default="", help="kor acilar, orn: 160-200,340-20")
    ap.add_argument("--olcek", type=float, default=3.0)
    ap.add_argument("--kare-yaz", default=None, help="tek kare PNG yazip cik")
    args = ap.parse_args()

    if cv2 is None:
        print("opencv gerekli:  pip install opencv-python")
        return 1

    kor = []
    for parca in filter(None, args.kor.split(",")):
        a, b = parca.split("-")
        kor.append((float(a), float(b)))

    guv = Guvenlik(yari_genislik_m=args.genislik / 2.0, dur_m=args.dur,
                   yavas_m=args.yavas, min_nokta=args.min_nokta, kor_acilar=kor)

    lid = None
    if args.oynat:
        veri = np.load(args.oynat, allow_pickle=True)
        turlar = list(veri["turlar"])
        kaynak = ("oynat", turlar)
        print(f"[OYNAT] {args.oynat}: {len(turlar)} tur")
    elif args.sahte:
        import goster
        kaynak = ("sahte", goster.sahte_oda)
        print("[SAHTE] Sentetik oda. Onune bir sey girince DUR olmali.")
    else:
        port = args.port or c1.port_bul()
        if port is None:
            print("[HATA] Seri port yok. Denemek icin:  python guvenlik.py --sahte")
            return 1
        print(f"[BAGLAN] {port} @ {args.baud}")
        lid = c1.RPLidarC1(port, args.baud)
        try:
            print(f"[BILGI]  {lid.bilgi()}")
        except c1.LidarHatasi as e:
            print(f"[UYARI] {e}")
        kaynak = ("canli", lid.taramalar())

    if args.kare_yaz:
        tur = (kaynak[1](40) if kaynak[0] == "sahte"
               else kaynak[1][0] if kaynak[0] == "oynat" else next(kaynak[1]))
        cv2.imwrite(args.kare_yaz, cizim(guv.degerlendir(tur), args.olcek, guv, 10.0))
        print(f"[YAZILDI] {args.kare_yaz}")
        if lid:
            lid.kapat()
        return 0

    pencere = "LiDAR GUVENLIK BOLGESI"
    cv2.namedWindow(pencere)
    olcek, kare, fps, son = args.olcek, 0, 0.0, time.monotonic()
    onceki_durum = None
    try:
        while True:
            if kaynak[0] == "sahte":
                tur = kaynak[1](kare); time.sleep(0.1)
            elif kaynak[0] == "oynat":
                tur = kaynak[1][kare % len(kaynak[1])]; time.sleep(0.1)
            else:
                tur = next(kaynak[1])
            kare += 1
            simdi = time.monotonic()
            dt = simdi - son; son = simdi
            if dt > 0:
                fps += 0.2 * (1.0 / dt - fps)

            s = guv.degerlendir(tur)
            if s["durum"] != onceki_durum:
                ey = s["en_yakin_m"]
                print(f"[{s['durum']:8s}] en yakin "
                      f"{ey*100:.0f} cm" if np.isfinite(ey) else
                      f"[{s['durum']:8s}] koridor bos")
                onceki_durum = s["durum"]

            cv2.imshow(pencere, cizim(s, olcek, guv, fps))
            t = cv2.waitKey(1) & 0xFF
            if t == ord("q"):
                break
            elif t in (ord("+"), ord("=")):
                olcek = max(1.0, olcek - 0.5)
            elif t == ord("-"):
                olcek = min(12.0, olcek + 0.5)
    except (KeyboardInterrupt, StopIteration):
        pass
    except c1.LidarHatasi as e:
        print(f"[HATA] {e}")
    finally:
        if lid:
            lid.kapat()
        cv2.destroyAllWindows()
    return 0


if __name__ == "__main__":
    sys.exit(main())
