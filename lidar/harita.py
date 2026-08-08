#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""2D harita cikarma -- tek tarama ve gezerek (ICP tabanli SLAM).

    python3 harita.py --tek                # odanin ortasinda tek tarama -> harita
    python3 harita.py --slam               # LiDAR'i gezdir, harita buyusun
    python3 harita.py --sahte --slam       # LiDAR YOKKEN sentetik odada dene
    python3 harita.py --oynat oda1.npz     # kayittan harita cikar

Cikti: harita.png (gorsel) + harita.npz (izgara + olcek + poz gecmisi)

NASIL CALISIR
  1) Her tarama, sensor merkezli (x, y) nokta bulutuna cevrilir.
  2) SLAM modunda yeni tarama, o ana kadar biriken haritaya ICP ile
     oturtulur -> sensorun ne kadar hareket ettigi cikar. (Tekerlek
     enkoderi olmadan "odometri" boyle uretilir; kayma da buradan gelir.)
  3) Isgal izgarasi log-odds ile guncellenir: taramanin cevreledigi alan
     BOS, isin uclari DOLU.

ICP nedir: iki nokta bulutunu ust uste getiren donme+oteleme'yi bulur.
Her adimda en yakin komsulari eslestirir, en iyi katı donusumu (Kabsch/SVD)
hesaplar, uygular ve tekrarlar.
"""

import argparse
import os
import sys
import time

import numpy as np

try:
    import cv2
except ImportError:
    cv2 = None
try:
    from scipy.spatial import cKDTree
except ImportError:
    cKDTree = None

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import c1
import goster as gos


# ============================================================================
#  Tarama -> nokta bulutu
# ============================================================================
# Tarama acisinin dondugu yon. Gercek cihazda ters cikarsa harita AYNA olur
# (oda dogru boyutta ama sag/sol takas). Haritan aynaysa bunu -1 yap.
ACI_YONU = +1


def tarama_xy(tur, min_m=0.10, max_m=12.0):
    """[(aci_derece, mesafe_mm, kalite)] -> (N,2) metre cinsinden nokta bulutu.

    Sensor cercevesi: +Y ileri (LiDAR 0 derece), +X saga.
    """
    if not tur:
        return np.empty((0, 2))
    a = np.array([t[0] for t in tur], float)
    m = np.array([t[1] for t in tur], float) / 1000.0
    gecerli = (m >= min_m) & (m <= max_m)
    a, m = a[gecerli], m[gecerli]
    r = np.radians(a) * ACI_YONU
    return np.stack([m * np.sin(r), m * np.cos(r)], axis=1)


def donusum(dx, dy, teta):
    c, s = np.cos(teta), np.sin(teta)
    return np.array([[c, -s, dx], [s, c, dy], [0, 0, 1.0]])


def uygula(T, P):
    if len(P) == 0:
        return P
    return (P @ T[:2, :2].T) + T[:2, 2]


# ============================================================================
#  ICP
# ============================================================================
class Eslestirici:
    """Nokta bulutu hizalama (point-to-point ICP)."""

    def __init__(self, max_eslesme_m=0.45, iterasyon=25, yakinsama=1e-4):
        self.max_eslesme = max_eslesme_m
        self.iterasyon = iterasyon
        self.yakinsama = yakinsama

    @staticmethod
    def _en_yakin(agac, hedef, P):
        if agac is not None:
            d, i = agac.query(P)
            return d, i
        # scipy yoksa kaba kuvvet (kucuk bulutlarda yeterli)
        fark = P[:, None, :] - hedef[None, :, :]
        d2 = np.einsum("ijk,ijk->ij", fark, fark)
        i = np.argmin(d2, axis=1)
        return np.sqrt(d2[np.arange(len(P)), i]), i

    def hizala(self, kaynak, hedef, T0=None):
        """kaynak'i hedef'e oturtan donusumu bulur. (T, ortalama_hata, oran)"""
        if len(kaynak) < 10 or len(hedef) < 10:
            return (T0 if T0 is not None else np.eye(3)), np.inf, 0.0

        agac = cKDTree(hedef) if cKDTree is not None else None
        T = np.eye(3) if T0 is None else T0.copy()
        P = uygula(T, kaynak)
        onceki = np.inf
        hata, oran = np.inf, 0.0

        for _ in range(self.iterasyon):
            d, idx = self._en_yakin(agac, hedef, P)
            iyi = d < self.max_eslesme
            if iyi.sum() < 10:
                break
            A = P[iyi]
            B = hedef[idx[iyi]]
            # Kabsch: agirlik merkezlerini cakistir, SVD ile donmeyi bul
            ma, mb = A.mean(0), B.mean(0)
            H = (A - ma).T @ (B - mb)
            U, _, Vt = np.linalg.svd(H)
            R = Vt.T @ U.T
            if np.linalg.det(R) < 0:                  # yansimayi engelle
                Vt[1, :] *= -1
                R = Vt.T @ U.T
            t = mb - R @ ma
            adim = np.eye(3)
            adim[:2, :2] = R
            adim[:2, 2] = t
            T = adim @ T
            P = uygula(adim, P)

            hata = float(d[iyi].mean())
            oran = float(iyi.mean())
            if abs(onceki - hata) < self.yakinsama:
                break
            onceki = hata
        return T, hata, oran


# ============================================================================
#  Isgal izgarasi
# ============================================================================
class Izgara:
    """Log-odds isgal izgarasi. Deger > 0 dolu, < 0 bos, 0 bilinmiyor."""

    def __init__(self, boyut_m=14.0, cozunurluk_m=0.03,
                 dolu_kazanc=0.85, bos_kazanc=0.30, sinir=5.0):
        self.coz = cozunurluk_m
        self.n = int(boyut_m / cozunurluk_m)
        self.izgara = np.zeros((self.n, self.n), np.float32)
        self.merkez = self.n // 2
        self.dolu_kazanc = dolu_kazanc
        self.bos_kazanc = bos_kazanc
        self.sinir = sinir

    def hucre(self, P):
        """(N,2) metre -> (N,2) tamsayi hucre (satir, sutun)."""
        s = self.merkez - np.round(P[:, 1] / self.coz).astype(int)   # +Y yukari
        u = self.merkez + np.round(P[:, 0] / self.coz).astype(int)
        return s, u

    def ekle(self, dunya_noktalar, sensor_xy):
        """Bir taramayi haritaya isle.

        BOS alan: taramanin uclarinin olusturdugu poligonun ici. 360 derece
        tarama icin bu tam olarak gorulen serbest bolgedir -- her isini tek tek
        Bresenham ile yurumekten cok daha hizli ve ayni sonucu verir.
        """
        if len(dunya_noktalar) < 3 or cv2 is None:
            return
        s, u = self.hucre(dunya_noktalar)
        ic = (s >= 0) & (s < self.n) & (u >= 0) & (u < self.n)
        s, u = s[ic], u[ic]
        if len(s) < 3:
            return

        maske = np.zeros((self.n, self.n), np.uint8)
        poligon = np.stack([u, s], axis=1).astype(np.int32)
        cv2.fillPoly(maske, [poligon], 1)
        self.izgara[maske > 0] -= self.bos_kazanc          # gorulen alan bos
        self.izgara[s, u] += self.dolu_kazanc + self.bos_kazanc   # uclar dolu
        np.clip(self.izgara, -self.sinir, self.sinir, out=self.izgara)

    def noktalar(self, esik=0.6):
        """Haritadaki dolu hucreleri metre cinsinden nokta bulutu olarak verir."""
        s, u = np.nonzero(self.izgara > esik)
        if len(s) == 0:
            return np.empty((0, 2))
        return np.stack([(u - self.merkez) * self.coz,
                         (self.merkez - s) * self.coz], axis=1)

    def gorsel(self, pozlar=None, olcek_cizgisi=True):
        """Harita gorseli: beyaz=bos, siyah=dolu, gri=bilinmiyor."""
        img = np.full((self.n, self.n, 3), 128, np.uint8)
        # Esik -0.3 DEGIL: tek tarama sonrasi deger tam olarak -bos_kazanc
        # (-0.30) olur ve "< -0.3" kil payi False doner -> --tek modunda harita
        # bombos gorunurdu.
        img[self.izgara < -0.05] = (245, 245, 245)
        # Duvarlar tek hucre kalinligindadir; kucultulmus goruntude kaybolur.
        # SADECE GORSELDE kalinlastiriyoruz -- izgara verisi degismiyor.
        dolu = (self.izgara > 0.6).astype(np.uint8)
        if cv2 is not None and dolu.any():
            dolu = cv2.dilate(dolu, np.ones((3, 3), np.uint8))
        img[dolu > 0] = (25, 25, 28)

        if olcek_cizgisi:
            adim = int(1.0 / self.coz)                    # 1 m
            for k in range(-self.n // 2 // adim, self.n // 2 // adim + 1):
                p = self.merkez + k * adim
                if 0 <= p < self.n:
                    cv2.line(img, (p, 0), (p, self.n), (200, 200, 205), 1)
                    cv2.line(img, (0, p), (self.n, p), (200, 200, 205), 1)

        if pozlar is not None and len(pozlar) > 1:
            yol = np.array([[self.merkez + int(round(x / self.coz)),
                             self.merkez - int(round(y / self.coz))]
                            for x, y, _ in pozlar], np.int32)
            cv2.polylines(img, [yol], False, (60, 120, 240), 2, cv2.LINE_AA)
            sx, sy, _ = pozlar[-1]
            cv2.circle(img, (self.merkez + int(round(sx / self.coz)),
                             self.merkez - int(round(sy / self.coz))),
                       5, (40, 90, 230), -1, cv2.LINE_AA)
        return img

    # ----------------------------------------------------------------- sunum
    def sunum(self, pozlar=None, baslik="ODA HARITASI", altbilgi="",
              hedef_px=1400, pay_m=0.6, esik=0.6):
        """Rapor/sunum icin olculendirilmis harita.

        gorsel() ham izgarayi 1:1 basar: 14 m'lik tuvalin ortasinda 4 m'lik bir
        oda kucucuk kalir ve duvarlar tek piksel olur. Burada haritanin DOLU
        oldugu bolgeye kirpip buyutuyoruz, metre izgarasi + olcek + olculer
        ekliyoruz. Izgara verisine dokunulmuyor, sadece cizim.

        NOT: OpenCV yazi tipleri Turkce karakter basmaz; etiketler ASCII.
        """
        if cv2 is None:
            return self.gorsel(pozlar)

        dolu_m = self.izgara > esik
        bilinen = dolu_m | (self.izgara < -0.05)
        if not bilinen.any():
            return self.gorsel(pozlar)

        # --- haritanin dolu oldugu kare pencereye kirp ---
        s_i, u_i = np.nonzero(bilinen)
        pay = int(round(pay_m / self.coz))
        s0, s1 = s_i.min() - pay, s_i.max() + pay
        u0, u1 = u_i.min() - pay, u_i.max() + pay
        k = max(s1 - s0 + 1, u1 - u0 + 1)
        sm, um = (s0 + s1) // 2, (u0 + u1) // 2          # pencere merkezi
        s0 = int(np.clip(sm - k // 2, 0, max(0, self.n - k)))
        u0 = int(np.clip(um - k // 2, 0, max(0, self.n - k)))
        k = min(k, self.n)
        alt = self.izgara[s0:s0 + k, u0:u0 + k]

        # --- renklendir, buyut ---
        harita = np.full((k, k, 3), 168, np.uint8)              # bilinmiyor
        harita[alt < -0.05] = (250, 250, 250)                   # bos
        olcek = hedef_px / float(k)                             # piksel / hucre
        harita = cv2.resize(harita, (hedef_px, hedef_px),
                            interpolation=cv2.INTER_NEAREST)
        # Duvarlari buyutulmus goruntude kalinlastir: 1 hucre kalinliginda dursun
        duvar = (alt > esik).astype(np.uint8) * 255
        duvar = cv2.resize(duvar, (hedef_px, hedef_px),
                           interpolation=cv2.INTER_NEAREST)
        kal = max(2, int(round(olcek * 0.9)))
        duvar = cv2.dilate(duvar, np.ones((kal, kal), np.uint8))
        harita[duvar > 0] = (32, 32, 38)

        px_m = olcek / self.coz                                  # piksel / metre

        def ekran(x_m, y_m):
            """Dunya metre -> sunum goruntusu pikseli."""
            return (int(round((self.merkez + x_m / self.coz - u0) * olcek)),
                    int(round((self.merkez - y_m / self.coz - s0) * olcek)))

        # --- metre izgarasi ve etiketler ---
        x_min = (u0 - self.merkez) * self.coz
        y_max = (self.merkez - s0) * self.coz
        for m in range(int(np.ceil(x_min)), int(x_min + k * self.coz) + 1):
            px, _ = ekran(m, 0)
            if 0 <= px < hedef_px:
                cv2.line(harita, (px, 0), (px, hedef_px),
                         (205, 205, 212), 1 if m else 2, cv2.LINE_AA)
                cv2.putText(harita, f"{m}m", (px + 4, hedef_px - 8),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.42, (110, 110, 118), 1,
                            cv2.LINE_AA)
        for m in range(int(np.ceil(y_max - k * self.coz)), int(y_max) + 1):
            _, py = ekran(0, m)
            if 0 <= py < hedef_px:
                cv2.line(harita, (0, py), (hedef_px, py),
                         (205, 205, 212), 1 if m else 2, cv2.LINE_AA)
                cv2.putText(harita, f"{m}m", (6, py - 5),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.42, (110, 110, 118), 1,
                            cv2.LINE_AA)

        # --- gezilen yol + baslangic/bitis ---
        if pozlar is not None and len(pozlar) > 1:
            yol = np.array([ekran(x, y) for x, y, _ in pozlar], np.int32)
            cv2.polylines(harita, [yol], False, (70, 130, 245), 3, cv2.LINE_AA)
            cv2.circle(harita, tuple(yol[0]), 9, (90, 175, 90), -1, cv2.LINE_AA)
            cv2.circle(harita, tuple(yol[-1]), 9, (45, 90, 235), -1, cv2.LINE_AA)
        else:
            cv2.circle(harita, ekran(0, 0), 9, (45, 90, 235), -1, cv2.LINE_AA)

        # --- olculer ---
        nk = self.noktalar(esik=esik)
        en = float(np.ptp(nk[:, 0])) if len(nk) else 0.0
        boy = float(np.ptp(nk[:, 1])) if len(nk) else 0.0

        # --- cerceve: baslik ust, aciklama alt ---
        UST, ALT, YAN = 74, 116, 34
        tuval = np.full((hedef_px + UST + ALT, hedef_px + 2 * YAN, 3), 255,
                        np.uint8)
        tuval[0:UST, :] = (38, 40, 46)
        tuval[UST:UST + hedef_px, YAN:YAN + hedef_px] = harita
        cv2.rectangle(tuval, (YAN, UST), (YAN + hedef_px, UST + hedef_px),
                      (90, 90, 96), 2)

        cv2.putText(tuval, baslik, (YAN, 48), cv2.FONT_HERSHEY_SIMPLEX, 1.0,
                    (255, 255, 255), 2, cv2.LINE_AA)
        cv2.putText(tuval, "RPLIDAR C1  |  460800 baud  |  10 Hz",
                    (tuval.shape[1] - 470, 46), cv2.FONT_HERSHEY_SIMPLEX, 0.55,
                    (185, 190, 200), 1, cv2.LINE_AA)

        ty = UST + hedef_px + 34
        cv2.putText(tuval, f"Olculen alan: {en:.2f} m x {boy:.2f} m",
                    (YAN, ty), cv2.FONT_HERSHEY_SIMPLEX, 0.72, (25, 25, 30), 2,
                    cv2.LINE_AA)
        if altbilgi:
            cv2.putText(tuval, altbilgi, (YAN, ty + 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.5, (95, 95, 105), 1,
                        cv2.LINE_AA)

        # --- gosterge (legend) ---
        lx = YAN + int(hedef_px * 0.42)
        for i, (renk, yazi) in enumerate([((32, 32, 38), "duvar / engel"),
                                          ((250, 250, 250), "serbest alan"),
                                          ((168, 168, 168), "bilinmiyor"),
                                          ((70, 130, 245), "sensor / yol")]):
            yy = ty - 14 + (i // 2) * 30
            xx = lx + (i % 2) * 230
            cv2.rectangle(tuval, (xx, yy), (xx + 22, yy + 16), renk, -1)
            cv2.rectangle(tuval, (xx, yy), (xx + 22, yy + 16), (140, 140, 145), 1)
            cv2.putText(tuval, yazi, (xx + 30, yy + 14),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.46, (55, 55, 62), 1,
                        cv2.LINE_AA)

        # --- olcek cubugu (1 m) ---
        bx = tuval.shape[1] - YAN - int(px_m) - 10
        by = ty + 6
        cv2.line(tuval, (bx, by), (bx + int(px_m), by), (25, 25, 30), 4)
        for ux in (bx, bx + int(px_m)):
            cv2.line(tuval, (ux, by - 8), (ux, by + 8), (25, 25, 30), 3)
        cv2.putText(tuval, "1 metre", (bx + int(px_m) // 2 - 34, by + 30),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (25, 25, 30), 1, cv2.LINE_AA)
        return tuval


# ============================================================================
#  SLAM
# ============================================================================
class Slam:
    def __init__(self, izgara=None, eslestirici=None,
                 anahtar_mesafe_m=0.25, anahtar_aci_derece=12.0):
        self.izgara = izgara or Izgara()
        self.esl = eslestirici or Eslestirici()
        self.poz = np.eye(3)                  # dunya <- sensor
        self.pozlar = [(0.0, 0.0, 0.0)]
        self.anahtar_mesafe = anahtar_mesafe_m
        self.anahtar_aci = np.radians(anahtar_aci_derece)
        self.son_anahtar = np.eye(3)
        self.harita_noktalar = None
        self.son_hata = 0.0
        self.son_oran = 0.0

    @staticmethod
    def _poz_ayikla(T):
        return float(T[0, 2]), float(T[1, 2]), float(np.arctan2(T[1, 0], T[0, 0]))

    def adim(self, tur, hiz_tahmini=None):
        """Bir tarama isle. (basarili, x, y, teta) doner."""
        P = tarama_xy(tur)
        if len(P) < 20:
            return False, *self._poz_ayikla(self.poz)

        if self.harita_noktalar is None or len(self.harita_noktalar) < 50:
            # Ilk tarama: haritayi baslat, poz baslangic noktasi
            self.izgara.ekle(uygula(self.poz, P), self.poz[:2, 2])
            self.harita_noktalar = self.izgara.noktalar()
            return True, *self._poz_ayikla(self.poz)

        # Tahmin: bir onceki hareketi tekrar et (sabit hiz varsayimi)
        T0 = self.poz if hiz_tahmini is None else hiz_tahmini @ self.poz
        T, hata, oran = self.esl.hizala(P, self.harita_noktalar, T0)
        self.son_hata, self.son_oran = hata, oran

        # Kotu eslesme -> guvenme, poz sabit kalsin (yanlis poz haritayi bozar)
        if oran < 0.35 or not np.isfinite(hata):
            return False, *self._poz_ayikla(self.poz)

        self.poz = T
        self.pozlar.append(self._poz_ayikla(T))

        # Anahtar kare: yeterince hareket ettiysek haritaya isle
        d = self.poz[:2, 2] - self.son_anahtar[:2, 2]
        daci = abs(np.arctan2(self.poz[1, 0], self.poz[0, 0])
                   - np.arctan2(self.son_anahtar[1, 0], self.son_anahtar[0, 0]))
        if np.hypot(*d) > self.anahtar_mesafe or daci > self.anahtar_aci:
            self.izgara.ekle(uygula(self.poz, P), self.poz[:2, 2])
            self.harita_noktalar = self.izgara.noktalar()
            self.son_anahtar = self.poz.copy()
        return True, *self._poz_ayikla(self.poz)


# ============================================================================
#  Ana program
# ============================================================================
def kaynak_ac(args):
    """(tip, ureteci_veya_liste, lidar) doner."""
    if args.oynat:
        veri = np.load(args.oynat, allow_pickle=True)
        turlar = list(veri["turlar"])
        print(f"[OYNAT] {args.oynat}: {len(turlar)} tur")
        return "liste", turlar, None
    if args.sahte:
        print("[SAHTE] Sentetik oda")
        return "sahte", None, None
    port = args.port or c1.port_bul()
    if port is None:
        print("[HATA] Seri port yok. Deneme icin:  python3 harita.py --sahte --slam")
        return None, None, None
    print(f"[BAGLAN] {port} @ {args.baud}")
    lid = c1.RPLidarC1(port, args.baud)
    try:
        print(f"[SAGLIK] {lid.saglik()['metin']}")
    except c1.LidarHatasi:
        pass
    return "canli", lid.taramalar(), lid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=460800)
    ap.add_argument("--tek", action="store_true", help="tek tarama -> harita")
    ap.add_argument("--slam", action="store_true", help="gezerek harita cikar")
    ap.add_argument("--sahte", action="store_true")
    ap.add_argument("--oynat", default=None)
    ap.add_argument("--cikti", default="harita", help="cikti dosya adi (uzantisiz)")
    ap.add_argument("--boyut", type=float, default=14.0, help="harita kenari (m)")
    ap.add_argument("--coz", type=float, default=0.03, help="hucre boyu (m)")
    ap.add_argument("--ortalama", type=int, default=5,
                    help="--tek modunda kac tarama ortalanacak")
    ap.add_argument("--baslik", default=None,
                    help="sunum haritasinin basligi (rapora koyarken)")
    args = ap.parse_args()

    if cv2 is None:
        print("opencv gerekli:  pip install opencv-python")
        return 1
    if not (args.tek or args.slam):
        args.tek = True

    tip, kaynak, lid = kaynak_ac(args)
    if tip is None:
        return 1

    def sonraki(i):
        if tip == "sahte":
            return gos.sahte_oda(i)
        if tip == "liste":
            return kaynak[i % len(kaynak)]
        return next(kaynak)

    izgara = Izgara(args.boyut, args.coz)

    def sunum_yaz(izg, pozlar, aciklama):
        """Rapora konacak olculendirilmis haritayi yazar."""
        yol = args.cikti + "_sunum.png"
        baslik = args.baslik or ("ODA HARITASI - TEK TARAMA" if args.tek
                                 else "ODA HARITASI - SLAM (GEZEREK)")
        alt = (f"{aciklama}   |   hucre {args.coz*100:.0f} cm   |   "
               f"{time.strftime('%d.%m.%Y %H:%M')}")
        cv2.imwrite(yol, izg.sunum(pozlar, baslik=baslik, altbilgi=alt))
        print(f"[SUNUM] {yol}  <- rapora/sunuma bunu koy")

    try:
        # ------------------------------------------------ TEK TARAMA
        if args.tek:
            print(f"[TEK] {args.ortalama} tarama toplaniyor... (sabit dur)")
            hepsi = []
            for i in range(args.ortalama):
                tur = sonraki(i)
                hepsi.extend(tur)
                print(f"   tarama {i+1}/{args.ortalama}: {len(tur)} nokta")
            P = tarama_xy(hepsi)
            izgara.ekle(P, np.zeros(2))
            img = izgara.gorsel(pozlar=[(0.0, 0.0, 0.0), (0.0, 0.0, 0.0)])
            cv2.imwrite(args.cikti + ".png", img)
            np.savez_compressed(args.cikti + ".npz",
                                izgara=izgara.izgara, coz=izgara.coz,
                                pozlar=np.array([[0.0, 0.0, 0.0]]))
            en, boy = np.ptp(P[:, 0]), np.ptp(P[:, 1])
            sunum_yaz(izgara, None,
                      f"{args.ortalama} tarama ortalandi, {len(P)} nokta")
            print(f"[BITTI] {args.cikti}.png yazildi")
            print(f"        {len(P)} nokta | odanin kapladigi alan "
                  f"~{en:.2f} x {boy:.2f} m")
            return 0

        # ------------------------------------------------ SLAM
        slam = Slam(izgara)
        pencere = "HARITA  (q: cikis, s: kaydet)"
        cv2.namedWindow(pencere)
        i = 0
        onceki_poz = np.eye(3)
        son_yaz = time.monotonic()
        while True:
            tur = sonraki(i)
            i += 1
            hiz = slam.poz @ np.linalg.inv(onceki_poz)
            onceki_poz = slam.poz.copy()
            ok, x, y, teta = slam.adim(tur, hiz_tahmini=hiz)

            if time.monotonic() - son_yaz > 0.08:
                son_yaz = time.monotonic()
                img = slam.izgara.gorsel(slam.pozlar)
                durum = (f"tarama {i}  poz ({x:+.2f}, {y:+.2f}) m  "
                         f"{np.degrees(teta):+6.1f} deg   "
                         f"ICP hata {slam.son_hata*100:.1f} cm  "
                         f"eslesme %{slam.son_oran*100:.0f}")
                if not ok:
                    durum += "   [HIZALANAMADI]"
                cv2.putText(img, durum, (10, 22), cv2.FONT_HERSHEY_SIMPLEX,
                            0.45, (30, 30, 30), 2, cv2.LINE_AA)
                cv2.putText(img, durum, (10, 22), cv2.FONT_HERSHEY_SIMPLEX,
                            0.45, (240, 240, 240), 1, cv2.LINE_AA)
                cv2.imshow(pencere, img)

            t = cv2.waitKey(1) & 0xFF
            if t == ord("q"):
                break
            if t == ord("s"):
                cv2.imwrite(args.cikti + ".png", slam.izgara.gorsel(slam.pozlar))
                print(f"[KAYDEDILDI] {args.cikti}.png")

        cv2.imwrite(args.cikti + ".png", slam.izgara.gorsel(slam.pozlar))
        np.savez_compressed(args.cikti + ".npz",
                            izgara=slam.izgara.izgara, coz=slam.izgara.coz,
                            pozlar=np.array(slam.pozlar))
        yol_m = sum(float(np.hypot(b[0] - a[0], b[1] - a[1]))
                    for a, b in zip(slam.pozlar, slam.pozlar[1:]))
        sunum_yaz(slam.izgara, slam.pozlar,
                  f"{len(slam.pozlar)} poz, {yol_m:.1f} m guzergah, "
                  f"son eslesme %{slam.son_oran*100:.0f}")
        print(f"[BITTI] {args.cikti}.png / .npz  ({len(slam.pozlar)} poz)")

    except (KeyboardInterrupt, StopIteration):
        print("\n[DURDURULDU]")
    except c1.LidarHatasi as e:
        print(f"[HATA] {e}")
    finally:
        if lid:
            lid.kapat()
        # Ekransiz makinede (SSH / sunucu / --tek modu) GUI derlenmemis olabilir;
        # dosyalar yazildiktan SONRA burada cokmesin.
        try:
            cv2.destroyAllWindows()
        except cv2.error:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
