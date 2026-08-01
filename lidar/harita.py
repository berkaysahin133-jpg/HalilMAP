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
        print(f"[BITTI] {args.cikti}.png / .npz  ({len(slam.pozlar)} poz)")

    except (KeyboardInterrupt, StopIteration):
        print("\n[DURDURULDU]")
    except c1.LidarHatasi as e:
        print(f"[HATA] {e}")
    finally:
        if lid:
            lid.kapat()
        cv2.destroyAllWindows()
    return 0


if __name__ == "__main__":
    sys.exit(main())
