# -*- coding: utf-8 -*-
"""Pist simulatoru: robot olmadan kapali cevrim test ve ayar.

Ne ise yarar:
  Pistin gercek videosu olmadan da algoritmayi kosturup OLCEBILIRSIN.
  Gercek pozisyonu bildigimiz icin "sapma kac mm" sorusunun kesin cevabi var.
  Ayar yaparken once burada dogrula, sonra robota tasi -- 11 gunde en hizli yol.

Icerik:
    Pist        : dunya koordinatlarinda cizgi (duz / yay / 90 kose)
    Kamera      : perspektif izdusum (persfektif.py ile ayni model)
    Arac        : diferansiyel surus kinematigi
"""

import numpy as np
import cv2


# ============================================================================
#  PIST
# ============================================================================
def pist_duz(uzunluk=300.0, adim=1.0):
    Y = np.arange(0, uzunluk, adim)
    return np.stack([np.zeros_like(Y), Y], axis=1)


def pist_yay(yaricap=80.0, aci_derece=90.0, giris=60.0, cikis=60.0, adim=1.0, sag=True):
    """Duz -> yay -> duz. Yumusak viraj testi."""
    p = [np.stack([np.zeros(int(giris / adim)),
                   np.arange(0, giris, adim)], axis=1)]
    aci = np.radians(aci_derece)
    n = max(2, int(yaricap * aci / adim))
    t = np.linspace(0, aci, n)
    isaret = 1.0 if sag else -1.0
    X = isaret * yaricap * (1 - np.cos(t))
    Y = giris + yaricap * np.sin(t)
    p.append(np.stack([X, Y], axis=1))

    # Yay cikisindaki teget yonunde duz devam
    yon = np.array([isaret * np.sin(aci), np.cos(aci)])
    son = p[-1][-1]
    m = np.arange(adim, cikis, adim)[:, None]
    p.append(son + m * yon)
    return np.vstack(p)


def pist_kose(giris=90.0, cikis=90.0, adim=1.0, sag=True):
    """90 derece keskin L kosesi -- kose tespitinin ana testi."""
    isaret = 1.0 if sag else -1.0
    dikey = np.stack([np.zeros(int(giris / adim)), np.arange(0, giris, adim)], axis=1)
    yatay = np.stack([isaret * np.arange(0, cikis, adim),
                      np.full(int(cikis / adim), giris)], axis=1)
    return np.vstack([dikey, yatay])


# ============================================================================
#  KAMERA (persfektif.py ile ayni izdusum modeli)
# ============================================================================
class SimKamera:
    def __init__(self, per_ayar, kam_ayar):
        self.w = kam_ayar.islem_genislik
        self.h = kam_ayar.islem_yukseklik
        self.f = (self.w / 2.0) / np.tan(np.radians(per_ayar.yatay_fov_derece) / 2.0)
        self.cu, self.cv = self.w / 2.0, self.h / 2.0
        self.teta = np.radians(per_ayar.egim_derece)
        self.yukseklik = per_ayar.kamera_yuksekligi_cm

    def izdusum(self, XY):
        """Arac cerçevesindeki (N,2) yer noktalarini goruntu pikseline cevirir.

        Kameranin arkasinda/ufkun ustunde kalanlar NaN doner.
        """
        XY = np.asarray(XY, float).reshape(-1, 2)
        dx, dy = XY[:, 0], XY[:, 1]
        dz = -self.yukseklik
        st, ct = np.sin(self.teta), np.cos(self.teta)

        xc = dx
        yc = -dy * st - dz * ct
        zc = dy * ct - dz * st

        gecerli = zc > 1e-3
        u = np.full_like(dx, np.nan)
        v = np.full_like(dx, np.nan)
        u[gecerli] = self.cu + self.f * xc[gecerli] / zc[gecerli]
        v[gecerli] = self.cv + self.f * yc[gecerli] / zc[gecerli]
        return np.stack([u, v], axis=1)


# ============================================================================
#  SAHNE CIZIMI
# ============================================================================
class Sahne:
    def __init__(self, pist_xy, sim_kamera, cizgi_genislik_cm=2.5,
                 zemin=200, cizgi=35, gurultu=4.0):
        self.pist = np.asarray(pist_xy, float)
        self.kam = sim_kamera
        self.genislik = cizgi_genislik_cm
        self.zemin = zemin
        self.cizgi = cizgi
        self.gurultu = gurultu
        self._isik = self._isik_haritasi()

    def _isik_haritasi(self):
        """Esit olmayan salon aydinlatmasi: bir kose parlak, bir kose golgede.

        Sabit esikli algoritmalar tam olarak bunun yuzunden cokuyor.
        """
        h, w = self.kam.h, self.kam.w
        yy, xx = np.mgrid[0:h, 0:w].astype(np.float32)
        egim = 0.55 + 0.45 * (xx / w) + 0.25 * (1.0 - yy / h)
        return np.clip(egim, 0.35, 1.35)

    def _arac_cercevesi(self, poz):
        """Dunya pistini arac cercevesine tasi. poz = (X, Y, teta)."""
        X, Y, teta = poz
        d = self.pist - np.array([X, Y])
        # teta: +Y ekseninden saga (+X) dogru pozitif.
        # Arac eksenleri (dunya cinsinden):
        #   ileri = ( sin t, cos t)      sag = ( cos t, -sin t)
        # Nokta arac cercevesinde: x_r = d . sag,  y_r = d . ileri
        c, s = np.cos(teta), np.sin(teta)
        xr = d[:, 0] * c - d[:, 1] * s
        yr = d[:, 0] * s + d[:, 1] * c
        return np.stack([xr, yr], axis=1)

    def kare(self, poz, isik_carpani=1.0):
        """Verilen poz icin sentetik kamera goruntusu (BGR)."""
        yerel = self._arac_cercevesi(poz)
        # Sadece onumuzdeki ve gorus alanindaki parca
        m = (yerel[:, 1] > 2.0) & (yerel[:, 1] < 400.0) & (np.abs(yerel[:, 0]) < 400.0)
        yerel = yerel[m]

        img = np.full((self.kam.h, self.kam.w), float(self.zemin), np.float32)

        if len(yerel) >= 2:
            # Merkez cizgiyi +-yariGenislik kadar otele, kapali poligon yap
            teg = np.gradient(yerel, axis=0)
            boy = np.linalg.norm(teg, axis=1, keepdims=True) + 1e-9
            teg = teg / boy
            nor = np.stack([teg[:, 1], -teg[:, 0]], axis=1)   # dik vektor
            yari = self.genislik / 2.0
            sol_k = yerel + nor * yari
            sag_k = yerel - nor * yari

            p1 = self.kam.izdusum(sol_k)
            p2 = self.kam.izdusum(sag_k)
            ok = ~(np.isnan(p1).any(axis=1) | np.isnan(p2).any(axis=1))
            p1, p2 = p1[ok], p2[ok]
            if len(p1) >= 2:
                poligon = np.vstack([p1, p2[::-1]])
                sinirli = np.clip(poligon, -1e4, 1e4).astype(np.int32)
                cv2.fillPoly(img, [sinirli], float(self.cizgi))

        img = img * self._isik * isik_carpani
        if self.gurultu > 0:
            img += np.random.randn(*img.shape).astype(np.float32) * self.gurultu
        img = np.clip(img, 0, 255).astype(np.uint8)
        return cv2.cvtColor(img, cv2.COLOR_GRAY2BGR)

    # ------------------------------------------------------------- olcum
    def capraz_hata(self, poz):
        """Aracin pist merkez cizgisine gercek dik uzakligi (cm). + ise arac sagda."""
        X, Y, teta = poz
        d = self.pist - np.array([X, Y])
        mes = np.linalg.norm(d, axis=1)
        i = int(np.argmin(mes))
        # Isaret: pist tegetine gore hangi tarafta
        j = min(i + 1, len(self.pist) - 1)
        t = self.pist[j] - self.pist[max(i - 1, 0)]
        n = np.array([t[1], -t[0]])
        nb = np.linalg.norm(n)
        if nb < 1e-9:
            return float(mes[i])
        return float(np.dot(-d[i], n / nb))


# ============================================================================
#  ARAC KINEMATIGI
# ============================================================================
class SimArac:
    """Diferansiyel surus. teta: +Y ekseninden saga dogru pozitif (rad)."""

    def __init__(self, iz_genisligi_cm, poz=(0.0, 0.0, 0.0), tepki_s=0.12):
        self.X, self.Y, self.teta = poz
        self.W = iz_genisligi_cm
        self.tepki = tepki_s          # motor/aktarma gecikmesi
        self.v_sol = 0.0
        self.v_sag = 0.0

    def adim(self, sol_cm_s, sag_cm_s, dt):
        # Birinci mertebe motor tepkisi (gercek arac aninda hizlanmaz)
        a = dt / max(self.tepki, 1e-3)
        a = min(1.0, a)
        self.v_sol += a * (sol_cm_s - self.v_sol)
        self.v_sag += a * (sag_cm_s - self.v_sag)

        v = 0.5 * (self.v_sol + self.v_sag)
        omega = (self.v_sol - self.v_sag) / self.W

        self.teta += omega * dt
        self.X += v * np.sin(self.teta) * dt
        self.Y += v * np.cos(self.teta) * dt
        return v, omega

    @property
    def poz(self):
        return (self.X, self.Y, self.teta)
