# -*- coding: utf-8 -*-
"""Serit (cizgi) algilama: binarizasyon -> kayan pencere -> polinom -> kose analizi.

Mimari neden boyle:
  Eski yontem "esikle, en buyuk konturu al, centroid'ini hesapla" idi. Tek sayi
  uretir; cizginin SEKLINI bilmez. Bu yuzden:
    - Viraji ancak icine girdikten sonra fark eder
    - T-kavsakta / capraz cizgide centroid bosluga kayar
    - Golge bir lekeyi cizgi sanabilir

  Burada cizgiyi ALTTAN YUKARI takip ediyoruz (kayan pencere). Cikan nokta
  bulutuna polinom oturtuyoruz. Boylece elimizde:
    - Yanal hata (cm)          -> direksiyon
    - Yon hatasi (derece)      -> direksiyon
    - Egrilik (1/cm)           -> hiz profili
    - Cizginin nerede bittigi  -> kose/kavsak tespiti
"""

import numpy as np
import cv2


class SeritOlcum:
    """Tek karelik algilama sonucu."""
    __slots__ = ("gecerli", "guven", "yanal_hata_cm", "yon_hatasi_rad", "egrilik",
                 "katsayilar", "noktalar_cm", "bitis_y_cm", "kose_yonu",
                 "kose_mesafe_cm", "yatay_kosu_cm", "maske", "dolu_pencere",
                 "referans_y_cm", "arac_yanal_cm", "cember")

    def __init__(self):
        self.gecerli = False
        self.guven = 0.0            # 0..1
        self.yanal_hata_cm = 0.0    # + ise cizgi sagda
        self.yon_hatasi_rad = 0.0   # + ise cizgi saga dogru gidiyor
        self.egrilik = 0.0          # 1/cm
        self.katsayilar = None      # X = f(Y) polinom katsayilari
        self.noktalar_cm = []       # [(X,Y), ...] takip edilen merkezler
        self.bitis_y_cm = 0.0       # cizginin takip edilebildigi en uzak nokta
        self.kose_yonu = 0          # -1 sol, +1 sag, 0 yok
        self.kose_mesafe_cm = 0.0   # koseye kalan mesafe
        self.yatay_kosu_cm = 0.0    # kose kanitinin gucu
        self.maske = None
        self.dolu_pencere = 0
        self.referans_y_cm = 0.0   # olcumlerin alindigi mesafe (ekstrapolasyon yok)
        self.arac_yanal_cm = 0.0   # cizginin ARAC AKSI hizasindaki yanal konumu
        self.cember = None         # (cx, cy, R) -- varsa X_of_Y bunu kullanir

    def X_of_Y(self, Y_cm):
        """Y mesafesindeki yanal konum. Cember varsa ondan, yoksa polinomdan."""
        if self.cember is not None:
            cx, cy, R = self.cember
            ic = R * R - (Y_cm - cy) ** 2
            if ic > 0.0:
                isaret = 1.0 if cx >= 0 else -1.0
                return float(cx - isaret * np.sqrt(ic))
        if self.katsayilar is None:
            return 0.0
        return float(np.polyval(self.katsayilar, Y_cm))


def cember_fit(Xs, Ys, agirlik=None):
    """Kasa cember fit -- noktalara CEMBER oturtur, parabol degil.

    Neden gerekli:
      Cizgiyi X = f(Y) parabolu ile modellemek yapisal olarak yanlistir.
      Bir cember yayinin bu parametrizasyondaki ikinci turevi SABIT DEGILDIR
      (f'' = R^2 / (R^2 - Y^2)^1.5, Y buyudukce buyur). Genis bir Y araligina
      parabol oturtunca:
        - egrilik ~%50 sisiyor
        - Y=0'a (arac aksina) geri ekstrapolasyon, KUSURSUZ veriyle bile
          ~1.7 cm sapiyor
      Kontrolcu bu yanliligi sadakatle sifira surdugu icin arac viraji
      iceriden kesiyordu. Cember modeli her ikisini de kokten cozer.

    Doner: (cx, cy, R) veya cozulemezse None.
    """
    Xs = np.asarray(Xs, float)
    Ys = np.asarray(Ys, float)
    if len(Xs) < 3:
        return None
    A = np.stack([Xs, Ys, np.ones_like(Xs)], axis=1)
    b = Xs * Xs + Ys * Ys
    if agirlik is not None:
        w = np.sqrt(np.clip(np.asarray(agirlik, float), 1e-6, None))[:, None]
        A = A * w
        b = b * w[:, 0]
    try:
        coz, *_ = np.linalg.lstsq(A, b, rcond=None)
    except np.linalg.LinAlgError:
        return None
    cx, cy = coz[0] / 2.0, coz[1] / 2.0
    r2 = coz[2] + cx * cx + cy * cy
    if not np.isfinite(r2) or r2 <= 1.0:
        return None
    return float(cx), float(cy), float(np.sqrt(r2))


class SeritDedektoru:
    def __init__(self, konfig, perspektif):
        self.k = konfig
        self.per = perspektif
        s = konfig.serit
        p = konfig.perspektif

        self.px_cm = p.piksel_cm
        self.W = perspektif.genislik_px
        self.H = perspektif.yukseklik_px

        # Yerel ortalama penceresi tek sayi olmali
        self.yerel_px = max(3, int(round(s.yerel_pencere_cm * self.px_cm)) | 1)
        self.pencere_yari_px = max(3, int(round(s.pencere_yari_genislik_cm * self.px_cm)))
        self.pencere_h = max(2, self.H // s.pencere_sayisi)

        # Takip hafizasi (bir sonraki karede aramayi buradan baslat)
        self._son_taban_px = None
        self._kayip_sayaci = 0

        # Gecerli bolge maskesi: yerel ortalama penceresinin YARISI kadar
        # iceri cekilir, cunku halenin ulastigi derinlik o kadardir.
        pay = max(3, (self.yerel_px // 2) | 1)
        self.gecerli_maske = cv2.erode(
            perspektif.gecerli_maske,
            cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (pay, pay)))

        # Kose onay sayaci: tek karelik gurultu manevra tetiklemesin
        self._kose_gecmis = []

    # ------------------------------------------------------------ binarizasyon
    def binarize(self, kus_gri):
        """Aydinlatmadan bagimsiz binarizasyon: yerel ortalama cikarma.

        Sabit esik (inRange(0,85)) neden yetersiz:
          Salon isigi tek tip degildir. Pencerenin altinda zemin 190, kosede 90
          olabilir. Tek esik ya kosede zemini "cizgi" sayar ya pencere altinda
          cizgiyi kacirir.
        Yerel ortalama cikarma, her pikseli KENDI KOMSULUGUYLA kiyaslar; mutlak
        parlaklik onemsizlesir, sadece "cevresinden ne kadar koyu" onemli olur.
        """
        s = self.k.serit
        yumusak = cv2.GaussianBlur(kus_gri, (5, 5), 0)
        yerel = cv2.blur(yumusak, (self.yerel_px, self.yerel_px))

        if s.cizgi_koyu:
            fark = cv2.subtract(yerel, yumusak)     # cizgi cevresinden koyu
        else:
            fark = cv2.subtract(yumusak, yerel)

        _, maske = cv2.threshold(fark, s.kontrast_esigi, 255, cv2.THRESH_BINARY)

        # Bant genisligi kadar kapama: kopuk cizgiyi birlestir, benek gurultuyu at
        k_boy = max(3, int(round(s.cizgi_genislik_cm * self.px_cm)) | 1)
        cekirdek = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (k_boy, k_boy))
        maske = cv2.morphologyEx(maske, cv2.MORPH_CLOSE, cekirdek)
        maske = cv2.morphologyEx(maske, cv2.MORPH_OPEN,
                                 cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3)))

        # Kusbakisinin kamera gorus alani DISINDA kalan bolgesini at.
        # Warp dolgusunun kenari, yerel ortalama cikarmada sahte bir cizgi
        # uretiyor ve kayan pencere ona kilitleniyordu.
        return cv2.bitwise_and(maske, self.gecerli_maske)

    # ------------------------------------------------------------ taban bulma
    def _taban_bul(self, maske):
        """Cizginin araca en yakin noktasi. Once tahminden, olmazsa histogramdan."""
        alt = maske[int(self.H * 0.75):, :]
        histogram = alt.sum(axis=0).astype(np.float32)
        if histogram.max() < 255 * 2:
            return None

        # Onceki kareyi biliyorsak yakinini tercih et (takip: titremeyi keser,
        # yandaki paralel cizgiye/golgeye atlamayi engeller)
        if self._son_taban_px is not None:
            agirlik = np.exp(-0.5 * ((np.arange(self.W) - self._son_taban_px)
                                     / (self.pencere_yari_px * 1.5)) ** 2)
            histogram = histogram * (0.35 + 0.65 * agirlik)

        return int(np.argmax(histogram))

    # -------------------------------------------------------- kayan pencereler
    def _kayan_pencere(self, maske, taban_px):
        """Alttan yukari cizgiyi takip et. (merkezler, bos_pencere_sayisi) doner."""
        s = self.k.serit
        merkezler = []
        x = taban_px
        bos_ardisik = 0
        bitis_v = self.H

        for i in range(s.pencere_sayisi):
            v_alt = self.H - i * self.pencere_h
            v_ust = max(0, v_alt - self.pencere_h)
            if v_ust >= v_alt:
                break

            u_sol = max(0, x - self.pencere_yari_px)
            u_sag = min(self.W, x + self.pencere_yari_px)
            pencere = maske[v_ust:v_alt, u_sol:u_sag]

            if pencere.size == 0:
                break

            sifir_disi = cv2.findNonZero(pencere)
            # OpenCV surumune gore (N,1,2) veya (N,2) donebiliyor
            if sifir_disi is not None:
                sifir_disi = np.asarray(sifir_disi).reshape(-1, 2)
            if sifir_disi is not None and len(sifir_disi) >= s.pencere_min_piksel:
                yeni_x = int(sifir_disi[:, 0].mean()) + u_sol
                # Pencereyi kaydir ama ziplamayi sinirla (gurultuye kacmasin)
                x = int(0.65 * yeni_x + 0.35 * x)
                merkezler.append((x, (v_ust + v_alt) / 2.0, len(sifir_disi)))
                bos_ardisik = 0
                bitis_v = v_ust
            else:
                bos_ardisik += 1
                if bos_ardisik >= s.max_bos_pencere:
                    break

        return merkezler, bitis_v

    # ------------------------------------------------------------- kose analizi
    def _kose_analiz(self, maske, merkezler, bitis_v):
        """Cizgi takibi bittigi yerde yatay uzanti var mi?

        90 derece L-viraj, kuşbakisinda gercekten 90 derecedir: dikey cizgi biter,
        yerine SAGA veya SOLA uzanan bir bant baslar. Bunu, takibin bittigi
        satirda yatay kosu (run) uzunlugu olcerek kaniti saglama aliyoruz.
        """
        if not merkezler:
            return 0, 0.0, 0.0

        son_x, son_v, _ = merkezler[-1]
        band_yari = max(2, int(self.k.serit.cizgi_genislik_cm * self.px_cm))
        v0 = int(max(0, min(self.H - 1, son_v - band_yari)))
        v1 = int(max(1, min(self.H, son_v + band_yari)))
        band = maske[v0:v1, :]
        if band.size == 0:
            return 0, 0.0, 0.0

        # Banttaki her sutunda piksel var mi
        sutun = (band.max(axis=0) > 0).astype(np.uint8)
        x0 = int(np.clip(son_x, 0, self.W - 1))
        if sutun[x0] == 0:
            # Cizgi merkezinde piksel yoksa en yakin dolu sutunu bul
            dolu = np.flatnonzero(sutun)
            if dolu.size == 0:
                return 0, 0.0, 0.0
            x0 = int(dolu[np.argmin(np.abs(dolu - x0))])

        sol = x0
        while sol > 0 and sutun[sol - 1]:
            sol -= 1
        sag = x0
        while sag < self.W - 1 and sutun[sag + 1]:
            sag += 1

        sol_cm = (x0 - sol) / self.px_cm
        sag_cm = (sag - x0) / self.px_cm
        esik = self.k.kose.yatay_kosu_cm

        if sag_cm >= esik and sag_cm > sol_cm * 1.5:
            yon, kosu = +1, sag_cm
        elif sol_cm >= esik and sol_cm > sag_cm * 1.5:
            yon, kosu = -1, sol_cm
        else:
            return 0, 0.0, max(sol_cm, sag_cm)

        _, Y_kose = self.per.kus_to_dunya(x0, son_v)
        return yon, float(Y_kose), float(kosu)

    # ------------------------------------------------------------------- ana
    def isle(self, kus_bgr):
        """Kusbakisi kareyi isler, SeritOlcum doner."""
        olcum = SeritOlcum()
        gri = cv2.cvtColor(kus_bgr, cv2.COLOR_BGR2GRAY) if kus_bgr.ndim == 3 else kus_bgr
        maske = self.binarize(gri)
        olcum.maske = maske

        taban = self._taban_bul(maske)
        if taban is None:
            self._kayip_sayaci += 1
            if self._kayip_sayaci > 5:
                self._son_taban_px = None
            self._kose_gecmis.clear()
            return olcum

        merkezler, bitis_v = self._kayan_pencere(maske, taban)
        olcum.dolu_pencere = len(merkezler)

        if len(merkezler) < self.k.serit.min_gecerli_pencere:
            self._kayip_sayaci += 1
            self._kose_gecmis.clear()
            return olcum

        self._kayip_sayaci = 0
        self._son_taban_px = merkezler[0][0]

        # Kusbakisi piksel -> dunya (cm)
        noktalar = [self.per.kus_to_dunya(u, v) for u, v, _ in merkezler]
        Xs = np.array([p[0] for p in noktalar])
        Ys = np.array([p[1] for p in noktalar])

        # X = f(Y) polinomu. Agirlik: yakin noktalar daha guvenilir.
        derece = min(self.k.serit.polinom_derece, len(noktalar) - 1)
        agirlik = np.array([n for _, _, n in merkezler], np.float64)
        agirlik = agirlik / (agirlik.max() + 1e-9)

        try:
            katsayi = np.polyfit(Ys, Xs, derece, w=agirlik)
        except (np.linalg.LinAlgError, ValueError):
            return olcum

        # Olcum noktasi: EN YAKIN TESPIT EDILEN nokta.
        # y_min_cm'de degerlendirmek, veri araliginin disina ekstrapolasyon
        # demekti; yanal hatada kazanc hatasi, yon acisinda tam bozulma yapiyordu.
        Y0 = float(Ys.min())
        tur = np.polyder(katsayi)
        egim = float(np.polyval(tur, Y0))

        olcum.gecerli = True
        olcum.katsayilar = katsayi
        olcum.noktalar_cm = list(zip(Xs, Ys))
        olcum.referans_y_cm = Y0
        olcum.yanal_hata_cm = float(np.polyval(katsayi, Y0))

        # Cizginin arac AKSI hizasindaki (Y=0) yanal konumu.
        # Y0 ~16 cm ilerde olculuyor; virajda cizginin oradaki konumu ile aracin
        # bulundugu yerdeki konumu geometrik olarak farklidir (~Y0^2/2R kadar).
        # Kontrolu Y0'daki degere gore yapmak, araci viraji iceriden kesmeye
        # zorluyordu. Fit edilen polinomdan aks hizasi analitik olarak cikarilir.
        # --- Geometri modeli: once DUZ MU diye bak, sonra cember ---
        # Cember fit (Kasa), noktalar dogrusal oldugunda matematiksel olarak
        # tekildir ve anlamsiz bir yariçap uretir. Bu yuzden once dogru
        # oturtup artigi olcuyoruz: artik gurultu seviyesindeyse yol duzdur ve
        # dogrusal ekstrapolasyon zaten KESINDIR.
        dogru = np.polyfit(Ys, Xs, 1)
        r_dogru = float(np.sqrt(np.mean((np.polyval(dogru, Ys) - Xs) ** 2)))

        if r_dogru <= self.k.serit.duzluk_esigi_cm:
            olcum.cember = None
            olcum.egrilik = 0.0
            olcum.arac_yanal_cm = float(np.clip(np.polyval(dogru, 0.0), -60.0, 60.0))
        else:
            cem = cember_fit(Xs, Ys, agirlik)
            R_MAX = 1500.0
            uygun = False
            if cem is not None and cem[2] < R_MAX:
                cx, cy, R = cem
                r_cember = float(np.sqrt(np.mean(
                    (np.hypot(Xs - cx, Ys - cy) - R) ** 2)))
                uygun = r_cember < r_dogru          # cember gercekten daha iyi mi
            if uygun:
                cx, cy, R = cem
                olcum.cember = cem
                isaret = 1.0 if cx >= 0 else -1.0
                d0 = float(np.hypot(cx, cy))
                # Aks hizasindaki yanal hata: ekstrapolasyon degil, GEOMETRI
                olcum.arac_yanal_cm = float(np.clip((d0 - R) * isaret, -60.0, 60.0))
                olcum.egrilik = float(isaret / R)
            else:
                olcum.cember = None
                olcum.arac_yanal_cm = float(np.clip(np.polyval(katsayi, 0.0), -60.0, 60.0))
                tur2 = float(np.polyval(np.polyder(tur), Y0))
                olcum.egrilik = float(tur2 / (1.0 + egim ** 2) ** 1.5)
        olcum.yon_hatasi_rad = float(np.arctan(egim))
        _, olcum.bitis_y_cm = self.per.kus_to_dunya(merkezler[-1][0], merkezler[-1][1])

        # Guven: kac pencere doldu + fit ne kadar iyi oturdu
        kapsam = len(merkezler) / float(self.k.serit.pencere_sayisi)
        artik = float(np.sqrt(np.mean((np.polyval(katsayi, Ys) - Xs) ** 2)))
        uyum = float(np.exp(-artik / 2.5))          # 2.5 cm RMS -> ~0.37
        olcum.guven = float(np.clip(0.45 * kapsam + 0.55 * uyum, 0.0, 1.0))

        # --- Kose ---
        yon, mesafe, kosu = self._kose_analiz(maske, merkezler, bitis_v)
        olcum.yatay_kosu_cm = kosu

        # Cok kareli onay: tek karelik parlama/golge manevra tetiklemesin
        self._kose_gecmis.append(yon)
        if len(self._kose_gecmis) > self.k.kose.min_onay_kare:
            self._kose_gecmis.pop(0)

        if (len(self._kose_gecmis) >= self.k.kose.min_onay_kare
                and yon != 0 and all(g == yon for g in self._kose_gecmis)):
            olcum.kose_yonu = yon
            olcum.kose_mesafe_cm = mesafe

        return olcum

    def sifirla(self):
        self._son_taban_px = None
        self._kayip_sayaci = 0
        self._kose_gecmis.clear()
