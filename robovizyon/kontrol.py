# -*- coding: utf-8 -*-
"""Pure Pursuit direksiyon + fiziksel hiz profili.

Neden PID degil:
  Piksel hatasi uzerine kurulu P kontrolu, duz yolda kalici yanal sapma birakir
  (arac cizgiye PARALEL ama yaninda gidebilir; hata sifir gorunur ama arac
  cizginin ustunde degildir). Kd ekleyince titrer, Ki ekleyince windup yapar.

  Pure Pursuit, cizginin ilerisinde bir HEDEF NOKTA secip oraya varan yayin
  egriligini hesaplar. Kalici sapma matematiksel olarak sifirdir: arac cizgiye
  paralel ama yaninda ise hedef nokta yana duser ve arac cizgiye geri oturur.
  Tek ayar parametresi vardir: on gorus mesafesi (Ld).
"""

import numpy as np


class SurusKomutu:
    __slots__ = ("hiz_cm_s", "egrilik", "sol_cm_s", "sag_cm_s", "hedef_x_cm",
                 "hedef_y_cm", "on_gorus_cm", "sebep")

    def __init__(self):
        self.hiz_cm_s = 0.0
        self.egrilik = 0.0
        self.sol_cm_s = 0.0
        self.sag_cm_s = 0.0
        self.hedef_x_cm = 0.0
        self.hedef_y_cm = 0.0
        self.on_gorus_cm = 0.0
        self.sebep = ""


class PurePursuit:
    def __init__(self, konfig):
        self.k = konfig
        self._hiz = 0.0          # rampa icin anlik hiz hafizasi

    # ------------------------------------------------------------------ hedef
    def _on_gorus(self, hiz):
        c = self.k.kontrol
        return float(np.clip(c.on_gorus_taban_cm + c.on_gorus_kazanc_s * hiz,
                             c.on_gorus_taban_cm, c.on_gorus_max_cm))

    def _hedef_nokta(self, olcum, Ld):
        """Cizgi uzerinde, aractan Ld kadar ileride bir nokta bul.

        Yay uzunlugu yerine Y mesafesi kullaniyoruz (kucuk acilarda fark ihmal
        edilebilir, hesap cok daha ucuz). Cizgi Ld kadar uzanmiyorsa en uzak
        gorulen noktayi kullan.
        """
        Y0 = olcum.referans_y_cm or self.k.perspektif.y_min_cm
        Y_hedef = min(Y0 + Ld, olcum.bitis_y_cm)
        Y_hedef = max(Y_hedef, Y0 + 5.0)
        X_hedef = olcum.X_of_Y(Y_hedef)
        return float(X_hedef), float(Y_hedef)

    # ------------------------------------------------------------------- hiz
    def _hiz_profili(self, egrilik, guven, kose_mesafe=None):
        """v = sqrt(a_yanal / |kappa|) -- klasik hiz profili.

        Aracin devrilmeden/kaymadan alabilecegi en yuksek hizi virajin GERCEK
        yariçapindan hesaplar. "Virajda %30 yavasla" gibi tahmini bir kural degil,
        fiziksel bir sinir.
        """
        c = self.k.kontrol
        v = c.hiz_max_cm_s

        kap = abs(egrilik)
        if kap > 1e-4:
            v = min(v, float(np.sqrt(c.yanal_ivme_max_cm_s2 / kap)))

        if guven < 0.55:
            v *= c.dusuk_guven_hiz_carpani

        if kose_mesafe is not None:
            # Koseye yaklasirken kontrollu yavasla (frenleme mesafesi kadar once)
            fren_mesafe = max(4.0, (v * v) / (2.0 * c.ivmelenme_cm_s2))
            if kose_mesafe < fren_mesafe:
                v = min(v, c.hiz_kose_cm_s)

        return float(np.clip(v, c.hiz_min_cm_s, c.hiz_max_cm_s))

    def _rampa(self, hedef_hiz, dt):
        """Ani hiz degisimi patinaj ve akim sicramasi yapar."""
        c = self.k.kontrol
        max_degisim = c.ivmelenme_cm_s2 * dt
        fark = float(np.clip(hedef_hiz - self._hiz, -max_degisim, max_degisim))
        self._hiz += fark
        return self._hiz

    # ------------------------------------------------------------------- ana
    def hesapla(self, olcum, dt, kose_mesafe=None):
        c = self.k.kontrol
        komut = SurusKomutu()

        if not olcum.gecerli:
            self._hiz = max(0.0, self._hiz - c.ivmelenme_cm_s2 * dt * 2)
            komut.sebep = "cizgi yok"
            return komut

        Ld = self._on_gorus(max(self._hiz, c.hiz_min_cm_s))
        X_h, Y_h = self._hedef_nokta(olcum, Ld)

        # Hedef noktanin araca gore konumu
        Y0 = olcum.referans_y_cm or self.k.perspektif.y_min_cm
        dx = X_h
        dy = max(1.0, Y_h - Y0)
        L2 = dx * dx + dy * dy

        # Pure Pursuit egriligi: kappa = 2*dx / L^2
        egrilik = 2.0 * dx / L2

        # Egrilik on-beslemesi.
        # Saf Pure Pursuit, SABIT yariçapli bir yayda kalici bir ic-yanal sapma
        # birakir (yaklasik Ld^2 / 8R). Yolun kendi egriligini komuta dogrudan
        # ekleyince bu sapma buyuk olcude kapanir; pursuit terimi sadece
        # duzeltme gorevi gorur.
        egrilik += c.egrilik_on_besleme * olcum.egrilik

        # Capraz-hata duzeltmesi: yaydaki kalici ic-kesmeyi kapatir.
        # ARAC AKSI hizasindaki hatayi kullaniyoruz; on gorus noktasindaki hata
        # virajda geometrik olarak zaten sifirdan farkli olmak zorundadir.
        e_arac = getattr(olcum, "arac_yanal_cm", olcum.yanal_hata_cm)
        egrilik += c.yanal_duzeltme * e_arac

        egrilik = float(np.clip(egrilik, -c.max_egrilik_1_cm, c.max_egrilik_1_cm))

        # Hiz: hem cizginin egriligi hem komutun egriligi dikkate alinir
        etkin_egrilik = max(abs(egrilik), abs(olcum.egrilik))
        hedef_hiz = self._hiz_profili(etkin_egrilik, olcum.guven, kose_mesafe)
        hiz = self._rampa(hedef_hiz, dt)

        # Diferansiyel surus karisimi
        omega = egrilik * hiz                       # rad/s
        yari_iz = c.iz_genisligi_cm / 2.0
        sol = hiz + omega * yari_iz
        sag = hiz - omega * yari_iz

        # Doyma: fark korunarak olcekle (kirpmak donus yariçapini bozar)
        tepe = max(abs(sol), abs(sag))
        if tepe > c.hiz_max_cm_s:
            olcek = c.hiz_max_cm_s / tepe
            sol *= olcek
            sag *= olcek

        komut.hiz_cm_s = hiz
        komut.egrilik = egrilik
        komut.sol_cm_s = float(sol)
        komut.sag_cm_s = float(sag)
        komut.hedef_x_cm = X_h
        komut.hedef_y_cm = Y_h
        komut.on_gorus_cm = Ld
        komut.sebep = "takip"
        return komut

    def sifirla(self):
        self._hiz = 0.0
