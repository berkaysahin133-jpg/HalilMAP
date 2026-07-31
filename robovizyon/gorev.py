# -*- coding: utf-8 -*-
"""Gorev durum makinesi: takip / kose manevrasi / QR / kurtarma.

Eski koddaki "VIRAJ_ILERI_SURESI = 0.6 sn" gibi tahmini sayilar burada YOK.
Kusbakisi sayesinde kosenin kac cm ilerde oldugunu biliyoruz; hiz komutunu da
biz veriyoruz. Yani ne kadar ilerlememiz gerektigini INTEGRE ederek buluyoruz.
Pivot cikisi da kapali cevrim: sure degil, cizginin hizalanmasi bitirir.
"""

import time
from enum import Enum

import numpy as np


class Durum(Enum):
    BASLANGIC = "BASLANGIC"
    TAKIP = "TAKIP"
    KOSE_YAKLAS = "KOSE_YAKLAS"      # koseye kalan mesafeyi kat et
    KOSE_PIVOT = "KOSE_PIVOT"        # yerinde don, cizgi hizalaninca bitir
    QR_YAVASLA = "QR_YAVASLA"
    QR_DUR = "QR_DUR"
    QR_PIVOT = "QR_PIVOT"
    ARAMA = "ARAMA"                  # cizgi kayboldu, tarayarak ara
    GUVENLI_DURUS = "GUVENLI_DURUS"


class Gorev:
    def __init__(self, konfig, dedektor, kontrolcu, motor, qr_okuyucu=None):
        self.k = konfig
        self.dedektor = dedektor
        self.kontrolcu = kontrolcu
        self.motor = motor
        self.qr = qr_okuyucu

        self.durum = Durum.BASLANGIC
        self._simdi = time.monotonic()
        self.t_durum = self._simdi
        self.kose_yonu = 0
        self.kalan_mesafe_cm = 0.0
        self.arama_yonu = +1
        self.qr_soguma = 0.0
        self.son_gecerli_t = time.monotonic()
        self.telemetri = {}

    # ------------------------------------------------------------------ yardim
    def _gec(self, yeni, not_=""):
        if yeni != self.durum:
            print(f"[DURUM] {self.durum.value} -> {yeni.value}  {not_}")
            self.durum = yeni
            # DIKKAT: time.monotonic() DEGIL. adim()'a disaridan verilen zaman
            # tabani kullanilmali, yoksa zaman asimlari hic tetiklenmez
            # (simulasyon/replay'de durum makinesi kilitleniyordu).
            self.t_durum = self._simdi

    def _sure(self, simdi):
        return simdi - self.t_durum

    def _pivot_beklenen_sure(self, derece=90.0):
        """Yerinde 90 donusun tahmini suresi -- komut ettigimiz hizdan.

        Pivot cikisini SADECE hizalanma sartina birakmak tehlikeli: arac
        yanlislikla 180 donerse GELDIGI cizgiyi gorup "hizalandim" der.
        Beklenen sureye gore bir pencere koyarak bunu engelliyoruz.
        """
        m, c = self.k.motor, self.k.kontrol
        v = (m.pivot_ofset / max(m.tam_gaz_ofset, 1)) * c.hiz_max_cm_s
        omega = 2.0 * v / max(c.iz_genisligi_cm, 1.0)          # rad/s
        return float(np.radians(derece) / max(omega, 1e-3))

    def _hizalandi(self, olcum):
        """Pivot cikis sarti: cizgi hem ortada hem duz."""
        if not olcum.gecerli:
            return False
        ka = self.k.kose
        return (abs(olcum.yanal_hata_cm) < ka.hizalama_sapma_cm
                and abs(np.degrees(olcum.yon_hatasi_rad)) < ka.hizalama_aci_derece)

    # -------------------------------------------------------------------- ana
    def adim(self, olcum, kare_bgr, dt, simdi=None):
        """Bir kare isle, motorlari sur. Telemetri sozlugu doner."""
        simdi = simdi if simdi is not None else time.monotonic()
        self._simdi = simdi
        g = self.k.guvenlik

        if olcum.gecerli:
            self.son_gecerli_t = simdi

        if self.durum == Durum.BASLANGIC:
            self.motor.dur()
            if olcum.gecerli:
                self._gec(Durum.TAKIP, "cizgi bulundu")
            elif self._sure(simdi) > 3.0:
                self._gec(Durum.ARAMA, "baslangicta cizgi yok")

        # ------------------------------------------------------------- TAKIP
        elif self.durum == Durum.TAKIP:
            if not olcum.gecerli:
                if simdi - self.son_gecerli_t > g.cizgi_kayip_sure_s:
                    self.motor.dur()
                    self._gec(Durum.ARAMA, "cizgi kayboldu")
                else:
                    komut = self.kontrolcu.hesapla(olcum, dt)
                    self.motor.sur(komut.sol_cm_s, komut.sag_cm_s)
                return self._telemetri(olcum, simdi)

            # --- QR ---
            if self.qr is not None and simdi > self.qr_soguma:
                if self.qr.tara(kare_bgr):
                    self._gec(Durum.QR_YAVASLA, f"QR '{self.k.qr.hedef_icerik}' onaylandi")
                    return self._telemetri(olcum, simdi)

            # --- Kose ---
            if olcum.kose_yonu != 0:
                self.kose_yonu = olcum.kose_yonu
                # kose_mesafe_cm zaten ARAC AKSINDAN olculur (kus_to_dunya'da
                # Y=0 arac merkezidir). Ustune bir de y_min_cm cikarmak, araci
                # koseden ~16 cm ONCE durduruyordu; pivot sonrasi yeni cizgi o
                # kadar yana dusuyor ve hizalama sarti hic saglanmiyordu.
                # Diferansiyel arac AKSI etrafinda doner -> aks kosede olmali.
                self.kalan_mesafe_cm = max(
                    0.0, olcum.kose_mesafe_cm - self.k.kose.yaklasma_pay_cm)
                self._gec(Durum.KOSE_YAKLAS,
                          f"{'sag' if self.kose_yonu > 0 else 'sol'} kose, "
                          f"{self.kalan_mesafe_cm:.1f} cm ilerde")
                return self._telemetri(olcum, simdi)

            komut = self.kontrolcu.hesapla(olcum, dt)
            self.motor.sur(komut.sol_cm_s, komut.sag_cm_s)
            self.telemetri["komut"] = komut

        # ------------------------------------------------------- KOSE_YAKLAS
        elif self.durum == Durum.KOSE_YAKLAS:
            # Mesafe koseyi GORDUGUMUZ anda kusbakisindan olculdu; simdi sadece
            # o mesafeyi katetmemiz gerekiyor.
            #
            # KRITIK: Bu hareket algilamaya BAGLI OLMAMALI. Koseye yaklastikca
            # onumuzdeki dikey cizgi kisalir, pencere sayisi min_gecerli_pencere
            # altina duser ve algilama gecersiz olur. Onceden burada hiz sifira
            # iniyor, arac koseye ~39 cm kala kilitleniyordu; ardindan pivot bos
            # zemine bakip 90 yerine ~180 donuyor ve GELDIGI cizgiyi "hizalandim"
            # saniyordu. Artik olcum gecersizken de sabit hizla duz devam eder.
            yavas = self.k.kontrol.hiz_kose_cm_s
            if olcum.gecerli:
                komut = self.kontrolcu.hesapla(olcum, dt, kose_mesafe=self.kalan_mesafe_cm)
                sol, sag_, v = komut.sol_cm_s, komut.sag_cm_s, komut.hiz_cm_s
                self.telemetri["komut"] = komut
            else:
                sol = sag_ = v = yavas
            self.motor.sur(sol, sag_)
            self.kalan_mesafe_cm -= v * dt

            # Zaman asimi mesafeye gore: uzak koseye yetismek icin sure tanı
            ust_sure = self.kalan_mesafe_cm / max(yavas, 1.0) + 4.0
            if self.kalan_mesafe_cm <= 0.0 or self._sure(simdi) > ust_sure:
                self.motor.dur()
                self._gec(Durum.KOSE_PIVOT, f"apex, {self.kose_yonu:+d} yone pivot")
                self.dedektor.sifirla()

        # -------------------------------------------------------- KOSE_PIVOT
        elif self.durum == Durum.KOSE_PIVOT:
            self.motor.pivot(self.kose_yonu)
            sure = self._sure(simdi)
            ka = self.k.kose
            beklenen = self._pivot_beklenen_sure()
            alt = max(ka.pivot_min_sure, 0.55 * beklenen)
            ust = min(ka.pivot_max_sure, 1.8 * beklenen)
            if sure > alt and self._hizalandi(olcum):
                self.motor.dur()
                self.kontrolcu.sifirla()
                self._gec(Durum.TAKIP, f"hizalandi ({sure:.2f} sn / beklenen {beklenen:.2f})")
            elif sure > ust:
                self.motor.dur()
                self.arama_yonu = self.kose_yonu
                self._gec(Durum.ARAMA, f"pivot zaman asimi ({sure:.2f} sn)")

        # --------------------------------------------------------- QR akisi
        elif self.durum == Durum.QR_YAVASLA:
            yavas = self.k.kontrol.hiz_kose_cm_s
            self.motor.sur(yavas, yavas)
            if self._sure(simdi) > 0.35:
                self.motor.dur()
                self._gec(Durum.QR_DUR)

        elif self.durum == Durum.QR_DUR:
            self.motor.dur()
            if self._sure(simdi) > 0.3:
                self.kose_yonu = +1                # gorev tanimi: saga 90
                self.dedektor.sifirla()
                self._gec(Durum.QR_PIVOT)

        elif self.durum == Durum.QR_PIVOT:
            self.motor.pivot(self.kose_yonu)
            sure = self._sure(simdi)
            ka = self.k.kose
            beklenen = self._pivot_beklenen_sure()
            alt = max(ka.pivot_min_sure, 0.55 * beklenen)
            ust = min(ka.pivot_max_sure, 1.8 * beklenen)
            if sure > alt and self._hizalandi(olcum):
                self.motor.dur()
                self.kontrolcu.sifirla()
                self.qr_soguma = simdi + self.k.qr.soguma_s
                if self.qr:
                    self.qr.sifirla()
                self._gec(Durum.TAKIP, f"QR donusu tamam ({sure:.2f} sn)")
            elif sure > ust:
                self.motor.dur()
                self.arama_yonu = +1
                self.qr_soguma = simdi + self.k.qr.soguma_s
                self._gec(Durum.ARAMA, "QR pivot zaman asimi")

        # -------------------------------------------------------------- ARAMA
        elif self.durum == Durum.ARAMA:
            if olcum.gecerli and olcum.guven > 0.5:
                self.motor.dur()
                self.kontrolcu.sifirla()
                self._gec(Durum.TAKIP, "cizgi tekrar bulundu")
            elif self._sure(simdi) < g.arama_sure_s:
                # Yavas tarama: cizgiyi atlamayacak kadar dusuk hizda
                self.motor.pivot(self.arama_yonu)
            else:
                self.motor.dur()
                self._gec(Durum.GUVENLI_DURUS, "arama sonucsuz")

        # ----------------------------------------------------- GUVENLI_DURUS
        elif self.durum == Durum.GUVENLI_DURUS:
            self.motor.dur()
            if olcum.gecerli and olcum.guven > 0.6:
                self.kontrolcu.sifirla()
                self._gec(Durum.TAKIP, "cizgi geri geldi")

        return self._telemetri(olcum, simdi)

    def _telemetri(self, olcum, simdi):
        self.telemetri.update({
            "durum": self.durum.value,
            "gecerli": olcum.gecerli,
            "guven": round(olcum.guven, 2),
            "yanal_cm": round(olcum.yanal_hata_cm, 2),
            "yon_derece": round(float(np.degrees(olcum.yon_hatasi_rad)), 1),
            "egrilik": round(olcum.egrilik, 4),
            "bitis_cm": round(olcum.bitis_y_cm, 1),
            "kose": olcum.kose_yonu,
            "kose_cm": round(olcum.kose_mesafe_cm, 1),
            "kalan_cm": round(self.kalan_mesafe_cm, 1),
            "t": round(simdi, 3),
        })
        return self.telemetri

    def durdur(self):
        self.motor.dur()
        self._gec(Durum.GUVENLI_DURUS, "manuel durdurma")
