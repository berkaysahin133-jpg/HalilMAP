# -*- coding: utf-8 -*-
"""Tum ayarlar tek yerde. JSON'a kaydedilir/yuklenir; pistte yaptigin ayar kaybolmaz."""

import json
import os
from dataclasses import dataclass, asdict, field, fields


@dataclass
class KameraAyar:
    indeks: int = 0
    genislik: int = 640
    yukseklik: int = 480
    fps: int = 60
    # Manuel pozlama: hareket bulanikligini ve otomatik parlaklik dalgalanmasini keser
    manuel_pozlama: bool = True
    pozlama: int = 60          # V4L2 birimi ~100us -> 60 = 6 ms
    kazanc: int = 0
    # Isleme cozunurlugu (kucuk = hizli). Kusbakisi bundan uretilir.
    islem_genislik: int = 320
    islem_yukseklik: int = 240


@dataclass
class PerspektifAyar:
    """Kusbakisi (Inverse Perspective Mapping) parametreleri.

    Iki yol var:
      1) Geometrik  : kamera yuksekligi + egim acisi + FOV gir, homografi hesaplansin
      2) 4 nokta    : kalibre.py ile yere koydugun dikdortgenin koselerini tikla
    """
    # --- Geometrik yol ---
    kamera_yuksekligi_cm: float = 22.0    # yerden lens merkezine
    egim_derece: float = 32.0             # yataydan asagi dogru egim
    yatay_fov_derece: float = 62.0        # kamera datasheet'i / olcum

    # --- Kusbakisi dunya penceresi (arac merkezine gore, cm) ---
    x_min_cm: float = -30.0               # sol
    x_max_cm: float = +30.0               # sag
    y_min_cm: float = 12.0                # aracin hemen onu
    y_max_cm: float = 75.0                # en uzak gorus
    piksel_cm: float = 4.0                # kusbakisi cozunurlugu (px / cm)

    # --- 4 nokta yolu (kalibre.py doldurur; None ise geometrik kullanilir) ---
    kaynak_noktalar: list | None = None   # [[u,v] x4]  goruntude
    hedef_noktalar_cm: list | None = None # [[X,Y] x4]  yerde (cm)


@dataclass
class SeritAyar:
    """Cizgi tespiti."""
    cizgi_koyu: bool = True               # acik zeminde koyu cizgi
    cizgi_genislik_cm: float = 2.5        # bandin gercek genisligi (sekil filtresi)

    # Yerel ortalama cikarma esigi (aydinlatmadan bagimsiz binarizasyon)
    yerel_pencere_cm: float = 9.0         # cizgi genisliginin ~3 kati
    kontrast_esigi: int = 18              # yerel ortalamadan bu kadar koyu = cizgi

    pencere_sayisi: int = 12              # kayan pencere adedi
    pencere_yari_genislik_cm: float = 9.0
    pencere_min_piksel: int = 25          # bu sayinin altinda pencere "bos"
    max_bos_pencere: int = 2              # ust uste bu kadar bos -> cizgi bitti

    polinom_derece: int = 2
    duzluk_esigi_cm: float = 0.35         # dogru artigi bunun altindaysa yol DUZ
                                          # (cember fit dogrusal noktalarda tekildir)
    min_gecerli_pencere: int = 3          # fit icin gereken en az dolu pencere


@dataclass
class KoseAyar:
    """90 derece L-viraj / T-kavsak tespiti."""
    yatay_kosu_cm: float = 14.0           # koseyi kanitlayan yatay uzanti
    min_onay_kare: int = 3                # bu kadar ust uste gorulmeden manevra yok
    hizalama_aci_derece: float = 8.0      # pivot cikisi: sapma bu acinin altina insin
    hizalama_sapma_cm: float = 4.5        # pivot cikisi: yanal hata bu degerin altina insin
    pivot_min_sure: float = 0.30
    pivot_max_sure: float = 4.0
    yaklasma_pay_cm: float = 0.0          # aks tam kosede olsun (diferansiyel
                                          # arac AKS etrafinda doner)


@dataclass
class KontrolAyar:
    """Pure Pursuit + hiz profili."""
    iz_genisligi_cm: float = 42.0         # sol-sag teker merkez mesafesi
    hiz_max_cm_s: float = 45.0
    hiz_min_cm_s: float = 12.0
    hiz_kose_cm_s: float = 18.0           # koseye yaklasirken
    yanal_ivme_max_cm_s2: float = 35.0    # viraj hizini belirler: v = sqrt(a/|k|)

    on_gorus_taban_cm: float = 18.0       # Ld = taban + kazanc * v
    on_gorus_kazanc_s: float = 0.35
    on_gorus_max_cm: float = 55.0
    # Pure Pursuit, sabit yariçapli bir yayda GEREKLI egriligi zaten kendisi
    # uretir (on gorus noktasi yana dustugu icin kappa = 1/R cikar). Yolun
    # egriligini ustune eklemek CIFT SAYIM olur ve arac viraji iceriden keser.
    # Bu yuzden varsayilan 0. Yalnizca olculen kalici sapmayi kapatmak icin
    # kucuk bir deger (0.1-0.3) verilebilir.
    egrilik_on_besleme: float = 0.0

    # Capraz-hata duzeltmesi (1/cm^2).
    # Saf Pure Pursuit, sabit yariçapli yayda viraji ICERIDEN keser; kalici
    # sapma yaklasik Ld^2/(8R) kadardir. Olculen yanal hatayi dogrudan egrilik
    # komutuna eklemek bu sapmayi kapatir. Duz yolda etkisi yoktur (hata ~0).
    yanal_duzeltme: float = 0.004         # simulasyonda supuruldu: 0.004 optimum.
                                          # Daha yuksek deger genis viraji
                                          # iyilestirir ama dar virajda (R<50)
                                          # kararsizlasiyor.

    ivmelenme_cm_s2: float = 90.0         # hiz rampasi (patinaj engelleyici)
    max_egrilik_1_cm: float = 0.05        # |kappa| tavani (1/cm) ~ 20 cm donus yaricapi

    # Guven dustukce yavasla
    dusuk_guven_hiz_carpani: float = 0.45


@dataclass
class MotorAyar:
    port: str | None = None               # None -> otomatik bul
    baud: int = 115200
    notr: int = 2048
    # Nötre göre tam gaz ofseti. hiz_max_cm_s bu ofsete karsilik gelir.
    tam_gaz_ofset: int = 900
    yon: int = +1                         # +1: DAC > notr ileri | -1: tersi
    pivot_ofset: int = 700
    komut_hz: float = 50.0


@dataclass
class QRAyar:
    aktif: bool = True
    hedef_icerik: str = "11"
    tarama_arasi: int = 2                 # her N karede bir tara
    onay_kare: int = 2                    # bu kadar kare ayni icerigi okumadan manevra yok
    soguma_s: float = 4.0
    roi_ust: float = 0.10                 # tam karede QR aranacak dikey band
    roi_alt: float = 0.85
    buyutme: float = 2.0                  # okunamazsa ROI'yi bu kadar buyutup tekrar dene


@dataclass
class GuvenlikAyar:
    cizgi_kayip_sure_s: float = 1.0       # bu kadar cizgi yoksa dur
    arama_sure_s: float = 2.5             # kurtarma taramasi
    watchdog_s: float = 0.25              # firmware ile ayni olmali


@dataclass
class Konfig:
    kamera: KameraAyar = field(default_factory=KameraAyar)
    perspektif: PerspektifAyar = field(default_factory=PerspektifAyar)
    serit: SeritAyar = field(default_factory=SeritAyar)
    kose: KoseAyar = field(default_factory=KoseAyar)
    kontrol: KontrolAyar = field(default_factory=KontrolAyar)
    motor: MotorAyar = field(default_factory=MotorAyar)
    qr: QRAyar = field(default_factory=QRAyar)
    guvenlik: GuvenlikAyar = field(default_factory=GuvenlikAyar)

    # ---------- kalicilik ----------
    def kaydet(self, yol="konfig.json"):
        with open(yol, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2, ensure_ascii=False)
        return yol

    @classmethod
    def yukle(cls, yol="konfig.json"):
        if not os.path.exists(yol):
            return cls()
        with open(yol, encoding="utf-8") as f:
            ham = json.load(f)
        k = cls()
        for f_ in fields(cls):
            if f_.name in ham and isinstance(ham[f_.name], dict):
                alt = getattr(k, f_.name)
                for anahtar, deger in ham[f_.name].items():
                    if hasattr(alt, anahtar):
                        setattr(alt, anahtar, deger)
        return k
