# -*- coding: utf-8 -*-
"""Hata ayiklama gorsellestirmesi. Ne gordugunu GORMEDEN ayar yapamazsin."""

import cv2
import numpy as np

YESIL = (60, 220, 60)
KIRMIZI = (60, 60, 235)
MAVI = (235, 160, 60)
SARI = (60, 220, 235)
MOR = (220, 80, 200)
BEYAZ = (245, 245, 245)


def _yazi(img, metin, konum, renk=BEYAZ, olcek=0.42, kalin=1):
    cv2.putText(img, metin, konum, cv2.FONT_HERSHEY_SIMPLEX, olcek,
                (0, 0, 0), kalin + 2, cv2.LINE_AA)
    cv2.putText(img, metin, konum, cv2.FONT_HERSHEY_SIMPLEX, olcek,
                renk, kalin, cv2.LINE_AA)


def kus_panel(kus_bgr, olcum, perspektif, komut=None):
    """Kusbakisi gorunum: maske + takip noktalari + polinom + hedef nokta."""
    panel = kus_bgr.copy()
    if olcum.maske is not None:
        renkli = cv2.cvtColor(olcum.maske, cv2.COLOR_GRAY2BGR)
        renkli[:, :, 0] = 0
        renkli[:, :, 2] = 0
        panel = cv2.addWeighted(panel, 0.65, renkli, 0.35, 0)

    # Merkez ekseni
    u0, _ = perspektif.dunya_to_kus(0.0, 0.0)
    cv2.line(panel, (int(u0), 0), (int(u0), panel.shape[0]), (90, 90, 90), 1)

    if olcum.gecerli:
        # Takip edilen pencere merkezleri
        for X, Y in olcum.noktalar_cm:
            u, v = perspektif.dunya_to_kus(X, Y)
            cv2.circle(panel, (int(u), int(v)), 3, SARI, -1)

        # Oturtulan polinom
        Y0 = perspektif.per.y_min_cm
        Y1 = max(Y0 + 1.0, olcum.bitis_y_cm)
        egri = []
        for Y in np.linspace(Y0, Y1, 25):
            u, v = perspektif.dunya_to_kus(olcum.X_of_Y(Y), Y)
            egri.append([int(u), int(v)])
        if len(egri) > 1:
            cv2.polylines(panel, [np.array(egri, np.int32)], False, YESIL, 2, cv2.LINE_AA)

        if olcum.kose_yonu != 0:
            u, v = perspektif.dunya_to_kus(0.0, olcum.kose_mesafe_cm)
            cv2.line(panel, (0, int(v)), (panel.shape[1], int(v)), MOR, 2)
            _yazi(panel, f"KOSE {'SAG' if olcum.kose_yonu > 0 else 'SOL'} "
                         f"{olcum.kose_mesafe_cm:.0f}cm", (4, int(v) - 5), MOR)

    if komut is not None and komut.hedef_y_cm:
        u, v = perspektif.dunya_to_kus(komut.hedef_x_cm, komut.hedef_y_cm)
        cv2.circle(panel, (int(u), int(v)), 6, KIRMIZI, 2)
        cv2.line(panel, (int(u0), panel.shape[0] - 1), (int(u), int(v)), KIRMIZI, 1)

    return panel


def ana_panel(kare_bgr, olcum, perspektif, telemetri, komut=None, fps=0.0):
    """Orijinal kamera goruntusu + kusbakisindan geri yansitilmis cizgi."""
    panel = kare_bgr.copy()
    h, w = panel.shape[:2]

    if olcum.gecerli:
        Y0 = perspektif.per.y_min_cm
        Y1 = max(Y0 + 1.0, olcum.bitis_y_cm)
        kus_noktalar = []
        for Y in np.linspace(Y0, Y1, 25):
            kus_noktalar.append(perspektif.dunya_to_kus(olcum.X_of_Y(Y), Y))
        geri = perspektif.ters_warp_noktalar(kus_noktalar)
        if len(geri) > 1:
            cv2.polylines(panel, [geri.astype(np.int32)], False, YESIL, 2, cv2.LINE_AA)

    # Gorus alani sinirlari
    kose_kus = [(0, 0), (perspektif.genislik_px, 0),
                (perspektif.genislik_px, perspektif.yukseklik_px),
                (0, perspektif.yukseklik_px)]
    cerceve = perspektif.ters_warp_noktalar(kose_kus)
    cv2.polylines(panel, [cerceve.astype(np.int32)], True, (110, 110, 110), 1)

    # Telemetri kutusu
    kutu = panel[0:96, 0:220].copy()
    panel[0:96, 0:220] = cv2.addWeighted(kutu, 0.35, np.zeros_like(kutu), 0.65, 0)

    d = telemetri
    renk = YESIL if d.get("gecerli") else KIRMIZI
    _yazi(panel, f"{d.get('durum', '-')}", (6, 16), renk, 0.5, 1)
    _yazi(panel, f"yanal  {d.get('yanal_cm', 0):+6.1f} cm", (6, 32))
    _yazi(panel, f"yon    {d.get('yon_derece', 0):+6.1f} deg", (6, 46))
    _yazi(panel, f"guven  {d.get('guven', 0):5.2f}   bitis {d.get('bitis_cm', 0):.0f}cm", (6, 60))
    if komut is not None:
        _yazi(panel, f"hiz {komut.hiz_cm_s:5.1f} cm/s   Ld {komut.on_gorus_cm:.0f}cm", (6, 74))
        _yazi(panel, f"sol {komut.sol_cm_s:+5.1f}  sag {komut.sag_cm_s:+5.1f}", (6, 88))
    _yazi(panel, f"{fps:4.1f} fps", (w - 62, 16), SARI)
    return panel


def yan_yana(ana, kus):
    """Iki paneli tek pencerede birlestir."""
    h = max(ana.shape[0], kus.shape[0])
    olcek = h / float(kus.shape[0])
    kus_b = cv2.resize(kus, (int(kus.shape[1] * olcek), h))
    tuval = np.zeros((h, ana.shape[1] + kus_b.shape[1], 3), np.uint8)
    tuval[:ana.shape[0], :ana.shape[1]] = ana
    tuval[:, ana.shape[1]:] = kus_b
    return tuval
