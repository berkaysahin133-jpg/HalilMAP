#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cizgi_takip.py mantik testi - kamera/seri port olmadan."""
import os, sys, numpy as np, cv2
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cizgi_takip as CT

W, H = CT.ISLEM_W, CT.ISLEM_H
gecti = basarisiz = 0

def kontrol(ad, sart, detay=""):
    global gecti, basarisiz
    if sart:
        gecti += 1; print(f"  OK   {ad}  {detay}")
    else:
        basarisiz += 1; print(f"  FAIL {ad}  {detay}")

def sahne(cx_orani=0.5, kalinlik=14, yatay_bant=None, gurultu=True, parlaklik=200):
    """Beyaz zemin uzerine siyah dikey cizgi. yatay_bant=(y0,y1) -> L kosesi."""
    img = np.full((H, W), parlaklik, np.uint8)
    if gurultu:
        img = cv2.add(img, (np.random.randn(H, W) * 6).astype(np.int16).clip(-40, 40).astype(np.uint8))
    x = int(W * cx_orani)
    cv2.rectangle(img, (x - kalinlik // 2, 0), (x + kalinlik // 2, H), 25, -1)
    if yatay_bant:
        y0, y1 = yatay_bant
        cv2.rectangle(img, (x, y0), (W - 1, y1), 25, -1)
    return img

print("\n=== 1. DAC KONVANSIYONU ===")
d = CT.MotorLink._dac
kontrol("notr = 2048", d(0.0) == 2048, f"-> {d(0.0)}")
kontrol("ileri > notr (YON=+1)", d(0.55) > 2048, f"u=0.55 -> {d(0.55)}")
kontrol("geri  < notr", d(-0.55) < 2048, f"u=-0.55 -> {d(-0.55)}")
kontrol("tam gaz 0..4095 icinde", 0 <= d(1.0) <= 4095 and 0 <= d(-1.0) <= 4095,
        f"{d(-1.0)}..{d(1.0)}")
kontrol("simetrik", abs((d(0.9) - 2048) + (d(-0.9) - 2048)) <= 1)
# Eski pivot: motor_sur(1150, 2750) -> notre gore -898 / +702 = ASIMETRIK.
# Yeni pivot simetrik olmali (asimetri donerken yana kaydiriyordu), ama
# eski calisan degerlerin bandinda kalmali.
ps, pi_ = d(-CT.PIVOT_HIZ), d(CT.PIVOT_HIZ)
kontrol("pivot simetrik (eski asimetri giderildi)",
        abs((ps - 2048) + (pi_ - 2048)) <= 1,
        f"({ps}, {pi_}) -> ofset {ps-2048:+d}/{pi_-2048:+d}  eski: -898/+702")
kontrol("pivot eski degerlerin bandinda",
        abs(ps - 1150) < 150 and abs(pi_ - 2750) < 150,
        f"({ps}, {pi_})  eski: (1150, 2750)")
kontrol("ESKI TEMEL_HIZ=1550 geri vitesde",
        1550 < 2048, "1550 < 2048 -> YON=+1'de GERI  [orijinal koddaki hata]")

print("\n=== 2. SERIT DEDEKTORU ===")
det = CT.SeritDedektoru(W, H)
for _ in range(6):                       # esik filtresinin oturmasi icin
    det.olc(sahne(0.5), CT.BANT_YAKIN)
m = det.olc(sahne(0.5), CT.BANT_YAKIN)
kontrol("ortadaki cizgi bulundu", m.gecerli)
kontrol("ortadaki cizgi cx ~ 0", abs(m.cx) < 0.08, f"cx={m.cx:+.3f}")

m = det.olc(sahne(0.78), CT.BANT_YAKIN)
kontrol("sagdaki cizgi cx > 0", m.gecerli and m.cx > 0.4, f"cx={m.cx:+.3f}")
m = det.olc(sahne(0.22), CT.BANT_YAKIN)
kontrol("soldaki cizgi cx < 0", m.gecerli and m.cx < -0.4, f"cx={m.cx:+.3f}")

bos = np.full((H, W), 200, np.uint8)
m = det.olc(bos, CT.BANT_YAKIN)
kontrol("bos zeminde cizgi YOK", not m.gecerli)

karanlik = np.full((H, W), 15, np.uint8)   # kamera kapali / tam golge
m = det.olc(karanlik, CT.BANT_YAKIN)
kontrol("tamamen koyu karede cizgi YOK (Otsu kacmasi engellendi)", not m.gecerli)

kontrol("esik mantikli aralikta",
        det.ESIK_TABAN <= det.esik_f <= det.ESIK_TAVAN, f"esik={det.esik_f:.1f}")

print("\n=== 3. L-VIRAJ (KOSE) TESPITI ===")
det2 = CT.SeritDedektoru(W, H)
kose_img = sahne(0.5, yatay_bant=(int(H*0.74), int(H*0.90)))
for _ in range(6):
    det2.olc(kose_img, CT.BANT_YAKIN)
yk = det2.olc(kose_img, CT.BANT_YAKIN)
uz = det2.olc(kose_img, CT.BANT_UZAK, det2.esik_f)
kontrol("kose: yakin bant yassi kontur", yk.gecerli and yk.en_boy > CT.KOSE_EN_BOY,
        f"en_boy={yk.en_boy:.2f} (esik {CT.KOSE_EN_BOY})")
kontrol("kose: centroid saga kacti", yk.cx > CT.KOSE_CX_ESIK, f"cx={yk.cx:+.3f}")

duz = sahne(0.5)
det3 = CT.SeritDedektoru(W, H)
for _ in range(6): det3.olc(duz, CT.BANT_YAKIN)
yd = det3.olc(duz, CT.BANT_YAKIN)
kontrol("duz yolda kose tetiklenmiyor",
        not (abs(yd.cx) > CT.KOSE_CX_ESIK and yd.en_boy > CT.KOSE_EN_BOY),
        f"cx={yd.cx:+.3f} en_boy={yd.en_boy:.2f}")

print("\n=== 4. PID ISARETI (kritik) ===")
pid = CT.PID(CT.Kp, CT.Ki, CT.Kd, CT.I_SINIR, CT.D_FILTRE)
hata = +0.5                     # cizgi SAGDA
for _ in range(5):
    dr = pid.hesapla(hata, 0.033)
hiz = CT.HIZ_SEYIR
u_sol, u_sag = hiz + dr, hiz - dr
kontrol("cizgi sagda -> sol teker hizli (SAGA doner)", u_sol > u_sag,
        f"direksiyon={dr:+.3f}  sol={u_sol:+.3f} sag={u_sag:+.3f}")
kontrol("cizgi sagda -> sol DAC > sag DAC", d(u_sol) > d(u_sag),
        f"DAC {d(u_sol)} > {d(u_sag)}")

pid.sifirla()
hata = -0.5                     # cizgi SOLDA
for _ in range(5):
    dr = pid.hesapla(hata, 0.033)
kontrol("cizgi solda -> sag teker hizli (SOLA doner)",
        (hiz + dr) < (hiz - dr), f"direksiyon={dr:+.3f}")

print("\n=== 5. PID SAGLAMLIK ===")
pid.sifirla()
for _ in range(400):
    dr = pid.hesapla(1.0, 0.033)       # surekli doymus hata
kontrol("anti-windup: integral patlamiyor", abs(pid.ki * pid.integral) <= CT.I_SINIR + 1e-6,
        f"I katkisi={pid.ki*pid.integral:+.3f} sinir={CT.I_SINIR}")
kontrol("cikis makul", abs(dr) < 5.0, f"cikis={dr:+.3f}")

pid.sifirla()
pid.hesapla(0.0, 0.033)
dr = pid.hesapla(0.9, 1e-6)            # dt ~ 0 (donma/jitter)
kontrol("dt~0'da turev patlamiyor", np.isfinite(dr) and abs(dr) < 5.0, f"cikis={dr:+.3f}")

print("\n=== 6. HIZ OLCEKLEME / DOYMA ===")
for dr_test, ad in ((0.0, "duz"), (0.9, "keskin viraj")):
    egrilik = abs(dr_test)
    h = max(CT.HIZ_MIN, CT.HIZ_SEYIR * (1.0 - CT.YAVASLAMA * min(1.0, egrilik)))
    us, ug = h + dr_test, h - dr_test
    tepe = max(abs(us), abs(ug), 1.0)
    us, ug = us / tepe, ug / tepe
    kontrol(f"{ad}: cikislar -1..1 icinde", -1 <= us <= 1 and -1 <= ug <= 1,
            f"hiz={h:.2f} sol={us:+.2f} sag={ug:+.2f} DAC=({d(us)},{d(ug)})")
kontrol("virajda hiz dusuyor",
        max(CT.HIZ_MIN, CT.HIZ_SEYIR*(1-CT.YAVASLAMA*0.9)) < CT.HIZ_SEYIR)

print("\n=== 7. MOTOR LINK (kuru mod) ===")
link = CT.MotorLink(kuru=True)
link.gonder(0.5, 0.5)
kontrol("paket uretildi", link._son_paket == (d(0.5), d(0.5)), f"{link._son_paket}")
link.dur()
kontrol("dur() -> notr", link._son_paket == (2048, 2048), f"{link._son_paket}")
link.gonder(9.0, -9.0)
kontrol("asiri deger kirpildi", 0 <= link._son_paket[0] <= 4095 and 0 <= link._son_paket[1] <= 4095,
        f"{link._son_paket}")
link.kapat()

print(f"\n{'='*52}\nGECTI: {gecti}   BASARISIZ: {basarisiz}\n{'='*52}")
sys.exit(1 if basarisiz else 0)
