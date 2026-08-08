#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""arac_kontrol/cizgi_takip.py (tek dosya surum) KAPALI CEVRIM dogrulamasi.

Simulatorden gercek kamera goruntusu uretilir, tek dosya kodu kostururulur,
Arduino'ya gonderdigi DAC paketleri geri cm/s'ye cevrilip araca uygulanir.
Gercek konumu bildigimiz icin sapma kesin olculur.
"""
import sys, types, importlib, numpy as np, cv2
from unittest import mock

sys.path.insert(0, "/home/user/HalilMAP")
from robovizyon import Konfig
from robovizyon.simulasyon import SimKamera, SimArac, Sahne, pist_duz, pist_yay, pist_kose

SENARYOLAR = [
    ("duz yol",                   pist_duz(300),                                   (0., 0., 0.),      1.0, 4.0),
    ("duz / 12cm yanal ofset",    pist_duz(300),                                   (12., 0., 0.),     1.0, 4.0),
    ("duz / 20 derece egik",      pist_duz(300),                                   (0., 0., np.radians(20)), 1.0, 4.0),
    ("yay R=90 sag",              pist_yay(yaricap=90, aci_derece=90, giris=60, cikis=70, sag=True),  (0., 0., 0.), 1.0, 4.0),
    ("yay R=55 sol",              pist_yay(yaricap=55, aci_derece=90, giris=60, cikis=70, sag=False), (0., 0., 0.), 1.0, 4.0),
    ("duz / KARANLIK salon",      pist_duz(300),                                   (0., 0., 0.),      0.45, 4.0),
    ("duz / PARLAK + gurultu",    pist_duz(300),                                   (0., 0., 0.),      1.6, 12.0),
    ("90 KOSE sag",               pist_kose(giris=100, cikis=120, sag=True),       (0., 0., 0.),      1.0, 4.0),
    ("90 KOSE sol",               pist_kose(giris=100, cikis=120, sag=False),      (0., 0., 0.),      1.0, 4.0),
]

KF = Konfig()
SIM_KAM = SimKamera(KF.perspektif, KF.kamera)
HIZ_MAX = 45.0          # OFS_MAX = 900 buna karsilik gelir
DT = 1/30.


def kosu(ad, pist, baslangic, isik, gurultu, sure=26.0):
    sahne = Sahne(pist, SIM_KAM, KF.serit.cizgi_genislik_cm, gurultu=gurultu)
    arac = SimArac(KF.kontrol.iz_genisligi_cm, baslangic)
    kutu = {"i": 0, "durdu": False}
    yazilan = []

    class Kam:
        def __init__(s, *a, **k): pass
        def set(s, *a): return True
        def isOpened(s): return True
        def grab(s):
            kutu["i"] += 1
            return kutu["i"] <= int(sure / DT)
        def retrieve(s):
            if kutu["i"] > int(sure / DT) or kutu["durdu"]:
                return False, None
            return True, sahne.kare(arac.poz, isik_carpani=isik)
        def release(s): pass

    class Ser:
        is_open = True
        in_waiting = 0
        def __init__(s, *a, **k): pass
        def write(s, b):
            yazilan.append(b.decode().strip())
            return len(b)
        def read(s, n=1): return b""
        def reset_input_buffer(s): pass
        def reset_output_buffer(s): pass
        def close(s): pass

    saat = {"t": 1000.0}
    hatalar, durumlar, gecersiz = [], [], [0, 0]

    def sahte_waitkey(*a):
        # Modul henuz import edilirken calisir; sys.modules'tan erisiyoruz
        m = sys.modules.get("cizgi_takip")
        yon = getattr(m, "YON", -1) if m else -1
        # Her karede: son DAC paketini araca uygula, zamani ilerlet
        if yazilan:
            son = yazilan[-1]
            try:
                sol, sag = (int(v) for v in son[1:-1].split(","))
            except Exception:
                sol = sag = 2048
            v = lambda d: ((d - 2048) / yon) / 900.0 * HIZ_MAX
            # GERCEK DONANIM: motorlar fiziksel olarak takas bagli.
            # Kod MOTOR_TAKAS=True ile zaten cevirdigi icin burada geri ceviriyoruz
            # -- yani simulator gercek arabayi taklit ediyor.
            arac.adim(v(sag), v(sol), DT)
        saat["t"] += DT
        if m is not None:
            durumlar.append(getattr(m, "DURUM", "?"))
        if kutu["i"] > int(sure / DT) * 0.10:
            hatalar.append(sahne.capraz_hata(arac.poz))
        if np.hypot(arac.X - pist[-1, 0], arac.Y - pist[-1, 1]) < KF.perspektif.y_max_cm:
            kutu["durdu"] = True
        return -1

    pz = types.ModuleType("pyzbar.pyzbar"); pz.decode = lambda *a, **k: []
    sys.modules["pyzbar"] = types.ModuleType("pyzbar")
    sys.modules["pyzbar.pyzbar"] = pz

    with mock.patch("serial.Serial", Ser), \
         mock.patch("cv2.VideoCapture", Kam), \
         mock.patch("cv2.imshow", lambda *a: None), \
         mock.patch("cv2.waitKey", sahte_waitkey), \
         mock.patch("cv2.destroyAllWindows", lambda: None), \
         mock.patch("time.sleep", lambda *a: None), \
         mock.patch("time.monotonic", lambda: saat["t"]):
        sys.modules.pop("cizgi_takip", None)
        sys.path.insert(0, "/home/user/HalilMAP/arac_kontrol")
        importlib.import_module("cizgi_takip")

    sira = []
    for d in durumlar:
        if not sira or sira[-1] != d:
            sira.append(d)
    if not hatalar:
        return None
    h = np.array(hatalar)
    return {
        "ort": float(np.mean(h) * 10), "rms": float(np.sqrt(np.mean(h**2)) * 10),
        "max": float(np.max(np.abs(h)) * 10), "sira": sira,
        "son": arac.poz, "kare": kutu["i"],
    }


print(f"\n{'senaryo':<26}{'ORT':>9}{'RMS':>9}{'MAX':>9}   durum akisi")
print("-" * 100)
sonuc = {}
for ad, pist, bas, isik, gur in SENARYOLAR:
    r = kosu(ad, pist, bas, isik, gur)
    sonuc[ad] = r
    if r is None:
        print(f"{ad:<26}{'KOSU YOK':>27}")
        continue
    akis = " -> ".join(r["sira"][:7])
    print(f"{ad:<26}{r['ort']:+8.1f}mm{r['rms']:7.1f}mm{r['max']:7.1f}mm   {akis}")

print()
hata = 0
for ad, r in sonuc.items():
    if r is None:
        print(f"  FAIL {ad}: kosu yok"); hata += 1; continue
    duz = "duz" in ad
    kose = "KOSE" in ad
    if kose:
        ok = "PIVOT" in r["sira"] and "CIZGI_TAKIP" in r["sira"][r["sira"].index("PIVOT"):]
        yon_ok = (r["son"][0] > 30) if "sag" in ad else (r["son"][0] < -30)
        print(f"  {'OK  ' if ok else 'FAIL'} {ad}: pivot yapip takibe dondu")
        print(f"  {'OK  ' if yon_ok else 'FAIL'} {ad}: dogru yone gitti (X={r['son'][0]:+.0f} cm)")
        hata += (not ok) + (not yon_ok)
    else:
        e_rms = 12.0 if duz else 45.0
        ok = r["rms"] < e_rms
        print(f"  {'OK  ' if ok else 'FAIL'} {ad}: RMS {r['rms']:.1f} mm < {e_rms:.0f}")
        hata += not ok

print(f"\n{'='*60}\n  BASARISIZ: {hata}\n{'='*60}")
sys.exit(1 if hata else 0)
