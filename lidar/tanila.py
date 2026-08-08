#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TANILA -- LiDAR'dan veri gelmiyorsa BUNU CALISTIR.

    python tanila.py
    python tanila.py --port COM5

Ne yapar: cihazla tek tek konusur, hangi adimda ne oldugunu yazar ve sonunda
"sorun su" der. Ciktiyi ayrica tanila_cikti.txt dosyasina yazar -- o dosyayi
oldugu gibi paylasabilirsin.

Bu dosya bilerek c1.py'den BAGIMSIZ calisir (ham seri port kullanir). Boylece
surucudeki olasi bir hata gercegi gizleyemez.
"""

import argparse
import os
import platform
import sys
import time

KLASOR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, KLASOR)

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    print("pyserial yok:  pip install pyserial")
    sys.exit(1)

BAYRAK = b"\xA5"
STOP = b"\x25"
RESET = b"\x40"
SCAN = b"\x20"
BILGI = b"\x50"
SAGLIK = b"\x52"

HATLAR = [(False, True), (False, False), (True, True), (True, False)]

GUNLUK = []


def yaz(s=""):
    print(s)
    GUNLUK.append(s)


def baslik(s):
    yaz("")
    yaz("=" * 68)
    yaz("  " + s)
    yaz("=" * 68)


# ---------------------------------------------------------------- yardimcilar
def komut(ser, kod):
    ser.write(BAYRAK + kod)
    ser.flush()


def tanimlayici(ser):
    """7 baytlik yanit tanimlayicisi. (ham, uzunluk, mod, tip) doner."""
    d = ser.read(7)
    if len(d) != 7:
        return d, None, None, None
    if d[0:2] != b"\xA5\x5A":
        return d, None, None, None
    uzunluk = d[2] | (d[3] << 8) | (d[4] << 16) | ((d[5] & 0x3F) << 24)
    return d, uzunluk, d[5] >> 6, d[6]


def bayt_topla(ser, sure):
    """`sure` saniye boyunca gelen her seyi toplar (erken cikmaz -- hiz olcecegiz)."""
    bitis = time.monotonic() + sure
    toplam = bytearray()
    while time.monotonic() < bitis:
        n = ser.in_waiting
        if n:
            toplam.extend(ser.read(n))
        else:
            time.sleep(0.01)
    return bytes(toplam)


def olcum_coz(b):
    b0, b1, b2, b3, b4 = b
    if bool(b0 & 1) == bool((b0 >> 1) & 1):
        return None
    if (b1 & 1) != 1:
        return None
    return (b0 >> 2, ((b1 >> 1) | (b2 << 7)) / 64.0, (b3 | (b4 << 8)) / 4.0)


def coz_dene(ham):
    """Ham bayt yigininda hizalanip kac gecerli olcum cikardigimizi sayar."""
    en_iyi = (0, 0, [])
    for kaydir in range(min(5, max(0, len(ham) - 5) + 1)):
        i, iyi, ornek = kaydir, 0, []
        while i + 5 <= len(ham):
            s = olcum_coz(ham[i:i + 5])
            if s is None:
                break
            iyi += 1
            if len(ornek) < 6:
                ornek.append(s)
            i += 5
        if iyi > en_iyi[0]:
            en_iyi = (iyi, kaydir, ornek)
    return en_iyi


# ============================================================================
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None)
    ap.add_argument("--baud", type=int, default=460800)
    args = ap.parse_args()

    baslik("0 -- ORTAM")
    yaz(f"  isletim sistemi : {platform.system()} {platform.release()}")
    yaz(f"  python          : {sys.version.split()[0]}")
    yaz(f"  pyserial        : {serial.__version__}")

    # ---------------------------------------------------------------- portlar
    baslik("1 -- SERI PORTLAR")
    portlar = list(list_ports.comports())
    if not portlar:
        yaz("  HIC SERI PORT YOK.")
        yaz("")
        yaz("  Bu, LiDAR'in bilgisayara hic gorunmedigi anlamina gelir:")
        yaz("    * USB kablosunu cikar tak")
        yaz("    * Baska bir USB porta tak")
        yaz("    * Windows: Aygit Yoneticisi > 'Baglanti noktalari (COM ve LPT)'")
        yaz("      CP210x / CH340 gorunmuyorsa surucu kur (Silicon Labs CP210x VCP)")
        yaz("    * Linux: dmesg | tail   ve   sudo usermod -aG dialout $USER")
        return bitir(1)
    for p in portlar:
        vid = f"{p.vid:04X}:{p.pid:04X}" if p.vid else "----:----"
        yaz(f"  {p.device:12s}  {vid}  {p.description}")

    port = args.port or portlar[0].device
    yaz("")
    yaz(f"  Kullanilacak port: {port}")

    # ---------------------------------------------------------------- baglan
    baslik("2 -- PORT ACILIYOR")
    try:
        ser = serial.Serial(port, args.baud, timeout=1.0)
    except Exception as e:
        yaz(f"  ACILAMADI: {e}")
        yaz("")
        yaz("  'Access is denied' / 'Permission denied' ise portu baska program")
        yaz("  tutuyordur: RoboStudio, Arduino IDE, seri monitor, baska bir")
        yaz("  python penceresi. Hepsini KAPAT ve tekrar dene.")
        return bitir(1)
    yaz(f"  ACILDI  {port} @ {args.baud} baud")
    time.sleep(0.2)
    ser.reset_input_buffer()

    # ---------------------------------------------------------------- konusma
    baslik("3 -- CIHAZ KONUSUYOR MU (model / saglik)")
    konusuyor = False
    try:
        komut(ser, BILGI)
        ham, uzunluk, mod, tip = tanimlayici(ser)
        yaz(f"  GET_INFO tanimlayici : {ham.hex(' ').upper() or '(bos)'}")
        if uzunluk:
            d = ser.read(uzunluk)
            yaz(f"  govde ({len(d)}/{uzunluk} bayt)  : {d.hex(' ').upper()}")
            if len(d) >= 20:
                yaz(f"    model    : {d[0]}   (C1 = 65)")
                yaz(f"    yazilim  : {d[2]}.{d[1]}")
                yaz(f"    donanim  : {d[3]}")
                yaz(f"    seri no  : {d[4:20][::-1].hex().upper()}")
                konusuyor = True
    except Exception as e:
        yaz(f"  GET_INFO hata: {e}")

    try:
        ser.reset_input_buffer()
        komut(ser, SAGLIK)
        ham, uzunluk, mod, tip = tanimlayici(ser)
        if uzunluk:
            d = ser.read(uzunluk)
            if len(d) >= 3:
                durum = {0: "iyi", 1: "uyari", 2: "HATA"}.get(d[0], "?")
                yaz(f"    saglik   : {durum}  (kod {d[1] | (d[2] << 8)})")
                if d[0] == 2:
                    yaz("    >>> Cihaz HATA durumunda. USB'yi cikar 5 sn bekle tak.")
    except Exception as e:
        yaz(f"  GET_HEALTH hata: {e}")

    if not konusuyor:
        yaz("")
        yaz("  Cihaz cevap VERMIYOR. Sebep sirasiyla:")
        yaz("    1. Yanlis port -> yukaridaki listeden digerini dene:")
        yaz(f"         python tanila.py --port COM4")
        yaz("    2. Yanlis baud -> C1 460800'dur. Elindeki A1 ise 115200:")
        yaz("         python tanila.py --baud 115200")
        yaz("    3. TX/RX kablolari ters ya da kablo bozuk.")
        ser.close()
        return bitir(1)
    yaz("")
    yaz("  SONUC: port, baud ve kablo DOGRU. Cihaz konusuyor.")

    # ---------------------------------------------------- istenmeden veri var mi
    baslik("4 -- KOMUTSUZ DINLEME (1 sn)")
    ser.reset_input_buffer()
    bos = bayt_topla(ser, 1.0)
    yaz(f"  hic komut vermeden gelen: {len(bos)} bayt   "
        f"({'normal -- sessiz olmali' if len(bos) < 5 else 'DIKKAT: cihaz zaten tarama modunda'})")
    if len(bos) >= 5:
        yaz(f"  ilk baytlar: {bos[:30].hex(' ').upper()}")

    # ---------------------------------------------------------------- SCAN testi
    baslik("5 -- TARAMA TESTI (DTR/RTS kombinasyonlari)")
    yaz("  Her denemede: STOP -> hatlari ayarla -> SCAN -> 2.5 sn dinle")
    yaz("")
    yaz("  DTR    RTS    tanimlayici   gelen bayt   bayt/sn   cozulen olcum")
    yaz("  " + "-" * 62)

    sonuclar = []
    for dtr, rts in HATLAR:
        try:
            komut(ser, STOP)
            time.sleep(0.15)
            ser.dtr = dtr
            ser.rts = rts
            time.sleep(0.6)              # hat degisimi cihazi resetleyebilir
            ser.reset_input_buffer()
            komut(ser, SCAN)
            ham_t, uzunluk, mod, tip = tanimlayici(ser)
            tanim = "OK(5)" if uzunluk == 5 else (
                f"uz={uzunluk}" if uzunluk is not None else "YOK")
            veri = bayt_topla(ser, 2.5)
            iyi, kaydir, ornek = coz_dene(veri)
            yaz(f"  {str(dtr):6s} {str(rts):6s} {tanim:12s} {len(veri):9d}   "
                f"{len(veri)/2.5:7.0f}   {iyi:6d}")
            sonuclar.append((dtr, rts, uzunluk, len(veri), iyi, ornek, veri))
        except Exception as e:
            yaz(f"  {str(dtr):6s} {str(rts):6s} hata: {e}")
            sonuclar.append((dtr, rts, None, 0, 0, [], b""))

    komut(ser, STOP)
    time.sleep(0.1)

    en_iyi = max(sonuclar, key=lambda s: (s[4], s[3]))
    toplam_bayt = sum(s[3] for s in sonuclar)
    tanim_ok = any(s[2] == 5 for s in sonuclar)

    # ---------------------------------------------------------------- karar
    baslik("6 -- SONUC")

    if en_iyi[4] > 50:
        dtr, rts, _, nbayt, iyi, ornek, _ = en_iyi
        yaz("  *** CALISIYOR ***")
        yaz(f"  Motor hatti: DTR={dtr}  RTS={rts}")
        yaz(f"  2.5 saniyede {nbayt} bayt, {iyi} gecerli olcum "
            f"(~{iyi/2.5:.0f} olcum/sn, beklenen ~5000)")
        yaz("")
        yaz("  Ornek olcumler (kalite, aci derece, mesafe mm):")
        for k, a, m in ornek:
            yaz(f"    kalite {k:3d}   aci {a:7.2f}   mesafe {m:8.1f} mm")
        if iyi / 2.5 < 2000:
            yaz("")
            yaz("  UYARI: olcum hizi dusuk. Kafa tam hizina cikmamis olabilir")
            yaz("  (besleme zayif). Yine de harita cikar, sadece nokta az olur.")
        yaz("")
        yaz("  SIRADAKI ADIM -- su komutlari calistir:")
        yaz(f"     python goster.py --port {port}")
        yaz(f"     python harita.py --port {port} --tek")
        yaz(f"     python harita.py --port {port} --slam")
        kod = 0

    elif toplam_bayt > 0:
        yaz("  Veri GELIYOR ama cozulemiyor.")
        yaz(f"  En cok bayt gelen: DTR={en_iyi[0]} RTS={en_iyi[1]} -> {en_iyi[3]} bayt")
        yaz(f"  Ilk baytlar: {en_iyi[6][:40].hex(' ').upper()}")
        yaz("")
        yaz("  Bu genelde BAUD hizinin yanlis olmasi demektir. Sunlari dene:")
        yaz(f"     python tanila.py --port {port} --baud 115200")
        yaz(f"     python tanila.py --port {port} --baud 256000")
        yaz("  Yukaridaki 'ilk baytlar' satirini paylas -- protokolu cozeriz.")
        kod = 1

    elif tanim_ok:
        yaz("  Cihaz SCAN komutunu KABUL EDIYOR ama tek bayt bile gondermiyor.")
        yaz("")
        yaz("  Yazilim tarafi calisiyor: port acildi, model okundu, saglik")
        yaz("  okundu, SCAN kabul edildi. Geriye tek soru kaldi:")
        yaz("")
        try:
            cevap = input("  >>> LiDAR'in KAFASI DONUYOR MU?  (e = evet / h = hayir): ")
        except (EOFError, KeyboardInterrupt):
            cevap = ""
        cevap = cevap.strip().lower()[:1]
        GUNLUK.append(f"  >>> Kafa donuyor mu? cevap: {cevap or '(bos)'}")
        yaz("")

        if cevap == "e":
            yaz("  Kafa donuyor ama veri yok -- bu NADIR bir durum.")
            yaz("  Sirasiyla dene:")
            yaz("    1. USB'yi cikar, 10 sn bekle, tak, bu testi tekrarla.")
            yaz("       (Cihaz yarim kalmis bir tarama modunda kilitlenmis olabilir.)")
            yaz("    2. Farkli baud hizlari:")
            yaz(f"         python tanila.py --port {port} --baud 115200")
            yaz(f"         python tanila.py --port {port} --baud 256000")
            yaz("    3. Baska bir USB porta tak (yine de akim dusuk olabilir).")
            yaz("    4. Cihazin firmware'i sadece EXPRESS_SCAN destekliyor olabilir;")
            yaz("       o zaman surucuye ikinci bir tarama modu eklemek gerekir.")
            yaz("")
            yaz("  >>> tanila_cikti.txt dosyasini paylas, EXPRESS_SCAN'i ekleyelim.")
        else:
            yaz("  Kafa donmuyor -> sorun BESLEME. Yazilimla cozulmez.")
            yaz("")
            yaz("  SIRAYLA YAP, her adimdan sonra bu testi tekrarla:")
            yaz("    1. BASKA BIR USB PORTA TAK.")
            yaz("       - Masaustunde: kasanin ARKA panelindeki portlar (anakart uzeri)")
            yaz("       - Dizustunde: sarj adaptoru TAKILI iken dene")
            yaz("       - USB hub / uzatma kablosu kullaniyorsan CIKAR, dogrudan tak")
            yaz("    2. Kabloyu degistir. Bazi USB kablolari sadece sarj icindir")
            yaz("       ve ince damarlidir; motor akiminda gerilim duser.")
            yaz("    3. Adaptor kartinda ayri 5V besleme girisi varsa oradan besle.")
            yaz("    4. Kafanin onunde nakliye banti / koruyucu kopuk varsa CIKAR.")
            yaz("    5. Kafayi parmakla hafifce cevir -- serbest donuyor mu, sikismis mi?")
        kod = 1

    else:
        yaz("  SCAN komutuna tanimlayici bile gelmedi.")
        yaz("  Cihaz bilgi veriyor ama tarama komutunu islemiyor -- nadir.")
        yaz("  Yap: USB'yi cikar, 10 saniye bekle, tak, bu testi tekrarla.")
        yaz("  Duzelmezse RESET denenecek...")
        try:
            komut(ser, RESET)
            time.sleep(1.0)
            ser.reset_input_buffer()
            komut(ser, SCAN)
            _, uz, _, _ = tanimlayici(ser)
            v = bayt_topla(ser, 2.0)
            yaz(f"  RESET sonrasi: tanimlayici uz={uz}, {len(v)} bayt geldi")
        except Exception as e:
            yaz(f"  RESET denemesi hata: {e}")
        kod = 1

    try:
        komut(ser, STOP)
        time.sleep(0.05)
        ser.close()
    except Exception:
        pass
    return bitir(kod)


def bitir(kod):
    yol = os.path.join(KLASOR, "tanila_cikti.txt")
    try:
        with open(yol, "w", encoding="utf-8") as f:
            f.write("\n".join(GUNLUK))
        print(f"\n  (Bu cikti su dosyaya da yazildi: {yol})")
    except Exception:
        pass
    try:
        input("\n  Kapatmak icin ENTER...")
    except (EOFError, KeyboardInterrupt):
        pass
    return kod


if __name__ == "__main__":
    sys.exit(main())
