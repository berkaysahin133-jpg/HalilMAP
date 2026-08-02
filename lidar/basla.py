#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""BASLA -- LiDAR'i sifirdan calistiran tek dosya.

Hicbir sey bilmene gerek yok. Su dosyayi cift tiklayip calistir ya da:

    python basla.py        (Windows)
    python3 basla.py       (Linux / Mac)

Yapacaklari:
  1. Eksik Python paketlerini kendisi kurar
  2. Bagli seri portlari tarar, LiDAR'i kendisi bulur
  3. Cihazla konusur (model, seri no, saglik) ve dogrular
  4. Sana menu sunar: canli goruntu / oda haritasi

Bu dosya c1.py, goster.py ve harita.py ile AYNI KLASORDE olmali.
"""

import os
import subprocess
import sys

KLASOR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, KLASOR)

CIZGI = "=" * 66


def baslik(s):
    print(f"\n{CIZGI}\n  {s}\n{CIZGI}")


def bekle():
    try:
        input("\n  Devam etmek icin ENTER...")
    except (EOFError, KeyboardInterrupt):
        pass


# ============================================================================
#  ADIM 0 -- dosyalar yerinde mi
# ============================================================================
baslik("ADIM 0/4  --  Dosyalar kontrol ediliyor")
GEREKLI = ["c1.py", "goster.py", "harita.py"]
eksik_dosya = [d for d in GEREKLI if not os.path.exists(os.path.join(KLASOR, d))]
if eksik_dosya:
    print(f"  [HATA] Su dosyalar eksik: {', '.join(eksik_dosya)}")
    print(f"  Hepsi su klasorde olmali:\n     {KLASOR}")
    bekle()
    sys.exit(1)
print("  OK  c1.py, goster.py, harita.py bulundu")


# ============================================================================
#  ADIM 1 -- paketler
# ============================================================================
baslik("ADIM 1/4  --  Python paketleri")
PAKETLER = [("serial", "pyserial"), ("numpy", "numpy"),
            ("cv2", "opencv-python"), ("scipy", "scipy")]
eksik = []
for modul, pip_adi in PAKETLER:
    try:
        __import__(modul)
        print(f"  OK  {pip_adi}")
    except ImportError:
        print(f"  --  {pip_adi} YOK")
        eksik.append(pip_adi)

if eksik:
    print(f"\n  {len(eksik)} paket kuruluyor, biraz surebilir...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", *eksik])
        print("  OK  kuruldu")
    except Exception as e:
        print(f"\n  [HATA] Otomatik kurulum olmadi: {e}")
        print("  Su komutu elle calistir, sonra bu dosyayi tekrar ac:\n")
        print(f"     {sys.executable} -m pip install {' '.join(eksik)}\n")
        bekle()
        sys.exit(1)

import c1  # noqa: E402


# ============================================================================
#  ADIM 2 -- seri port
# ============================================================================
baslik("ADIM 2/4  --  LiDAR araniyor")
print("  Bagli seri portlar:")
portlar = c1.portlari_listele()

if not portlar:
    print("\n  [HATA] Hic seri port yok. Kontrol et:")
    print("    - LiDAR'in USB kablosu takili mi?")
    print("    - LiDAR'in kafasi DONUYOR mu? (donmuyorsa besleme yok)")
    print("    - Windows'ta: Aygit Yoneticisi > Baglanti noktalari (COM ve LPT)")
    print("      'CP210x' veya 'CH340' gorunuyor mu? Gorunmuyorsa surucu lazim.")
    print("    - Linux'ta:  sudo usermod -aG dialout $USER   (sonra cikis/giris)")
    bekle()
    sys.exit(1)

# Elle port verildiyse onu kullan:  python basla.py --port COM5
elle = None
if "--port" in sys.argv:
    i = sys.argv.index("--port")
    if i + 1 < len(sys.argv):
        elle = sys.argv[i + 1]

secili = elle or c1.port_bul()
print(f"\n  Denenecek port: {secili}" + ("  (elle verildi)" if elle else ""))


# ============================================================================
#  ADIM 3 -- cihazla konus
# ============================================================================
baslik("ADIM 3/4  --  Cihaza baglaniliyor")
lidar = None
denenecek = [secili] if elle else ([secili] + [p for p in portlar if p != secili])

for port in denenecek:
    print(f"\n  {port} @ 460800 deneniyor...")
    try:
        lidar = c1.RPLidarC1(port, 460800)
        bilgi = lidar.bilgi()
        saglik = lidar.saglik()
        print(f"  OK  BAGLANDI!")
        print(f"      model    : {bilgi['model']}")
        print(f"      yazilim  : {bilgi['yazilim']}")
        print(f"      seri no  : {bilgi['seri_no']}")
        print(f"      saglik   : {saglik['metin']}  (kod {saglik['hata_kodu']})")
        if saglik["durum"] == 2:
            print("      [UYARI] Cihaz hata durumunda. USB'yi cikar tak.")
        secili = port
        break
    except Exception as e:
        print(f"  --  olmadi: {e}")
        try:
            if lidar:
                lidar.kapat()
        except Exception:
            pass
        lidar = None

if lidar is None:
    print("\n  [HATA] Hicbir porta baglanilamadi.")
    print("\n  En sik sebepler:")
    print("    1. LiDAR'in kafasi donmuyor  -> USB yeterli akim vermiyor,")
    print("       baska bir USB porta tak (arka panel tercih).")
    print("    2. Yanlis port -> yukaridaki listeden dogru olani sec:")
    print(f"         python basla.py --port COM5")
    print("    3. Baska bir program portu tutuyor -> RoboStudio / Arduino IDE")
    print("       / seri monitor aciksa KAPAT.")
    print("    4. Linux izin sorunu -> sudo usermod -aG dialout $USER, cikis/giris")
    bekle()
    sys.exit(1)

# Baglanti dogrulandi, portu birak (alt programlar kendisi acacak)
lidar.kapat()


# ============================================================================
#  ADIM 4 -- ne yapmak istiyorsun
# ============================================================================
def calistir(betik, *arg):
    komut = [sys.executable, os.path.join(KLASOR, betik), "--port", secili, *arg]
    print(f"\n  > {' '.join(komut[1:])}\n")
    try:
        subprocess.call(komut)
    except KeyboardInterrupt:
        pass


while True:
    baslik("ADIM 4/4  --  Ne yapalim?")
    print("""
   1  CANLI GORUNTU        LiDAR ne goruyor, ekranda izle
                           (ilk once bunu yap -- calistigini gor)

   2  ODA HARITASI         LiDAR'i masaya/yere ORTAYA koy, SABIT dur
                           tek 360 tarama -> harita.png

   3  GEZEREK HARITA       LiDAR'i elinde YAVASCA gezdir,
   (SLAM)                  harita buyuye buyuye olussun

   4  KAYIT AL             gez, kaydet -> sonra robotsuz tekrar incele

   0  CIKIS
""")
    try:
        s = input("  Secim: ").strip()
    except (EOFError, KeyboardInterrupt):
        break

    if s == "1":
        print("\n  Pencere acilacak. Cikmak icin pencereye tiklayip 'q' bas.")
        calistir("goster.py")
    elif s == "2":
        print("\n  LiDAR'i sabit tut! 5 tarama alinacak.")
        calistir("harita.py", "--tek")
        print(f"\n  Harita yazildi: {os.path.join(KLASOR, 'harita.png')}")
    elif s == "3":
        print("""
  NASIL GEZDIRECEKSIN -- bunlar onemli:
    * YAVAS yuru. Saniyede 10 tarama aliyor; hizli gidersen ardisik
      taramalar ortusmez ve hizalayamaz.
    * Donerken DAHA DA yavas. Kayma en cok donuste birikir.
    * LiDAR'i YATAY tut, yuksekligini degistirme.
    * Ekranda "eslesme %" yaziyor. %35'in altina duserse kayboldu
      demektir; dur, biraz geri git, toparlanir.
    * 's' = anlik kaydet,  'q' = bitir ve kaydet
""")
        bekle()
        calistir("harita.py", "--slam")
        print(f"\n  Harita yazildi: {os.path.join(KLASOR, 'harita.png')}")
    elif s == "4":
        ad = input("  Kayit adi (orn: oda1): ").strip() or "kayit"
        calistir("goster.py", "--kayit", ad)
        print(f"\n  Kaydedildi: {ad}.npz")
        print(f"  Sonra harita cikarmak icin:")
        print(f"     python harita.py --oynat {ad}.npz --slam")
    elif s == "0":
        break
    else:
        print("  1, 2, 3, 4 veya 0 yaz.")

print("\n  Bitti.")
