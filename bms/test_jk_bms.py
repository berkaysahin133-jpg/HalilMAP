#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JK BMS surucu testi -- BATARYA TAKILI OLMADAN calisir.

Test verisi uydurma degil: gercek bir JK BMS'ten alinmis 300 baytlik
cerceveler kullaniliyor. En guclu dogrulama su iki capraz kontrol:

  1. Hucre gerilimlerinin TOPLAMI, cercevenin ayri bir yerindeki paket
     gerilimi alanina esit olmali. Ofsetlerden biri yanlissa tutmaz.
  2. kalan_kapasite / tam_kapasite orani, ayri bir bayttaki SOC degerine
     esit olmali.

Iki bagimsiz alan birbirini dogruluyorsa cozucu dogrudur.

    python3 test_jk_bms.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jk_bms as J

GECTI = BASARISIZ = 0


def kontrol(ad, sart, detay=""):
    global GECTI, BASARISIZ
    if sart:
        GECTI += 1
        print(f"  OK   {ad}  {detay}")
    else:
        BASARISIZ += 1
        print(f"  FAIL {ad}  {detay}")


def baslik(s):
    print(f"\n{'=' * 68}\n {s}\n{'=' * 68}")


CERCEVE = J._ORNEK_CERCEVE

# ============================================================================
baslik("1. CERCEVE BUTUNLUGU")
kontrol("cerceve 300 bayt", len(CERCEVE) == 300, f"{len(CERCEVE)} bayt")
kontrol("baslik 55 AA EB 90", CERCEVE[:4] == J.BASLIK_YANIT, CERCEVE[:4].hex().upper())
kontrol("cerceve tipi 0x02 (hucre bilgisi)", CERCEVE[4] == J.TIP_HUCRE)
kontrol("CRC dogru", J.crc(CERCEVE[:299]) == CERCEVE[299],
        f"hesap 0x{J.crc(CERCEVE[:299]):02X} = cerceve 0x{CERCEVE[299]:02X}")

# ============================================================================
baslik("2. KOMUT CERCEVESI")
k = J.komut_cercevesi(J.KOMUT_HUCRE_BILGISI)
kontrol("komut 20 bayt", len(k) == 20, f"{len(k)} bayt")
kontrol("onek AA 55 90 EB", k[:4] == J.BASLIK_ISTEK, k[:4].hex().upper())
kontrol("adres 0x96 5. bayta yazildi", k[4] == 0x96)
kontrol("komut CRC'si dogru", k[19] == J.crc(k[:19]), f"0x{k[19]:02X}")
kontrol("cihaz bilgisi komutu 0x97",
        J.komut_cercevesi(J.KOMUT_CIHAZ_BILGISI)[4] == 0x97)

# ============================================================================
baslik("3. SURUM OTOMATIK BULUNUYOR MU")
kontrol("bu cerceve 24S olarak taniniyor", J.surum_tahmin_et(CERCEVE) == "24S",
        J.surum_tahmin_et(CERCEVE))

d = J.hucre_bilgisi_coz(CERCEVE, "24S")
yanlis = J.hucre_bilgisi_coz(CERCEVE, "32S")
kontrol("yanlis surumle degerler tutarsizlasiyor",
        abs(yanlis["toplam_gerilim_v"] - sum(v for v in yanlis["hucre_gerilimleri"] if v > 0)) > 1.0,
        f"32S ile paket {yanlis['toplam_gerilim_v']:.2f} V, "
        f"hucre toplami {sum(v for v in yanlis['hucre_gerilimleri'] if v > 0):.2f} V")

# ============================================================================
baslik("4. CAPRAZ DOGRULAMA  --  ofsetler dogru mu")
hucre_toplami = sum(v for v in d["hucre_gerilimleri"] if v > 0)
fark_mv = abs(d["toplam_gerilim_v"] - hucre_toplami) * 1000
kontrol("hucre gerilimleri toplami = paket gerilimi", fark_mv < 50,
        f"{hucre_toplami:.3f} V vs {d['toplam_gerilim_v']:.3f} V "
        f"(fark {fark_mv:.0f} mV)")

soc_kapasiteden = d["kalan_kapasite_ah"] / d["tam_kapasite_ah"] * 100
kontrol("kalan/tam kapasite orani = SOC alani", abs(soc_kapasiteden - d["soc_yuzde"]) < 2.0,
        f"kapasiteden %{soc_kapasiteden:.1f}, SOC alani %{d['soc_yuzde']}")

# ============================================================================
baslik("5. DEGERLER FIZIKSEL OLARAK MAKUL MU")
kontrol("hucre sayisi 16", d["hucre_sayisi"] == 16, f"{d['hucre_sayisi']}")
kontrol("hucre gerilimleri LiFePO4 araliginda (2.5-3.65 V)",
        all(2.5 < v < 3.65 for v in d["hucre_gerilimleri"][:16]),
        f"{d['min_hucre_v']} - {d['max_hucre_v']} V")
kontrol("kullanilmayan hucreler 0 V",
        all(v == 0 for v in d["hucre_gerilimleri"][16:]))
kontrol("hucre dengesizligi kucuk (< 100 mV)", d["delta_hucre_v"] < 0.1,
        f"{d['delta_hucre_v']*1000:.0f} mV")
kontrol("SOC 0-100 arasinda", 0 <= d["soc_yuzde"] <= 100, f"%{d['soc_yuzde']}")
kontrol("SOH 0-100 arasinda", 0 <= d["soh_yuzde"] <= 100, f"%{d['soh_yuzde']}")
kontrol("kalan kapasite <= tam kapasite",
        d["kalan_kapasite_ah"] <= d["tam_kapasite_ah"],
        f"{d['kalan_kapasite_ah']} / {d['tam_kapasite_ah']} Ah")
kontrol("sicakliklar oda sicakliginda (-20..60 C)",
        all(-20 < d[k] < 60 for k in ("sicaklik_1_c", "sicaklik_2_c", "mosfet_sicaklik_c")),
        f"{d['sicaklik_1_c']} / {d['sicaklik_2_c']} / {d['mosfet_sicaklik_c']} C")
kontrol("hata listesi bos (saglikli paket)", d["hatalar"] == [], str(d["hatalar"]))
kontrol("guc = gerilim x akim",
        abs(d["guc_w"] - d["toplam_gerilim_v"] * d["akim_a"]) < 0.2,
        f"{d['guc_w']} W")

# ============================================================================
baslik("6. AKIM ISARETI VE DURUM")
import copy


def akimli_cerceve(amper):
    """Cerceveyi verilen akimla yeniden yazip CRC'sini duzeltir."""
    c = bytearray(CERCEVE)
    ham = int(round(amper * 1000)) & 0xFFFFFFFF
    c[126:130] = ham.to_bytes(4, "little")
    c[299] = J.crc(c[:299])
    return bytes(c)


for amper, beklenen in [(25.0, "SARJ"), (-40.0, "DESARJ"), (0.0, "BEKLEME")]:
    x = J.hucre_bilgisi_coz(akimli_cerceve(amper), "24S")
    kontrol(f"{amper:+.0f} A -> {beklenen}",
            x["durum"] == beklenen and abs(x["akim_a"] - amper) < 0.01,
            f"okunan {x['akim_a']:+.1f} A, durum {x['durum']}")

sarj = J.hucre_bilgisi_coz(akimli_cerceve(20.0), "24S")
kontrol("sarjda sarj gucu pozitif, desarj gucu sifir",
        sarj["sarj_gucu_w"] > 0 and sarj["desarj_gucu_w"] == 0,
        f"sarj {sarj['sarj_gucu_w']} W, desarj {sarj['desarj_gucu_w']} W")
desarj = J.hucre_bilgisi_coz(akimli_cerceve(-20.0), "24S")
kontrol("desarjda tersi", desarj["desarj_gucu_w"] > 0 and desarj["sarj_gucu_w"] == 0,
        f"sarj {desarj['sarj_gucu_w']} W, desarj {desarj['desarj_gucu_w']} W")
kontrol("desarjda kalan sure hesaplaniyor",
        desarj["kalan_sure_sa"] is not None and desarj["kalan_sure_sa"] > 0,
        f"{desarj['kalan_sure_sa']} saat")
kontrol("beklemede kalan sure None", d["kalan_sure_sa"] is None)

# ============================================================================
baslik("7. HATA BAYRAKLARI")


def hatali_cerceve(maske):
    c = bytearray(CERCEVE)
    c[136:138] = (maske & 0xFFFF).to_bytes(2, "little")
    c[299] = J.crc(c[:299])
    return bytes(c)


x = J.hucre_bilgisi_coz(hatali_cerceve(0b1), "24S")
kontrol("bit 0 -> hucre asiri gerilim", x["hatalar"] == ["Hucre asiri gerilim"], str(x["hatalar"]))
x = J.hucre_bilgisi_coz(hatali_cerceve(0b1000000010), "24S")
kontrol("iki bit birden okunuyor", len(x["hatalar"]) == 2, str(x["hatalar"]))

# ============================================================================
baslik("8. CERCEVE TOPLAYICI  --  BLE 20'ser bayt gonderir")
t = J.CerceveToplayici()
cikan = []
for i in range(0, 300, 20):                       # BLE bildirimi taklidi
    cikan += t.besle(CERCEVE[i:i + 20])
kontrol("20'ser baytlik parcalardan cerceve kuruldu", len(cikan) == 1, f"{len(cikan)} cerceve")
kontrol("kurulan cerceve orijinaliyle ayni", cikan and cikan[0] == CERCEVE)

t = J.CerceveToplayici()
yarim = t.besle(CERCEVE[:150])                    # yarida kesilen cerceve
sonra = t.besle(CERCEVE)                          # yeni onek gelir
kontrol("yarim cerceve sonrakini bozmuyor",
        yarim == [] and len(sonra) == 1, f"{len(sonra)} cerceve")

t = J.CerceveToplayici()
bozuk = bytearray(CERCEVE)
bozuk[299] ^= 0xFF
kontrol("CRC hatasi olan cerceve reddediliyor",
        t.besle(bytes(bozuk)) == [] and t.bozuk_crc == 1)

# ============================================================================
baslik("9. HATALI GIRDIYE DAYANIKLILIK")
for ad, veri in [("kisa cerceve", CERCEVE[:100]),
                 ("yanlis baslik", b"\x00\x00\x00\x00" + CERCEVE[4:]),
                 ("yanlis tip", CERCEVE[:4] + b"\x03" + CERCEVE[5:])]:
    try:
        J.hucre_bilgisi_coz(veri, "24S")
        kontrol(f"{ad} reddediliyor", False, "hata verilmedi")
    except J.BmsHatasi:
        kontrol(f"{ad} reddediliyor", True)

# ============================================================================
baslik("10. SAHTE OKUYUCU  --  batarya yokken arayuz gelistirmek icin")
import time

oku = J.SahteOkuyucu()
t0 = time.monotonic()
while oku.durum()["veri"] is None and time.monotonic() - t0 < 5:
    time.sleep(0.1)
s = oku.durum()
kontrol("sahte okuyucu veri uretiyor", s["veri"] is not None)
kontrol("bagli olarak isaretlendi", s["bagli"] is True)
kontrol("cihaz bilgisi de var", s["cihaz"] is not None and "model" in s["cihaz"],
        s["cihaz"]["model"] if s["cihaz"] else "-")
kontrol("hucre direncleri ozetten cikarildi (JSON kucuk kalsin)",
        "hucre_dirençleri" not in s["veri"])
import json
kontrol("cikti JSON'a cevrilebiliyor", isinstance(json.dumps(s), str),
        f"{len(json.dumps(s))} karakter")
oku.kapat()

# ============================================================================
print(f"\n{'=' * 68}")
print(f" GECTI: {GECTI}    BASARISIZ: {BASARISIZ}")
print(f"{'=' * 68}")
sys.exit(1 if BASARISIZ else 0)
