# -*- coding: utf-8 -*-
"""HalilMAP LiDAR durum raporu -> Excel."""

import os
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter
from openpyxl.drawing.image import Image as XLImage
from PIL import Image as PILImage

S = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gorseller")
CIKTI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "HalilMAP_LiDAR_Durum_Raporu.xlsx")

YAZI = "Arial"
LACI = "1F3864"
MAVI = "2E5C8A"
ACIK = "DCE6F1"
YESIL = "C6EFCE"
YESIL_Y = "006100"
SARI = "FFEB9C"
SARI_Y = "9C6500"
KIRMIZI = "FFC7CE"
KIRMIZI_Y = "9C0006"
GRI = "F2F2F2"

ince = Side(style="thin", color="BFBFBF")
KENAR = Border(left=ince, right=ince, top=ince, bottom=ince)


def basliklandir(ws, baslik, altbaslik=""):
    ws["A1"] = baslik
    ws["A1"].font = Font(name=YAZI, size=16, bold=True, color="FFFFFF")
    ws["A1"].fill = PatternFill("solid", fgColor=LACI)
    ws["A1"].alignment = Alignment(vertical="center")
    ws.row_dimensions[1].height = 32
    if altbaslik:
        ws["A2"] = altbaslik
        ws["A2"].font = Font(name=YAZI, size=10, italic=True, color="595959")
        ws.row_dimensions[2].height = 18


def tablo_basligi(ws, satir, basliklar, ilk_sutun=1):
    for i, b in enumerate(basliklar):
        h = ws.cell(row=satir, column=ilk_sutun + i, value=b)
        h.font = Font(name=YAZI, size=10, bold=True, color="FFFFFF")
        h.fill = PatternFill("solid", fgColor=MAVI)
        h.alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
        h.border = KENAR
    ws.row_dimensions[satir].height = 30


def satir_yaz(ws, satir, degerler, ilk_sutun=1, kalin=False, dolgu=None, sar=True):
    for i, d in enumerate(degerler):
        h = ws.cell(row=satir, column=ilk_sutun + i, value=d)
        h.font = Font(name=YAZI, size=10, bold=kalin)
        h.alignment = Alignment(vertical="top", wrap_text=sar)
        h.border = KENAR
        if dolgu:
            h.fill = PatternFill("solid", fgColor=dolgu)
    return satir + 1


def genislik(ws, genislikler, ilk_sutun=1):
    for i, g in enumerate(genislikler):
        ws.column_dimensions[get_column_letter(ilk_sutun + i)].width = g


def resim_ekle(ws, yol, hucre, hedef_px=760):
    """Resmi olceklendirip sayfaya yerlestirir."""
    if not os.path.exists(yol):
        return
    kucuk = yol.replace(".png", f"_x{hedef_px}.png")
    with PILImage.open(yol) as im:
        oran = hedef_px / im.width
        im.resize((hedef_px, int(im.height * oran))).save(kucuk)
    ws.add_image(XLImage(kucuk), hucre)


wb = Workbook()

# ===========================================================================
# 1. OZET
# ===========================================================================
ws = wb.active
ws.title = "1. Özet"
basliklandir(ws, "HalilMAP  —  LiDAR Entegrasyonu Durum Raporu",
             "Slamtec RPLIDAR C1  |  Hazırlayan: Berkay Şahin  |  02.08.2026")
genislik(ws, [26, 46, 16, 40])

r = 4
ws.cell(row=r, column=1, value="DURUM: LiDAR ÇALIŞIYOR — canlı veri alınıyor, harita çıkarılıyor").font = \
    Font(name=YAZI, size=12, bold=True, color=YESIL_Y)
ws.cell(row=r, column=1).fill = PatternFill("solid", fgColor=YESIL)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.row_dimensions[r].height = 24

r += 2
tablo_basligi(ws, r, ["İş paketi", "Ne yapıldı", "Durum", "Kanıt / ölçüm"])
r += 1
satirlar = [
    ("Cihaz haberleşmesi",
     "RPLIDAR C1 için sıfırdan sürücü yazıldı (c1.py). 460800 baud, 5 baytlık "
     "ölçüm protokolü, bayt kayması olduğunda yeniden hizalanma.",
     "TAMAM",
     "Model 65, yazılım 1.2, seri no okundu; sağlık: iyi (kod 0)"),
    ("Canlı tarama",
     "goster.py — kuş bakışı canlı görüntü, kayıt ve tekrar oynatma.",
     "TAMAM",
     "423 nokta/tur, 10.0 tur/s ölçüldü"),
    ("2B haritalama",
     "harita.py — tek tarama haritası ve gezerek harita (ICP tarama eşleştirme, "
     "log-odds işgal ızgarası).",
     "TAMAM",
     "Doğrulama odası 6.00×4.00 m → 6.03×4.02 m ölçüldü"),
    ("Engel algılama / durma",
     "guvenlik.py — aracın önünde koridor bölgesi; SERBEST / YAVAŞ / DUR "
     "kararı ve hız çarpanı üretir.",
     "TAMAM",
     "31 otomatik kontrol; histerezis, gürültü eşiği, bayat veri testleri"),
    ("Teşhis altyapısı",
     "tanila.py — cihaz cevap verip veri göndermediğinde sorunu adım adım "
     "bulur ve rapor dosyası yazar.",
     "TAMAM",
     "Bağlantı sorunu bu araçla çözüldü"),
    ("Çizgi izlemeye entegrasyon",
     "Güvenlik katmanının çizgi izleme döngüsüne bağlanması.",
     "PAZARTESİ",
     "Plan: '6. Pazartesi Planı' sayfası"),
    ("Odometri (tekerlek geri beslemesi)",
     "Kelly KLS-S 'Meter' pini üzerinden hall sinyali sayımı.",
     "VİDEO SONRASI",
     "Pinout doğrulandı, test kodu hazır (darbe_test.ino)"),
]
for ad, ne, durum, kanit in satirlar:
    dolgu = YESIL if durum == "TAMAM" else (SARI if durum == "PAZARTESİ" else GRI)
    r = satir_yaz(ws, r, [ad, ne, durum, kanit], dolgu=dolgu)

r += 1
ws.cell(row=r, column=1, value="ÖZET SAYILAR").font = Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Gösterge", "Değer", "", ""])
r += 1
say_satir = r
# '3. Doğrulama Testleri' sayfasında başlık 4. satırda, veri 5-7. satırlarda,
# TOPLAM 8. satırda. Aralıklar oradaki yerleşimle doğrulandı.
for ad, deg in [("Yazılan Python modülü", 6),
                ("Otomatik doğrulama kontrolü (donanımsız)", "=SUM('3. Doğrulama Testleri'!C5:C7)"),
                ("Başarısız kontrol", "=SUM('3. Doğrulama Testleri'!D5:D7)"),
                ("Tarama frekansı (Hz)", 10),
                ("Tur başına nokta (ölçülen)", 423),
                ("Harita hücre boyu (cm)", 3)]:
    r = satir_yaz(ws, r, [ad, deg], sar=False)
for i in range(say_satir, r):
    ws.cell(row=i, column=2).alignment = Alignment(horizontal="center")
    ws.cell(row=i, column=2).font = Font(name=YAZI, size=11, bold=True)

r += 1
ws.cell(row=r, column=1,
        value="Not: Doğrulama testleri LiDAR takılı olmadan çalışır; sonuçlar "
              "sentetik ama YÖRÜNGESİ BİLİNEN bir odada ölçülmüştür. Yani "
              "\"harita güzel görünüyor\" denmiyor, kaç santim saptığı ölçülüyor.")
ws.cell(row=r, column=1).font = Font(name=YAZI, size=9, italic=True, color="595959")
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[r].height = 34

# ===========================================================================
# 2. DONANIM
# ===========================================================================
ws = wb.create_sheet("2. Donanım")
basliklandir(ws, "Donanım ve Arayüz", "Üretici verisi + cihazdan okunan gerçek değerler")
genislik(ws, [30, 30, 46])

r = 4
tablo_basligi(ws, r, ["Özellik", "Değer", "Açıklama"])
r += 1
for a, b, c in [
    ("Cihaz", "Slamtec RPLIDAR C1", "2B 360° lazer tarayıcı"),
    ("Menzil", "0,05 – 12 m (beyaz yüzey)", "Siyah yüzeyde 6 m"),
    ("Tarama frekansı", "8 – 12 Hz (tipik 10)", "Ölçülen: 10,0 tur/s"),
    ("Örnekleme", "5 kHz", "Tur başına ~500 nokta; ölçülen 423"),
    ("Açısal çözünürlük", "0,72°", ""),
    ("Mesafe doğruluğu", "±15 mm (çözünürlük 30 mm)", ""),
    ("Arayüz", "TTL UART, 460800 baud", "EN KRİTİK AYAR — aşağıdaki nota bakınız"),
    ("Bağlantı", "USB (CP210x köprü) → PC", "Robotta Jetson Orin Nano'ya taşınacak"),
    ("Okunan model kodu", "65", "GET_INFO yanıtı"),
    ("Okunan yazılım sürümü", "1.2", "GET_INFO yanıtı"),
    ("Okunan donanım sürümü", "18", "GET_INFO yanıtı"),
    ("Cihaz sağlık durumu", "iyi (hata kodu 0)", "GET_HEALTH yanıtı"),
]:
    r = satir_yaz(ws, r, [a, b, c])

r += 1
ws.cell(row=r, column=1,
        value="DİKKAT — en sık yapılan hata: C1 460800 baud kullanır. İnternetteki "
              "RPLIDAR örneklerinin çoğu A1/A2 için yazılmış ve 115200 kullanır. "
              "O hızda port açılır, hiç veri gelmez ve sorun donanım sanılır.")
ws.cell(row=r, column=1).font = Font(name=YAZI, size=10, bold=True, color=SARI_Y)
ws.cell(row=r, column=1).fill = PatternFill("solid", fgColor=SARI)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=3)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="center")
ws.row_dimensions[r].height = 46

r += 2
ws.cell(row=r, column=1, value="PC mi, Jetson mu? — Gerekçe").font = Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Ölçüt", "PC", "Jetson Orin Nano"])
r += 1
for a, b, c in [("Kurulum süresi", "5 dakika", "JetPack + ROS 2 derleme, saatler"),
                ("Görselleştirme", "Akıcı", "Ağır"),
                ("Deneme döngüsü", "Hızlı", "Yavaş (SSH, kaynak sınırı)"),
                ("Robota takılı olmalı mı", "Hayır", "Evet")]:
    r = satir_yaz(ws, r, [a, b, c])
r += 1
ws.cell(row=r, column=1,
        value="Karar: Önce PC. LiDAR USB'den beslenip USB'den konuşuyor; "
              "makineler arası taşımak 5 saniye. Jetson, PC'de çalışan bir sistem "
              "varken kurulacak.")
ws.cell(row=r, column=1).font = Font(name=YAZI, size=10, italic=True)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=3)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[r].height = 32

# ===========================================================================
# 3. DOGRULAMA TESTLERI
# ===========================================================================
ws = wb.create_sheet("3. Doğrulama Testleri")
basliklandir(ws, "Otomatik Doğrulama Testleri",
             "Hepsi LiDAR TAKILI OLMADAN çalışır — her makinede tekrarlanabilir")
genislik(ws, [26, 52, 10, 10, 34])

r = 4
tablo_basligi(ws, r, ["Test dosyası", "Ne doğruluyor", "Geçti", "Kaldı", "Çalıştırma komutu"])
r += 1
ilk = r
for a, b, g, k, komut in [
    ("test_c1.py",
     "Ölçüm çözücü (kodla-çöz gidiş-dönüş), bozuk veri reddi, bayt kaymasında "
     "yeniden hizalanma, tam tur ayırma, komut baytları, 'veri gelmiyor' "
     "tespiti, doğru motor hattı seçimi, kısa sessizlikte pes etmeme",
     26, 0, "python test_c1.py"),
    ("test_harita.py",
     "Koordinat dönüşümü, ICP'nin bilinen dönüşümü geri bulması, tek tarama "
     "haritasının oda ölçüsü, SLAM'in bilinen yörüngeyi geri bulması, "
     "gürültü dayanıklılığı",
     20, 0, "python test_harita.py"),
    ("test_guvenlik.py",
     "Koordinat dönüşümü ve kör açılar, SERBEST/YAVAŞ/DUR kararları, koridor "
     "dışı nesnelerin elenmesi, tek gürültü noktasına takılmama, histerezis "
     "titreme testi, bayat veride güvenli tarafa düşme",
     31, 0, "python test_guvenlik.py"),
]:
    r = satir_yaz(ws, r, [a, b, g, k, komut])
son = r - 1
r = satir_yaz(ws, r, ["TOPLAM", "", f"=SUM(C{ilk}:C{son})", f"=SUM(D{ilk}:D{son})", ""],
              kalin=True, dolgu=ACIK)
for i in range(ilk, r):
    for c in (3, 4):
        ws.cell(row=i, column=c).alignment = Alignment(horizontal="center", vertical="center")

r += 2
ws.cell(row=r, column=1, value="Neden bu testler önemli?").font = Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
for metin in [
    "1) Donanımsız çalışırlar. Robot yanımızda olmadan, evde, gece yarısı da "
    "doğrulama yapılabiliyor.",
    "2) Sonuç göz kararı değil, sayı. Sentetik oda kullanılıyor ama sensörün "
    "gezdiği yörünge BİLİNİYOR; algoritmanın tahmini gerçekle karşılaştırılıp "
    "kaç santim saptığı ölçülüyor.",
    "3) Bir değişiklik bir şeyi bozarsa anında görülüyor. Örnek: harita "
    "görselleştirmesi geliştirilirken tüm testler tekrar çalıştırıldı, 20/20 "
    "kaldı.",
]:
    c = ws.cell(row=r, column=1, value=metin)
    c.font = Font(name=YAZI, size=10)
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
    c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[r].height = 30
    r += 1

# ===========================================================================
# 4. OLCULEN DOGRULUK
# ===========================================================================
ws = wb.create_sheet("4. Ölçülen Doğruluk")
basliklandir(ws, "Ölçülen Doğruluk",
             "Sentetik 6,00 × 4,00 m oda; sensörün gerçek yörüngesi bilinerek ölçüldü")
genislik(ws, [46, 20, 20, 40])

r = 4
ws.cell(row=r, column=1, value="A) ICP — bilinen dönüşüm geri bulunuyor mu").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Uygulanan dönüşüm", "Konum hatası", "Açı hatası", "Yorum"])
r += 1
for a, b, c, d in [("20 cm ileri", "0,0 mm", "0,00°", ""),
                   ("30 cm yana", "0,0 mm", "0,00°", ""),
                   ("8° dönme", "3,4 mm", "0,37°", ""),
                   ("25 cm / -15 cm / 6°", "5,2 mm", "0,35°", "Ötelenme + dönme birlikte"),
                   ("-30 cm / 20 cm / -10°", "0,0 mm", "0,00°", "")]:
    r = satir_yaz(ws, r, [a, b, c, d])

r += 2
ws.cell(row=r, column=1, value="B) SLAM — bilinen yörünge geri bulunuyor mu").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Senaryo", "Son konum hatası", "Açı hatası", "Yorum"])
r += 1
for a, b, c, d in [
    ("2,34 m düz gidiş", "0,8 cm (ort. 0,4 cm)", "—", "Düz gidişte kayma yok"),
    ("90° dönüşlü güzergâh", "1,0 cm", "0,18°", "Dönüş açısı çok iyi korunuyor"),
    ("3 cm ölçüm gürültüsü eklenmiş", "1,8 cm", "—", "Gürültüye dayanıklı"),
    ("4,9 m kapalı güzergâh, 2 dönüş", "9,9 cm (ort. 1,0 cm)", "—",
     "Yol uzadıkça hata BİRİKİR — bkz. sınırlar"),
]:
    r = satir_yaz(ws, r, [a, b, c, d])

r += 2
ws.cell(row=r, column=1, value="C) Harita ölçüsü — gerçek oda 6,00 × 4,00 m").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Yöntem", "Ölçülen genişlik", "Ölçülen derinlik", "Sapma"])
r += 1
olcu_ilk = r
for a, b, c in [("Tek tarama (oda ortasından)", 6.03, 4.02),
                ("Gezerek (SLAM), 4,9 m güzergâh", 6.09, 4.11)]:
    ws.cell(row=r, column=1, value=a).font = Font(name=YAZI, size=10)
    ws.cell(row=r, column=2, value=b).font = Font(name=YAZI, size=10)
    ws.cell(row=r, column=3, value=c).font = Font(name=YAZI, size=10)
    ws.cell(row=r, column=4, value=f"=MAX(ABS(B{r}-6),ABS(C{r}-4))*100").font = Font(name=YAZI, size=10)
    for cc in range(1, 5):
        ws.cell(row=r, column=cc).border = KENAR
        ws.cell(row=r, column=cc).alignment = Alignment(vertical="top", wrap_text=True)
    ws.cell(row=r, column=2).number_format = '0.00" m"'
    ws.cell(row=r, column=3).number_format = '0.00" m"'
    ws.cell(row=r, column=4).number_format = '0.0" cm"'
    r += 1

r += 1
ws.cell(row=r, column=1, value="D) Bilinen sınırlar — dürüst değerlendirme").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
for metin in [
    "• Yol uzadıkça ve dönüş sayısı arttıkça hata BİRİKİR. Küçük odada sorun "
    "değil, uzun depo koridorunda olur.",
    "• Sadece lazer taramasıyla çalışan SLAM, uzun ve simetrik koridorlarda "
    "kayar: ardışık iki tarama birbirinin aynısı olunca algoritma \"ne kadar "
    "ilerledim\" sorusunu cevaplayamaz.",
    "• Çözümü odometri (tekerlek geri beslemesi) ve döngü kapama. Odometri "
    "kaynağı belirlendi: Kelly KLS-S 'Meter' pini (bkz. 7. sayfa). Video "
    "sonrasına planlandı.",
    "• Buradaki sayılar sentetik ortamda ölçülmüştür; gerçek odada yüzey "
    "yansıtıcılığı ve cam yüzeyler nedeniyle bir miktar kötüleşmesi beklenir.",
]:
    c = ws.cell(row=r, column=1, value=metin)
    c.font = Font(name=YAZI, size=10)
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
    c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[r].height = 30
    r += 1

# ===========================================================================
# 5. HARITA CIKTILARI
# ===========================================================================
ws = wb.create_sheet("5. Harita Çıktıları")
basliklandir(ws, "Harita Çıktıları",
             "Aşağıdaki iki harita, gerçek yörüngesi bilinen DOĞRULAMA odasında üretilmiştir")
genislik(ws, [110])

ws["A4"] = ("UYARI: Bu iki görsel, algoritmanın doğruluğunu ÖLÇEBİLMEK için "
            "kullanılan sentetik doğrulama odasına aittir (gerçek boyut "
            "6,00 × 4,00 m). Kendi odanızın/deponuzun haritasını çıkarıp bu "
            "sayfadaki görselleri onlarla değiştirin:  "
            "python harita.py --tek     ve     python harita.py --slam   "
            "→ harita_sunum.png")
ws["A4"].font = Font(name=YAZI, size=10, bold=True, color=SARI_Y)
ws["A4"].fill = PatternFill("solid", fgColor=SARI)
ws["A4"].alignment = Alignment(wrap_text=True, vertical="center")
ws.row_dimensions[4].height = 60

ws["A6"] = "1) TEK TARAMA — sensör odanın ortasında, sabit"
ws["A6"].font = Font(name=YAZI, size=12, bold=True, color=LACI)
ws["A7"] = ("Tek bir 360° tarama zaten bir haritadır; kayma (drift) yoktur, "
            "geometri kusursuzdur. Eşyaların arkası gölgede kalır. "
            "Ölçülen: 6,06 × 4,05 m.")
ws["A7"].font = Font(name=YAZI, size=10)
ws["A7"].alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[7].height = 32
resim_ekle(ws, os.path.join(S, "ornek_tek_sunum.png"), "A9", 720)

ws["A50"] = "2) GEZEREK (SLAM) — sensör elde, yavaşça dolaştırılıyor"
ws["A50"].font = Font(name=YAZI, size=12, bold=True, color=LACI)
ws["A51"] = ("Her yeni tarama, biriken haritaya ICP ile oturtulur; böylece "
             "sensörün ne kadar hareket ettiği görüntüden çıkarılır. Tekerlek "
             "enkoderi olmadan \"odometri\" tam olarak böyle üretilir. "
             "126 anahtar poz, 4,9 m güzergâh, 2 dönüş. Ölçülen: 6,09 × 4,11 m.")
ws["A51"].font = Font(name=YAZI, size=10)
ws["A51"].alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[51].height = 32
resim_ekle(ws, os.path.join(S, "ornek_slam_sunum.png"), "A53", 720)

# ===========================================================================
# 6. ENGEL ALGILAMA
# ===========================================================================
ws = wb.create_sheet("6. Engel Algılama")
basliklandir(ws, "Engel Algılama ve Durma Sistemi",
             "guvenlik.py — LiDAR'ın araç üzerindeki asıl görevi")
genislik(ws, [22, 26, 18, 60])

r = 4
ws.cell(row=r, column=1,
        value="TASARIM KARARI: LiDAR bu araçta navigasyon YAPMAZ. Yönü çizgi "
              "izleme, konumu QR verir. LiDAR'ın işi, kameranın yapamadığı şeydir: "
              "önündeki boşluğu metrik olarak ölçmek ve aracı durdurmak.")
ws.cell(row=r, column=1).font = Font(name=YAZI, size=10, bold=True, color="1F3864")
ws.cell(row=r, column=1).fill = PatternFill("solid", fgColor=ACIK)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="center")
ws.row_dimensions[r].height = 46

r += 2
tablo_basligi(ws, r, ["Durum", "Koşul", "Hız çarpanı", "Davranış"])
r += 1
for a, b, c, d, dolgu in [
    ("SERBEST", "Koridor boş", 1.0, "Normal seyir hızı", YESIL),
    ("YAVAŞ", "Engel < 90 cm", 0.4, "Hız %40'a düşer, çizgi takibi sürer", SARI),
    ("DUR", "Engel < 40 cm", 0.0, "Motorlar nötre (2048) çekilir, direksiyon kırılmaz", KIRMIZI),
]:
    r = satir_yaz(ws, r, [a, b, c, d], dolgu=dolgu)
    ws.cell(row=r - 1, column=3).number_format = "0.0"
    ws.cell(row=r - 1, column=3).alignment = Alignment(horizontal="center")

r += 2
ws.cell(row=r, column=1, value="Mühendislik kararları ve gerekçeleri").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Karar", "Değer", "Neden", "Doğrulama"])
r += 1
for a, b, c, d in [
    ("En az nokta sayısı", "2 nokta",
     "Tek bir gürültü noktası aracı durdurmamalı. Bir ölçüm hatası koridorun "
     "içine düşerse araç durur ve pist ortasında kalır.",
     "Test: koridora tek nokta → SERBEST; iki nokta → DUR"),
    ("Histerezis", "12 cm",
     "Eşiğin tam üstünde titreyen bir engel, aracı sürekli dur-kalk yaptırır. "
     "Çıkış eşiği giriş eşiğinden büyük tutuldu (40 cm'de girer, 52 cm'de çıkar).",
     "Test: eşikte ±2 cm oynayan engelde 20 karede en fazla 1 durum değişimi"),
    ("Bayat veri davranışı", "0,7 sn → YAVAŞ",
     "Sensör susarsa tam hızla devam etmek en tehlikeli davranıştır. "
     "Veri gelmezse sistem kendiliğinden yavaşlar.",
     "Test: zaman damgası eski → durum YAVAŞ, çarpan 0,4"),
    ("Ayrı iş parçacığı", "Arka planda tarama",
     "Çizgi takibi ~30 Hz döner, LiDAR 10 Hz üretir. Ana döngüde okunursa "
     "direksiyon LiDAR'ı beklemeye başlar ve gecikir.",
     "GuvenlikOkuyucu sınıfı; ana döngü hiç bloklanmaz"),
    ("Kör açılar", "Ayarlanabilir",
     "LiDAR aracın kendi gövdesini/kablolarını görür. O yönler elenebiliyor.",
     "Test: düz ve sarmal (340°–20°) açı aralıkları"),
    ("Koridor genişliği", "Araç genişliği + pay",
     "Yandaki duvar veya raf aracı durdurmamalı; sadece ÖNÜNDEKİ engel önemli.",
     "Test: 75 cm yandaki engel → SERBEST"),
]:
    r = satir_yaz(ws, r, [a, b, c, d])

r += 2
ws.cell(row=r, column=1, value="Çizgi izleme koduna bağlantı — tek nokta").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
kod = ("from guvenlik import GuvenlikOkuyucu\n"
       "oku = GuvenlikOkuyucu(port=\"/dev/ttyUSB0\")   # arka planda tarar\n"
       "...\n"
       "d = oku.durum()\n"
       "carpan = d[\"hiz_carpani\"]                    # 1.0 / 0.4 / 0.0\n"
       "sol_dac = NOTR + int((sol_dac - NOTR) * carpan)\n"
       "sag_dac = NOTR + int((sag_dac - NOTR) * carpan)\n"
       "motor_sur(sol_dac, sag_dac)")
c = ws.cell(row=r, column=1, value=kod)
c.font = Font(name="Consolas", size=9)
c.fill = PatternFill("solid", fgColor=GRI)
c.alignment = Alignment(wrap_text=True, vertical="top")
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.row_dimensions[r].height = 118

r += 2
ws.cell(row=r, column=1,
        value="Bu yaklaşımın avantajı: her iki tekerleğin nötrden sapması aynı "
              "oranda ölçeklenir. Direksiyon oranı bozulmaz, DUR durumunda ikisi "
              "de tam nötre gider. Mevcut durum makinesine (pivot, köşe dönüşü, "
              "çizgi arama) hiç dokunulmaz — tek bir yerden uygulanır.")
ws.cell(row=r, column=1).font = Font(name=YAZI, size=10, italic=True)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[r].height = 46

r += 2
ws.cell(row=r, column=1, value="Üç durumun ekran görüntüleri").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
# Sutun genislikleri 22/26/18/60 -> A=0px, D=474px, G=1026px'ten baslar.
# Gorseller 300 px oldugu icin A, D, G capalari ust uste binmez.
for sutun, dosya, etiket in [(1, "g_serbest.png", "SERBEST — koridor boş"),
                             (4, "g_yavas.png", "YAVAŞ — engel < 90 cm"),
                             (7, "g_dur.png", "DUR — engel < 40 cm")]:
    h = ws.cell(row=r + 1, column=sutun, value=etiket)
    h.font = Font(name=YAZI, size=11, bold=True)
    h.alignment = Alignment(horizontal="left")
    resim_ekle(ws, os.path.join(S, dosya), f"{get_column_letter(sutun)}{r + 2}", 300)

# ===========================================================================
# 7. KODLAR VE KOMUTLAR
# ===========================================================================
ws = wb.create_sheet("7. Kodlar ve Komutlar")
basliklandir(ws, "Yazılan Kodlar ve Çalıştırma Komutları",
             "Depo: berkaysahin133-jpg/HalilMAP  |  dal: claude/new-session-3ojeoh  |  klasör: lidar/")
genislik(ws, [22, 52, 44, 12])

r = 4
tablo_basligi(ws, r, ["Dosya", "Görevi", "Çalıştırma komutu", "Satır"])
r += 1
for a, b, c, d in [
    ("basla.py", "Sıfırdan başlatan tek dosya: paketleri kurar, portu bulur, "
                 "cihazı doğrular, veri aktığını sınar, menü sunar.",
     "python basla.py", 250),
    ("tanila.py", "Teşhis. Veri gelmiyorsa hangi aşamada takıldığını satır satır "
                  "söyler, tanila_cikti.txt yazar.",
     "python tanila.py --port COM5", 300),
    ("c1.py", "RPLIDAR C1 sürücüsü. Sadece pyserial gerekir, ROS gerekmez.",
     "(diğer dosyalar tarafından kullanılır)", 330),
    ("goster.py", "Canlı kuş bakışı görüntü, kayıt ve tekrar oynatma.",
     "python goster.py --port COM5", 255),
    ("harita.py", "2B harita: tek tarama ve gezerek (ICP-SLAM). Rapora konacak "
                  "ölçülendirilmiş çizimi de üretir.",
     "python harita.py --tek\npython harita.py --slam", 570),
    ("guvenlik.py", "Engel algılama ve durma. Hem robot modülü hem canlı görsel.",
     "python guvenlik.py --genislik 0.6 --dur 0.4 --yavas 0.9", 340),
    ("test_c1.py", "Sürücü protokolü doğrulaması (donanımsız).", "python test_c1.py", 310),
    ("test_harita.py", "ICP/SLAM doğrulaması (donanımsız).", "python test_harita.py", 200),
    ("test_guvenlik.py", "Engel algılama doğrulaması (donanımsız).", "python test_guvenlik.py", 190),
    ("darbe_test.ino", "Kelly 'Meter' pininde darbe var mı, tur başına kaç tane "
                       "(odometri hazırlığı).",
     "Arduino IDE ile yükle, Seri Monitör 115200", 200),
]:
    r = satir_yaz(ws, r, [a, b, c, d])
    ws.cell(row=r - 1, column=4).alignment = Alignment(horizontal="center")

r += 2
ws.cell(row=r, column=1, value="Dosyaları indirme (Windows PowerShell)").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
c = ws.cell(row=r, column=1, value=(
    'cd "$env:USERPROFILE\\Desktop\\lidar"\n'
    '$b="https://raw.githubusercontent.com/berkaysahin133-jpg/HalilMAP/'
    'claude/new-session-3ojeoh/lidar"\n'
    'foreach($f in "c1.py","tanila.py","basla.py","goster.py","harita.py",'
    '"guvenlik.py"){ iwr "$b/$f" -OutFile $f }'))
c.font = Font(name="Consolas", size=9)
c.fill = PatternFill("solid", fgColor=GRI)
c.alignment = Alignment(wrap_text=True, vertical="top")
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.row_dimensions[r].height = 62

r += 2
ws.cell(row=r, column=1, value="Odometri hazırlığı — Kelly KLS-S 'Meter' pini").font = \
    Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
ws.cell(row=r, column=1, value=(
    "Kelly KLS-S kullanma kılavuzu, bölüm 3.2.1 'Pin definition of KLS-S "
    "Controller', DJ7091Y-2.3-21 konnektörü:\n"
    "    (8) Meter: Copy signal of hall sensors.  —  Dark Gray\n"
    "    Not 2: Meter function is to copy either of hall sensors.\n\n"
    "Yani motorun hall soketine hiç dokunmadan, gaz konnektöründeki koyu gri "
    "telden tek hall fazının sinyali okunabilir. Hoverboard hub motoru 15 kutup "
    "çiftine sahip olduğundan tur başına ~30 kenar, 6,5\" tekerlekte ~17 mm "
    "çözünürlük beklenir. Bu, 90° pivot dönüşünün süreyle değil AÇIYLA "
    "yapılmasını sağlar (batarya voltajı düştükçe süre tabanlı dönüş kayar)."))
ws.cell(row=r, column=1).font = Font(name=YAZI, size=10)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=4)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[r].height = 130

# ===========================================================================
# 8. SORUN - COZUM
# ===========================================================================
ws = wb.create_sheet("8. Sorun ve Çözüm")
basliklandir(ws, "Karşılaşılan Sorun ve Çözüm Yöntemi",
             "\"Cihaz bağlanıyor ama veri gelmiyor\" — teşhis süreci")
genislik(ws, [24, 54, 54])

r = 4
tablo_basligi(ws, r, ["Aşama", "Gözlem", "Çıkarım"])
r += 1
for a, b, c in [
    ("Belirti", "Port açılıyor, model ve seri numarası okunuyor, sağlık \"iyi\" "
                "dönüyor; ancak tarama komutundan sonra tek ölçüm gelmiyor.",
     "Hata mesajı \"zaman aşımı\" diyordu ve yanıltıcıydı."),
    ("Eleme 1", "GET_INFO ve GET_HEALTH doğru yanıt veriyor.",
     "Port, baud hızı (460800), kablo ve cihaz elektroniği DOĞRU. "
     "Sorun bu katmanda değil."),
    ("Eleme 2", "SCAN komutuna yanıt tanımlayıcısı geliyor (5 baytlık ölçüm "
                "vaat ediliyor) ama ölçüm akmıyor.",
     "Cihaz komutu anlıyor. Geriye fiziksel katman kalıyor: motor dönmüyorsa "
     "ölçüm üretilemez."),
    ("Kod düzeltmesi", "Sürücü, yanıt tanımlayıcısını görünce \"tarama başladı\" "
                       "sayıyordu; verinin gerçekten aktığını kontrol etmiyordu.",
     "tarama_baslat() artık veri akışını ÖLÇÜYOR. Ayrıca DTR/RTS motor hattının "
     "4 kombinasyonunu deniyor ve çalışanı kaydediyor."),
    ("Dayanıklılık", "Tek bir boş okumada hata veriliyordu; motor hızlanırken "
                     "kısa boşluklar normaldir.",
     "Sessizlik penceresi eklendi (2,5 sn). Motor rampası artık hata sayılmıyor."),
    ("Teşhis aracı", "Sorunun nerede olduğunu kullanıcı göremiyordu.",
     "tanila.py yazıldı: portları listeler, cihazla konuşur, 4 hat "
     "kombinasyonunda gelen ham baytı sayar, karar verir, rapor dosyası yazar."),
    ("SONUÇ", "Canlı tarama alındı: 423 nokta/tur, 10,0 tur/s.",
     "Sistem çalışır durumda. Oda haritası çıkarıldı."),
]:
    dolgu = YESIL if a == "SONUÇ" else None
    r = satir_yaz(ws, r, [a, b, c], dolgu=dolgu)

r += 2
ws.cell(row=r, column=1, value=(
    "Yöntemsel not: Bu tür bir arızada ilk refleks donanımı suçlamaktır. "
    "Burada izlenen yol, katmanları tek tek eleyerek sorunun nerede OLMADIĞINI "
    "kanıtlamak oldu. Cihazın kimlik ve sağlık bilgisini okuyabiliyor olmak, "
    "port/baud/kablo/elektronik katmanlarının tamamını temize çıkarır; geriye "
    "yalnızca tek bir olasılık kalır. Aynı teşhis mantığı tanila.py içine "
    "kalıcı olarak gömüldü, böylece sorun tekrarlarsa saatler değil dakikalar "
    "harcanır."))
ws.cell(row=r, column=1).font = Font(name=YAZI, size=10, italic=True)
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=3)
ws.cell(row=r, column=1).alignment = Alignment(wrap_text=True, vertical="top")
ws.row_dimensions[r].height = 84

# ===========================================================================
# 9. PAZARTESI PLANI
# ===========================================================================
ws = wb.create_sheet("9. Pazartesi Planı")
basliklandir(ws, "Pazartesi — Çizgi İzleme Entegrasyonu",
             "Araç başında yapılacaklar, sırayla")
genislik(ws, [6, 34, 54, 10, 26])

r = 4
tablo_basligi(ws, r, ["#", "Adım", "Ne yapılacak", "Süre (sa)", "Bittiğinin kanıtı"])
r += 1
ilk = r
for i, (ad, ne, sure, kanit) in enumerate([
    ("LiDAR montajı",
     "Aracın ön yüzüne, YATAY ve sabit yükseklikte (15–25 cm) monte et. "
     "Kabloyu tekerleklerden uzak tut.", 1.0,
     "goster.py'de duvarlar düzgün görünüyor"),
    ("Kör açı tespiti",
     "Araç dururken canlı görüntüye bak: aracın kendi gövdesini/kablosunu "
     "gördüğü açı aralıklarını not et.", 0.5,
     "guvenlik.py --kor 160-200 ile o noktalar kayboluyor"),
    ("Koridor ölçüleri",
     "Aracın genişliğini ölç, iki yana 10'ar cm pay ekle. Seyir hızında fren "
     "mesafesini ölç; DUR eşiği bundan büyük olmalı.", 1.0,
     "--genislik / --dur / --yavas değerleri yazıldı"),
    ("Güvenlik testi (motorsuz)",
     "Araç kapalıyken guvenlik.py'yi çalıştır, önüne kutu koy/çek. "
     "SERBEST→YAVAŞ→DUR geçişlerini doğrula.", 0.5,
     "Üç durum da ekranda doğru tetikleniyor"),
    ("Koda bağlama",
     "GuvenlikOkuyucu'yu cizgi_takip_stabil.py'ye ekle. Hız çarpanı "
     "motor_sur() çağrısından hemen ÖNCE, tek noktada uygulanır.", 1.0,
     "Kod çalışıyor, LiDAR yokken davranış değişmiyor"),
    ("Birlikte test",
     "Çizgi üzerinde sür, önüne engel koy. Engel çekilince kendiliğinden "
     "devam etmeli. Köşe dönüşlerinde yanlış durma olmamalı.", 1.5,
     "10 turda 0 yanlış durma, 10/10 doğru durma"),
    ("Depo/pist haritası",
     "harita.py --slam ile pisti yavaşça gez, haritayı çıkar.", 1.0,
     "harita_sunum.png üretildi"),
    ("Video çekimi",
     "10. sayfadaki 4 sahne.", 2.0,
     "4 sahne de çekildi"),
]):
    r = satir_yaz(ws, r, [i + 1, ad, ne, sure, kanit])
    ws.cell(row=r - 1, column=1).alignment = Alignment(horizontal="center")
    ws.cell(row=r - 1, column=4).alignment = Alignment(horizontal="center")
    ws.cell(row=r - 1, column=4).number_format = "0.0"
son = r - 1
r = satir_yaz(ws, r, ["", "TOPLAM", "", f"=SUM(D{ilk}:D{son})", ""],
              kalin=True, dolgu=ACIK)
ws.cell(row=r - 1, column=4).number_format = "0.0"
ws.cell(row=r - 1, column=4).alignment = Alignment(horizontal="center")

r += 2
ws.cell(row=r, column=1, value="Riskler ve önlemleri").font = Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
tablo_basligi(ws, r, ["Risk", "Önlem", "", "", ""])
r += 1
for a, b in [
    ("LiDAR yerdeki çizgiyi/eşiği engel sanabilir",
     "LiDAR'ı yeterince yüksek monte et; gerekirse en yakın mesafe eşiğini yükselt."),
    ("Köşe dönüşünde duvar koridora girip aracı durdurabilir",
     "Koridor uzunluğunu (DUR eşiğini) kısa tut; pivot sırasında güvenlik "
     "katmanını devre dışı bırakma seçeneği hazır."),
    ("LiDAR takılı değilken kod bozulmamalı",
     "GuvenlikOkuyucu ayrı iş parçacığında çalışır ve bağlanamazsa çizgi "
     "takibini etkilemez; kullanılmadan önce doğrulanacak."),
    ("USB portu yetersiz akım verirse motor durur",
     "Robotta beslemesi güçlü bir port kullan; tanila.py ile önceden doğrula."),
]:
    r = satir_yaz(ws, r, [a, b])
    ws.merge_cells(start_row=r - 1, start_column=2, end_row=r - 1, end_column=5)

# ===========================================================================
# 10. VIDEO PLANI
# ===========================================================================
ws = wb.create_sheet("10. Video Planı")
basliklandir(ws, "Video Çekim Planı", "LiDAR bölümü — toplam ~65 saniye")
genislik(ws, [6, 34, 54, 12, 34])

r = 4
tablo_basligi(ws, r, ["#", "Sahne", "Ne çekilecek", "Süre (sn)", "Neyi kanıtlıyor"])
r += 1
ilk = r
for i, (ad, ne, sure, kanit) in enumerate([
    ("Sensör çalışıyor",
     "Ekranda canlı tarama; LiDAR elle döndürülüyor, nokta bulutu dönüyor. "
     "Üst köşede 'nokta/tur' ve 'tur/s' göstergesi okunuyor.", 10,
     "Donanım gerçekten çalışıyor, ekran görüntüsü sahte değil"),
    ("Haritalama",
     "Depoyu/pisti gezerken haritanın büyüyerek oluşması; sonunda "
     "harita_sunum.png tam ekran, ölçüler görünür.", 20,
     "Haritalama yeteneği ve metrik doğruluk"),
    ("Engel algılama ve durma",
     "Araç çizgide giderken önüne kutu konuyor. Bölünmüş ekran: solda araç, "
     "sağda LiDAR görüntüsü yeşilden sarıya, sarıdan kırmızıya dönüyor; "
     "araç yavaşlayıp duruyor.", 25,
     "Sensör → karar → motor zinciri. Videonun en değerli kısmı."),
    ("Otomatik devam",
     "Kutu çekiliyor, araç kendiliğinden devam ediyor.", 10,
     "Sistem kilitlenmiyor, kendiliğinden toparlanıyor"),
]):
    r = satir_yaz(ws, r, [i + 1, ad, ne, sure, kanit])
    ws.cell(row=r - 1, column=1).alignment = Alignment(horizontal="center")
    ws.cell(row=r - 1, column=4).alignment = Alignment(horizontal="center")
son = r - 1
r = satir_yaz(ws, r, ["", "TOPLAM", "", f"=SUM(D{ilk}:D{son})", ""],
              kalin=True, dolgu=ACIK)
ws.cell(row=r - 1, column=4).alignment = Alignment(horizontal="center")

r += 2
ws.cell(row=r, column=1, value="Çekim notları").font = Font(name=YAZI, size=12, bold=True, color=LACI)
r += 1
for metin in [
    "• 3. sahne videonun en değerli 25 saniyesidir. Değerlendiren kişi "
    "\"LiDAR'ı gerçekten kullanmışlar mı, yoksa üstüne takıp geçmişler mi?\" "
    "diye bakar; kırmızı bölge ile duran aracı AYNI KAREDE göstermek bu soruyu "
    "tek seferde cevaplar.",
    "• Ekran kaydı ile araç görüntüsünü aynı anda alın (telefonla araç, "
    "bilgisayarda ekran kaydı, sonra yan yana kurgu).",
    "• Rapor 'RPLIDAR A1M8' yazıyor, elde 'C1' var. Videoda cihaz görünecek. "
    "Tek cümlelik açıklama yeterlidir: \"Tedarik sürecinde A1M8 yerine C1 temin "
    "edildi.\" C1 daha yeni bir modeldir; bunu belirtmek eksiklik değil, "
    "şeffaflıktır.",
    "• Ölçüler ekranda görünsün: haritada metre ızgarası ve \"Ölçülen alan\" "
    "yazısı var, kamera ona bir saniye sabitlensin.",
]:
    c = ws.cell(row=r, column=1, value=metin)
    c.font = Font(name=YAZI, size=10)
    ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=5)
    c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.row_dimensions[r].height = 44
    r += 1

# ===========================================================================
for sayfa in wb.worksheets:
    sayfa.sheet_view.showGridLines = False
    sayfa.freeze_panes = "A4"

wb.save(CIKTI)
print("YAZILDI:", CIKTI)
