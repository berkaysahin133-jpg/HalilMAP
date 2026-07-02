# TEKNOFEST SRUY 2026 — RoboVizyon Proje Detay Raporu — Aktarım Dokümanı

Bu doküman, yeni bir Claude sohbetine bu işi devam ettirmek için gereken HER ŞEYİ içerir.
Yeni sohbete girdiğinde bu dosyayı (veya bu mesajın tamamını) ilk mesajında Claude'a ver.

---

## 1. PROJE VE YARIŞMA KİMLİĞİ

- **Yarışma:** TEKNOFEST 2026 Sanayide Robotik Uygulamalar Yarışması (SRUY) — eski adıyla "Sanayide Dijital Teknolojiler Yarışması"
- **Şartname:** https://cdn.teknofest.org/media/upload/userFormUpload/2026_SRUY_TR_r5qei.pdf
- **Yarışma sayfası:** https://teknofest.org/tr/yarismalar/sanayide-robotik-uygulamalar-yarismasi/
- **Takım Adı:** RoboVizyon
- **Proje/Araç:** Forklift Tipi Otonom Mobil Robot (AGV)
- **Kategori:** Sanayide Robotik Uygulamalar — **Temel Seviye**
- **Başvuru ID:** 5358573
- **Takım ID:** 999327
- **Rapor türü:** Proje Detay Raporu (PDR) — **Son teslim tarihi: 1 Temmuz 2026, saat 17:00 (KYS sistemi üzerinden)**
- **Sonraki takvim:** Hareket-Kabiliyet Videosu — 11 Ağustos 2026; TEKNOFEST Finalleri — 30 Eylül–4 Ekim 2026, Şanlıurfa

### Takım Üyeleri (org şemasından alındı)
- Kürşat ALTUNER — Takım Danışmanı
- İlbey Batın DADALI — Takım Kaptanı / Yazılım Lideri
- Yusuf ŞAHİNER — Yazılım Ekip Üyesi
- Mert AKSOY — Yazılım / Arayüz Geliştirici
- Berkay ŞAHİN — Mekanik ve Elektronik (kullanıcının kendisi)
- Kerem Taha KARADAVUT — Mekanik ve Elektronik
- Cavit Eren YILDIZ — Mekanik ve Donanım
- Alya Dua ALPER — Teknik ve Mekanik Tasarım

---

## 2. GİT / DOSYA DURUMU (EN ÖNEMLİ KISIM)

- **Repo:** `berkaysahin133-jpg/HalilMAP` (GitHub)
- **Branch:** `claude/teknofest-robotics-report-zaz68i`
- **PR:** #1 (açık, `https://github.com/berkaysahin133-jpg/HalilMAP/pull/1`)
- **Son commit:** `c5ab1d8` — "Resmi kapak arka planı, el çizimi eskiz ve doğal Tecrübe metni eklendi"
- **Rapor dosyası (repo kökünde):** `RoboVizyon_TEKNOFEST_SRUY_2026_Proje_Detay_Raporu.docx` (~14,9 MB)
- Yeni sohbet açıldığında ilk yapılacak şey: bu branch'i fetch/checkout edip son hâldeki .docx dosyasını görmek.

### ⚠️ ÇOK ÖNEMLİ — ÜRETİM ALTYAPISI KALICI DEĞİL
Rapor, **python-docx ile Python script'i çalıştırılarak üretiliyor** (Word'de elle düzenlenmiyor). Script dosyaları şu an sadece bu oturumun geçici `/tmp/claude-0/.../scratchpad/` klasöründe duruyor ve **yeni sohbette bu klasöre erişim olmayacak**. Yani:
- Yeni sohbet, git'teki **son .docx dosyasını** görebilir (kalıcı).
- Ama üretim script'lerini (rb_main.py, rb_base.py, üretilmiş görseller/diyagramlar) **göremeyecek** — bunlar kayboldu.
- Bundan sonraki değişiklikler için yeni sohbetin ya (a) doğrudan .docx dosyasını python-docx ile açıp **var olan içeriği koruyarak** düzenlemesi, ya da (b) sıfırdan benzer bir üretim script'i yazması gerekecek.
- **Öneri:** Yeni sohbete "mevcut .docx dosyasını python-docx ile aç, ilgili paragrafı/bölümü bul ve değiştir" şeklinde nokta atışı talimatlar ver; tüm raporu sıfırdan yeniden üretmesini isteme (gereksiz risk).

---

## 3. KAYNAK DOSYALAR (kullanıcının en başta yüklediği dosyalar)

1. `ilbey_yar_m_rapaor.docx` — **Bu aslında resmi 2026 TEKNOFEST PDR şablonu** (başlıklar, puan dağılımı, format kuralları, ve kapak sayfası arka plan görseli — uzay/roket temalı TEKNOFEST görseli — buradan geldi). Ayrıca takımın ilk taslak metinlerini de içeriyordu (org şeması, mevcut durum bölümü).
2. `RoboVizyon_2026_SRUY_Proje_Detay_Raporu_FINAL.docx` — Başka bir kaynaktan/AI'dan üretilmiş, **YANLIŞ mimari** içeren dolgun bir taslak (redüktörlü DC motor + harici enkoder + BTS7960 sürücü anlatıyordu — bu YANLIŞ, düzeltildi). Ama iyi diyagramlar, tablolar, kaynakça formatı içeriyordu; şablon olarak kullanıldı.
3. `SRU_PDR.docx` — ilbey dosyasıyla neredeyse aynı (ikinci bir kopya).
4. `TEKNOFEST_SRUY_2026_Malzeme_Listesi.xlsx` — 51 kalemlik gerçek malzeme listesi, tedarikçi linkleriyle birlikte (Excel).

---

## 4. DÜZELTİLEN KRİTİK YANLIŞ BİLGİ (EN ÖNEMLİ TEKNİK DÜZELTME)

Kullanıcının gerçek deneyimi ile "RoboVizyon FINAL" taslağındaki mimari **ÇELİŞİYORDU**. Doğru mimari şu şekilde düzeltildi ve rapor boyunca tutarlı hale getirildi:

| Konu | YANLIŞ (eski taslakta) | DOĞRU (kullanıcının gerçek deneyimi, rapora işlendi) |
|---|---|---|
| Tahrik motoru | Enkoderli/redüktörlü DC motor | **Bozuk bir hoverboard'dan söktükleri BLDC hub motor** (geri kazanım, sıfır maliyet) |
| Motor sürücü | BTS7960B | **Kelly KLS-S serisi** (ilk seçilen sürücüde geri yön/reverse özelliği olmadığı için değiştirildi) |
| Enkoder | Harici E6B2-CWZ6C 600 P/R enkoder | **Yok — hub motorun içindeki Hall sensörleri kullanılıyor** (ayrı enkoder gerekmiyor) |
| Güç dağıtımı | 3 raylı (36→24V, 36→12V, 12→5V) | **2 raylı** (36→12V, 12→5V) — hub motorlar zaten 36V'ta Kelly ile direkt besleniyor, ara 24V rayına gerek yok |

Bu düzeltme; Sistem Tasarımı, Mekanik Tasarım, Elektronik Tasarım, Algoritma Tasarımı, Malzemeler, Bütçe, Tecrübe bölümlerinin **hepsine** işlendi.

---

## 5. RAPOR YAPISI (11 Bölüm, toplam 100 puan)

1. RAPOR ÖZETİ (10 puan)
2. TAKIM ŞEMASI (5 puan) — 2.1 Takım Üyeleri, 2.2 Organizasyon Şeması
3. PROJE MEVCUT DURUM DEĞERLENDİRMESİ (5 puan)
4. ARAÇ TASARIMI (40 puan) — en büyük bölüm:
   - 4.1 Sistem Tasarımı (10p)
   - 4.2 Aracın Mekanik Tasarımı / 4.3 Mekanik Tasarım Süreci (3p)
   - 4.4 Malzemeler (3p)
   - 4.5 Üretim Yöntemleri (2p)
   - 4.6 Fiziksel Özellikler (2p)
   - 4.7 Elektronik Tasarım, Algoritma ve Yazılım Tasarımı / 4.8 Elektronik Tasarım Süreci (3p)
   - 4.9 Algoritma Tasarım Süreci (3p)
   - 4.10 Yazılım Tasarım Süreci (4p)
   - 4.11 Dış Arayüzler (10p)
5. GÜVENLİK (10 puan)
6. TEST (5 puan)
7. TECRÜBE (5 puan)
8. ZAMAN, BÜTÇE VE RİSK PLANLAMASI (5 puan)
9. ÖZGÜNLÜK VE YERLİLİK (5 puan)
10. TİCARİLEŞME POTANSİYELİ (5 puan)
11. KAYNAKÇA (5 puan) — 15 kaynak (şartname, ROS2/SLAM/Nav2 akademik makaleleri, ArUco makalesi, üretici datasheet'leri — BNO055, RPLIDAR, Kelly, ASPİLSAN, ISO 3691-4 standardı, AGV pazar raporu vb.)

### Biçim kuralları (uygulandı)
- Yazı tipi: Arial 12pt; Başlıklar: Arial Black 14pt (H1) / 13pt (H2)
- Satır aralığı: 1.15, iki yana yaslı
- Sayfa kenar boşlukları: 2.5 cm (üst/alt/sağ/sol)
- Kapak, İçindekiler, Kaynakça ayrı sayfalarda
- Sayfa numaraları eklendi (footer, otomatik PAGE alanı)
- İçindekiler Word alan kodu (TOC) ile otomatik — **kullanıcı Word'de açınca sağ tık → "Alanı Güncelleştir" yapmalı**

---

## 6. GÖRSEL/TABLO/KOD ENVANTERİ (son hâliyle)

- **16 Şekil** (diyagramlar + CAD render'ları + grafikler)
- **14 Tablo** (malzeme listesi, bütçe, test planı, risk kaydı, vb.)
- **14 Fotoğraf** (gerçek saha/atölye fotoğrafları, insan-tonlu açıklamalarla)
- **1 Kod bloğu** (backend WebSocket sunucu kodu)

### Şekiller (16 adet, sırayla)
1. Organizasyon şeması
2. Sistem blok şeması (5 katmanlı mimari) — **yeniden tasarlandı** (mühendislik/blueprint görünümü, mavi grid arka plan)
3-6. Fusion 360 render'ları (izometrik, yan, ön, üst görünüm) — **kullanıcının gerçek CAD modeli**, eski "stok görünümlü" AI render'ların yerine kondu
7-8. (Fusion render'larla numaralandırma kaydı)
9. Güç dağıtım ve sürüş mimarisi (Kelly KLS + hub motor) — acil durdurma zinciriyle
10. Yarışma senaryosu ana görev akış diyagramı — **yeniden tasarlandı**
11. Görev yönetimi durum makinesi (a-h, 8 durum) — **yeniden tasarlandı**
12. Görüntü işleme hattı (çizgi takibi + QR) — **yeniden tasarlandı**
13. Yazılım mimarisi (ROS 2 düğüm grafiği) — **yeniden tasarlandı**
14. Proje zaman planı (Gantt)
15. Bütçe dağılımı grafikleri (pasta + bar chart, matplotlib)
16. Risk matrisi (olasılık × etki, matplotlib heatmap)

**Not:** 9-13 arası diyagramlar HTML/CSS ile özel bir "mühendislik şeması" görsel diliyle (`dstyle.css`: ince çizgiler, mavi grid arka plan, gölgesiz düz tasarım, Consolas monospace teknik etiketler) yeniden tasarlandı çünkü kullanıcı eski hâllerinin "AI çizmiş gibi" göründüğünü belirtti.

### Fotoğraflar (14 adet, sırayla)
1. Teknik çizim + konsept eskiz (telefon fotoğrafları)
2. **El çizimi 3 görünüşlü teknik eskiz** (ön/yan/izometrik, kullanıcının son yüklediği kalem çizimi) — YENİ EKLENEN
3-5. Sigma profil şasi montajı (atölyede, 3 farklı fotoğraf)
6. Batarya paketi üretimi (ASPİLSAN hücreleri, punta kaynak) — kullanıcının SON gönderdiği tek fotoğrafla değiştirildi (eski 2 punta kaynak fotoğrafı kaldırıldı)
7-9. Elektronik/kablaj/lehim (Kelly sürücü + Arduino + hub motor yerleşimi, YIHUA lehim istasyonu)
10-11. MuJoCo simülasyonu — rota ayrım noktasında QR okuma + "Rota: SAĞ/SOL" terminal logu + özel "Kontrol Paneli" penceresi
12. MuJoCo simülasyonu (genel görünüm, forklift.xml modeli)
13. GCS (Otonom Forklift operatör paneli) canlı çalışırken saha fotoğrafı
14. Motor sürücü konfigürasyonu / ilk hareket testleri

### Backend Kod Bloğu (1 adet)
- Yazılım Tasarım Süreci (4.10) bölümünde, gerçek Node.js WebSocket sunucu kodu (GCS-PLC köprüsü, MOTOR_COMMAND/MOTOR_ACK mesajlaşması) — insan diliyle açıklandı.

### Ayrıca üretilen özel görseller (matplotlib/HTML→Chromium screenshot ile)
- `gen_dashboard.png` — "OTONOM FORKLİFT GCS" operatör web arayüzü mockup'ı (kullanıcının kendi ekran görüntüsüne sadık, aktif/bağlı durumda)
- `gen_power.png` — Güç dağıtım şeması
- `gen_budget.png` — Bütçe pasta+bar grafiği
- `gen_cover2.png` — **Kapak sayfası** (resmi TEKNOFEST uzay/roket arka planı üzerine beyaz metinle takım bilgileri)

---

## 7. MÜHENDİSLİK HESAPLARI (kullanıcının özellikle istediği, eklendi)

Geçmiş yıl ödüllü raporlardaki somut hesap tarzına (örn. "mukavemet momenti 1.85→2.45 cm³, %33 artış") özenerek eklendi:

1. **Mast/aktüatör emniyet katsayısı:** Aktüatör kapasitesi (1500 N) / gerekli yük (≈78 N) ≈ 19× pay; ama mast dikmelerinin eğilme dayanımı asıl sınırlayıcı unsur, CAD statik kontrolde emniyet katsayısı ≈3.
2. **Tahrik tork-yük kontrolü:** F≈μ·m·g≈14,2 N, T≈F·r≈1,1 N·m — hub motor kalkış torku bunun üzerinde, tork açığı yok.
3. **Batarya Wh/W çalışma süresi:** 313 Wh / 150 W ≈ 2,1 saat; 30 dakikalık görev için ≈4× enerji marjı.
4. **Hall tabanlı odometri çözünürlüğü:** Tipik 15 kutup çiftli hub motor, devir başına ≈90 elektriksel geçiş, 150 mm tekerlekte darbe başına ≈5 mm konum çözünürlüğü.

---

## 8. BÜTÇE (nihai)

- **Toplam proje değeri:** 63.523,85 TL
- **Envanterden karşılanan:** 29.192,81 TL (Jetson Orin Nano, batarya hücreleri+BMS, Wi-Fi adaptörü + hub motor sıfır maliyet)
- **Net nakit ihtiyacı:** 34.331,04 TL
- TYF'de beyan edilen: 26.644,64 TL (fark: algılama seti genişletildi, Kelly sürücülere geçildi, güvenlik/gösterge donanımı eklendi)
- 7 kategori: Batarya ve Güç (%18,0), Tahrik ve Hareket (%12,1), Kaldırma Mekanizması (%5,2), Algılama/Konum (%15,2), İşlem ve Kontrol (%35,4 — en büyük kalem, Jetson Orin Nano), Şasi ve Mekanik (%11,3), Güvenlik/Gösterge (%2,9)

---

## 9. TECRÜBE BÖLÜMÜ İÇERİĞİ (9 madde, "Ders:" kalıbı KIRILDI — her biri farklı doğal cümleyle bitiyor)

1. Geri yön sorunu ve Kelly'ye geçiş
2. Hub motor kararı (hoverboard geri kazanımı)
3. Kamera açısı ve perspektif
4. Güç bütçesi (lead'den "dersi" kelimesi kaldırıldı)
5. 3B baskı dayanımı (PLA→PETG geçişi)
6. Batarya montajı (punta kaynak prosedürü)
7. ROS 2 zaman senkronizasyonu
8. OpenCV çoklu pencere hatası (MuJoCo simülasyonunda "NULL window" hatası — kullanıcının gönderdiği ekran görüntüsünden)
9. Süreç ve disiplin (eski adıyla "Süreç dersi")

**ÖNEMLİ ÜSLUP KURALI:** Hiçbir madde "Ders: ..." diye bitmiyor artık. Her biri farklı bağlaçla doğal şekilde ifade ediliyor ("Bu olay bize şunu gösterdi...", "Aslında ...mış", "Buradan öğrendiğimiz şey...", "Böylece anladık ki...", "Bu deneyim ...gösterdi", "Sonuçta ...fark ettik", "Bu bize ...öğretti", "Kısacası ...gerekiyormuş", "Gördük ki..."). **Yeni sohbette eklenecek her türlü yeni "ders/tecrübe" metninde bu çeşitliliği KORUMASI gerekiyor — asla "Ders:" kalıbını tekrar kullanma.**

---

## 10. ARAŞTIRILAN GEÇMİŞ YIL RAPORLARI (kalibrasyon için, toplam 8 adet incelendi)

TEKNOFEST sayfasındaki "Geçmiş Yıl Raporları" bölümünden (cdn.t3kys.com'da barındırılıyor, bazı linkler 403 veriyor):
1. **RoboMOSB** (M-1963-V2) — önceki yılın **1.'lik derecesi**, 26 sayfa
2. Karasu ŞHKMTAL Robotik Ekibi 2 (KARASU-2), 18 sayfa
3. RACLAB-FAAL (Sanayide Dijital Dönüşüm), 52 sayfa
4. GFLROBOTICS OTONOM, 26 sayfa
5. Karasu ŞHKMTAL Robotik Ekibi 1 (KARASU-1), 20 sayfa
6. YİĞİDO (TRADENS) — en kapsamlı, 80 sayfa, 240+ tork/N·m hesabı geçiyor
7. ARF-208 (ARF-Solo), 48 sayfa
8. NCT-Norma (Tam Otonom Yük Taşıyıcı Sanayi Robotu) — konsept olarak en yakın örnek, 36 sayfa

**Çıkarım:** Bizim rapordaki Tecrübe bölümü ve mühendislik hesapları, incelenen örneklerin çoğundan (özellikle NCT-Norma gibi genel/pasif ifadeli olanlardan) daha somut ve detaylı. Yapı (bölüm başlıkları, puan dağılımı) tüm örneklerle birebir aynı çünkü hepsi aynı resmi şablonu kullanıyor. Ayrıca resmi şartname PDF'inden final puanlama kriterleri (Haritalama +30, Rota hazırlama +20, PLC haberleşme +20, Görüntü işleme +10, QR okuma +10, Çarpışma engelleme +10, kapıdan geçiş +20, kullanıcı arayüzü +20, görevi tamamlama +30, Yerlilik +5, Özgünlük +5, Otomatik Şarj +5 vb.) çekilip Tablo 3'teki izlenebilirlik tablosuyla eşleştirildi.

---

## 11. BİLİNEN SORUNLAR / SINIRLAMALAR

1. **Görsel önizleme API limiti:** Bu oturumda uzun süre görsel gösterildiği için "Request too large (max 32MB)" hatası almaya başladım; son birkaç diyagram/kapak değişikliğini **görsel olarak doğrulayamadım** (sadece kod/koordinat mantığıyla ürettim, dosya boyutu/piksel doğrulaması yaptım ama insan gözüyle kontrol edemedim). Kullanıcı Word'de açıp göz gezdirmeli, özellikle:
   - Kapak sayfasındaki metin okunabilirliği (koyu arka plan üzerine beyaz metin — kontrastı kontrol et)
   - Durum makinesi diyagramındaki (Şekil 11) bağlantı çizgilerinin kutuların üzerinden geçip geçmediği
2. **İçindekiler tablosu** Word alan kodu olarak eklendi, kullanıcının Word'de sağ tık → "Alanı Güncelleştir" yapması gerekiyor (otomatik dolmuyor, sadece dosya açıldığında).
3. **"Şekiller ve Tablolar Listesi"** sayfası (bazı geçmiş ödüllü raporlarda vardı) eklenmedi — zaman kısıtı nedeniyle bilinçli olarak atlandı (nice-to-have, zorunlu değil).
4. Rapor dosyası artık **~14,9 MB** — KYS sistemine yüklerken boyut sınırı varsa kontrol edilmeli.

---

## 12. YENİ SOHBETTE NASIL DEVAM EDİLMELİ

1. Yeni sohbete bu dokümanı yapıştır.
2. Git branch'ini fetch et: `git fetch origin claude/teknofest-robotics-report-zaz68i && git checkout claude/teknofest-robotics-report-zaz68i` (ya da mevcut PR #1 üzerinden devam et).
3. `.docx` dosyasını python-docx ile aç (`from docx import Document; d = Document("RoboVizyon_TEKNOFEST_SRUY_2026_Proje_Detay_Raporu.docx")`), gerekli paragrafı bulup DOĞRUDAN düzenle — sıfırdan üretme script'i yazmaya gerek yok, dosyanın kendisi üzerinde çalışılabilir.
4. Kullanıcının söyleyeceği yeni isteklere göre ilgili bölümü bul (yukarıdaki bölüm listesine göre), düzenle, yeniden kaydet.
5. Her değişiklikten sonra: commit + push (aynı branch'e), dosyayı kullanıcıya gönder.
6. **Üslup kuralı:** Rapor tamamen birinci çoğul şahıs ("yaptık", "kullandık"), somut/insan tonunda, "Ders:" gibi kalıplardan kaçınarak yazılmalı — asla AI-tarzı jenerik/kalıplaşmış ifade kullanma.
7. Deadline BUGÜN/YARIN olabilir (1 Temmuz 2026 17:00) — hız kullanıcı için kritik, gereksiz açıklama yapmadan direkt işe geç.
