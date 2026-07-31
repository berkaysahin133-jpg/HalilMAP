# RoboVizyon — Kuşbakışı Çizgi Takip Yığını

Otonom araçların kullandığı mimarinin küçültülmüş hâli. Piksel eşiği + centroid + PID
yerine: **kuşbakışı dönüşüm → kayan pencere → çember modeli → Pure Pursuit**.

```
robovizyon/
  konfig.py       Tüm ayarlar tek yerde, konfig.json'a kaydedilir
  persfektif.py   Kuşbakışı (IPM) dönüşümü + görüş alanı doğrulaması
  serit.py        Binarizasyon → kayan pencere → çember/doğru fit → köşe analizi
  kontrol.py      Pure Pursuit + fiziksel hız profili
  gorev.py        Durum makinesi (takip / köşe / QR / kurtarma)
  motor.py        cm/s → DAC → Arduino
  qr.py           ROI taraması + çok kareli onay
  kamera.py       Taze kare (buffer gecikmesi yok)
  gorsel.py       Hata ayıklama panelleri
  simulasyon.py   Sentetik pist — robot olmadan kapalı çevrim test

surus.py            Ana çalıştırma
kalibre.py          Kuşbakışı kalibrasyonu + canlı eşik ayarı
test_robovizyon.py  69 kontrol (birim + kapalı çevrim simülasyon)
```

---

## Neden bu mimari

| Eski yaklaşım | Sorunu | Buradaki karşılığı |
|---|---|---|
| `inRange(gray, 0, 85)` | Salon ışığı tek tip değil; pencere altında zemin 190, köşede 90 olur | **Yerel ortalama çıkarma** — her piksel kendi komşuluğuyla kıyaslanır, mutlak parlaklık önemsizleşir |
| En büyük kontur + centroid | Tek sayı üretir, çizginin **şeklini** bilmez; virajı ancak içine girince fark eder | **Kayan pencere** ile çizgi alttan yukarı takip edilir, tüm nokta bulutu çıkar |
| Piksel hatası (`cx − 80`) | 1 piksel yakında 2 mm, uzakta 3 cm; ayarlar hızla/eğimle kayar | **Kuşbakışı** — hata santimetre cinsinden, ayarlar fiziksel anlamlı |
| `cx >= 145` ile köşe | Tahmini eşik; gölge/kavşak yanlış tetikler | **Geometrik**: dikey çizgi biter, yatay koşu ölçülür, köşenin **kaç cm ilerde** olduğu bilinir |
| PID | Düz yolda kalıcı yanal sapma bırakır; Kd titretir, Ki windup yapar | **Pure Pursuit** — kalıcı sapma yok, tek ayar parametresi (Ld) |
| `VIRAJ_ILERI_SURESI = 0.6` | Tahmini süre; akü düşünce şaşar | Köşe mesafesi **ölçülür**, hız komutu integre edilerek katedilir |
| Sabit süreli pivot | Açık çevrim, açı tutmaz | Çizgi hizalanınca biter; süre yalnızca üst sınır |

---

## Ölçülen performans (simülasyon, 45 cm/s)

Sentetik pistte gerçek konum bilindiği için sapma kesin ölçülebiliyor:

| Senaryo | Ortalama | RMS | Tepe | Çizgi kaybı |
|---|---|---|---|---|
| Düz yol | −2.2 mm | **2.6 mm** | 4.2 mm | %0 |
| Düz / 12 cm yanal ofsetle başla | −2.0 mm | 3.0 mm | 11.0 mm | %0 |
| Düz / 20° eğik başla | −2.2 mm | 2.6 mm | 4.4 mm | %0 |
| Karanlık salon (0.5× ışık) | −2.9 mm | 3.1 mm | 4.4 mm | %0 |
| Parlak + ağır gürültü | −2.2 mm | 2.5 mm | 4.1 mm | %0 |
| Geniş yay R=90 cm | +22.5 mm | 23.5 mm | 33.8 mm | %0 |
| Dar yay R=55 cm | −36.7 mm | 38.8 mm | 58.0 mm | %0 |

**90° köşe:** `TAKIP → KOSE_YAKLAS → KOSE_PIVOT → TAKIP`, hizalanma 0.90 sn
(teorik 0.94), köşe sonrası takip RMS 33 mm. Sağ ve sol için de.

**Dürüst not:** Düz yolda sapma pratikte sıfır. Yayda kalan 2–4 cm, Pure Pursuit'in
geometrik iç-kesmesi ile çember fit yanlılığının toplamıdır; yarıçap küçüldükçe artar.
Bu sayılar **simülasyondan**; gerçek pistte kalibrasyon kalitesi ve zemin tutuşu
belirleyici olur. Ama mimari, eski koddaki hata sınıflarının tamamını ortadan kaldırıyor.

---

## Kurulum ve ilk çalıştırma

```bash
pip install opencv-python numpy pyserial pyzbar
sudo apt install -y libzbar0

python3 test_robovizyon.py          # 69 kontrol — donanım gerekmez
```

### 1. Motor yönü (tekerlekler havada)

```bash
python3 -c "
from robovizyon import Konfig, MotorLink
import time
k = Konfig(); m = MotorLink(k.motor, k.kontrol)
m.sur(20, 20); time.sleep(2); m.kapat()"
```
İleri döndüyse `yon = +1` kalsın; geri döndüyse `konfig.json`'da `motor.yon = -1`.

### 2. Kuşbakışı kalibrasyonu

```bash
python3 kalibre.py --geometrik
```
Kamera yüksekliğini (yerden lens merkezine, cm) ve eğimini (yataydan aşağı, derece)
ölç, trackbar'lara gir. **Hedef:** yerdeki düz çizgi, sağdaki kuşbakışı panelinde de
düz ve dikey görünsün; genişliği her mesafede aynı kalsın. `s` ile kaydet.

Daha hassas isterseniz yere bilinen ölçüde dikdörtgen yapıştırıp:
```bash
python3 kalibre.py --dortnokta --en 40 --boy 60 --uzaklik 15
```

> Program, kameranın **kör noktasını** kendisi hesaplar. `y_min_cm` görülemeyen bir
> mesafeye ayarlıysa uyarır ve düzeltir — bu kontrol olmadan polinom görülmeyen
> bölgede ekstrapole ediliyor, yanal hata %28 kazanç hatası alıyordu.

### 3. Sürüş

```bash
python3 surus.py --kuru        # motor komutu GITMEZ, sadece algılamayı izle
python3 surus.py              # gerçek sürüş ('q' ile çık)
python3 surus.py --kayit kosu1   # ham video + telemetri CSV kaydet
```

---

## 🔑 11 gün için en önemli özellik: offline ayar

Robota erişimin olmadığı saatlerde de ilerleyebilirsin.

**1. Pisti kaydet** — kamerayı robota monte ettiğin konumda tutup pisti bir kez gez:
```bash
python3 surus.py --kayit pist1 --kuru
```
(veya telefonu aynı yükseklik/açıda tutup video çek)

**2. Bilgisayarda ayarla** — robot gerekmez:
```bash
python3 kalibre.py --video kayitlar/pist1.avi    # eşik + perspektif
python3 surus.py  --video kayitlar/pist1.avi     # tüm yığın, ne karar verdiğini izle
```

**3. Ayarları simülasyonda doğrula:**
```bash
python3 test_robovizyon.py
```

Bu döngü sayesinde pist başında saatler harcamak yerine, tek geçişte kaydedip
sakin sakin oturup ayar yapabilirsin.

---

## Ayar sırası

1. **`motor.yon`** — her şeyden önce (tekerlekler havada)
2. **Kuşbakışı** — `kalibre.py`, çizgi kuşbakışında düz görünene kadar
3. **`serit.kontrast_esigi`** — maske sadece çizgiyi kaplasın, gölge/zemin kaplamasın
4. **`kontrol.hiz_max_cm_s`** — düşük başla (20), oturunca yükselt
5. **`kontrol.on_gorus_taban_cm`** — salınım varsa artır, viraj geç dönülüyorsa azalt
6. **`kontrol.yanal_ivme_max_cm_s2`** — virajda kayıyorsa azalt (fiziksel sınır)
7. **`kose.yatay_kosu_cm`** — L-virajda tetiklensin, kavşak/gölgede tetiklenmesin
8. **`kontrol.yanal_duzeltme`** — en son; yayda kalıcı sapma varsa hafif artır
   (0.006 üstü dar virajda kararsızlaşıyor)

## Simülasyonda kendi pistini dene

```python
from robovizyon.simulasyon import pist_duz, pist_yay, pist_kose
# pist_kose(giris=95, cikis=110, sag=True)  -> 90 derece L
# pist_yay(yaricap=60, aci_derece=90, sag=False)
```
`test_robovizyon.py` içindeki `senaryolar` listesine ekleyip ölç.
