# RPLIDAR C1 — başlangıç

```
basla.py         Sıfırdan başlatan tek dosya — ne yapacağını bilmiyorsan BUNU çalıştır
tanila.py        Teşhis — veri gelmiyorsa BUNU çalıştır, sorunu söyler
c1.py            Bağımsız sürücü (sadece pyserial). ROS gerekmez.
goster.py        Canlı görünüm / kayıt / oynatma / sentetik oda
harita.py        2D harita: tek tarama + gezerek (ICP-SLAM)
guvenlik.py      Güvenlik bölgesi — LiDAR'ın araç üzerindeki asıl görevi
test_c1.py       Protokol testi — LİDAR OLMADAN çalışır (26 kontrol)
test_harita.py   ICP/SLAM testi — LİDAR OLMADAN çalışır (20 kontrol)
test_guvenlik.py Güvenlik bölgesi testi — LİDAR OLMADAN çalışır (31 kontrol)
```

## LiDAR'ın araç üzerindeki görevi

LiDAR bu araçta **navigasyon yapmaz** — yönü çizgi izleme, konumu QR verir.
LiDAR'ın işi, kameranın yapamadığı şey: önündeki boşluğu metrik olarak ölçmek.

```bash
python guvenlik.py --sahte      # LiDAR olmadan dene
python guvenlik.py              # canlı
python guvenlik.py --genislik 0.6 --dur 0.4 --yavas 0.9
```

Aracın önünde koridor şeklinde bir bölge tanımlanır (`--genislik` = araç
genişliği + pay). Bölgeye giren nesneye göre:

| Durum | Koşul | Hız çarpanı |
|---|---|---|
| 🟢 SERBEST | koridor boş | ×1.0 |
| 🟡 YAVAS | engel < 90 cm | ×0.4 |
| 🔴 DUR | engel < 40 cm | ×0.0 |

Üç tasarım kararı ve gerekçeleri:

- **`min_nokta=2`** — tek gürültü noktası aracı durdurmamalı.
- **Histerezis (12 cm)** — eşiğin tam üstünde titreyen engel, aracı sürekli
  dur-kalk yaptırır. Çıkış eşiği giriş eşiğinden büyük. (Test: eşikte ±2 cm
  oynayan engelde 20 karede en fazla 1 durum değişimi.)
- **Bayat veri → YAVAS** — sensör susarsa tam hızla devam etmek en tehlikeli
  davranıştır. 0.7 sn veri gelmezse otomatik yavaşlar.

### Çizgi izleme koduna bağlamak

```python
from guvenlik import GuvenlikOkuyucu
oku = GuvenlikOkuyucu(port="/dev/ttyUSB0")   # arka planda tarar, ana döngüyü bloklamaz
...
d = oku.durum()
hiz = int(TABAN_HIZ * d["hiz_carpani"])
if d["durum"] == "DUR":
    duzeltme = 0                             # dururken direksiyon kırma
```

> LiDAR'ı ana döngüde okuma. Çizgi takibi ~30 Hz döner, LiDAR 10 Hz üretir;
> `next(taramalar())` çağırırsan direksiyon LiDAR'ı beklemeye başlar.
> `GuvenlikOkuyucu` bu yüzden ayrı iş parçacığında çalışır.

## ⚠ "Bağlanıyor ama veri gelmiyor"

```
[BILGI]  {'model': 65, 'yazilim': '1.2', ...}
[SAGLIK] iyi (kod 0)
[HATA]   veri gelmiyor
```

**Bu tablo teşhisin tamamı:**

| Ne oldu | Ne demek |
|---|---|
| Model + seri no okundu | Port, baud (460800) ve kablo **doğru** |
| Sağlık "iyi" | Cihazın elektroniği **sağlam** |
| SCAN kabul edildi, ölçüm yok | **Kafa dönmüyor** → USB yeterli akım vermiyor |

Ölçüm yalnızca kafa dönerken üretilir. Motor stall olursa cihaz komutlara
cevap vermeye devam eder ama tek bayt ölçüm göndermez — tam olarak bu tablo.

```bash
python tanila.py            # hangi aşamada takıldığını satır satır söyler
```

`tanila.py` DTR/RTS motor hattının 4 kombinasyonunu da dener, gelen ham baytı
sayar ve `tanila_cikti.txt` yazar. Sırasıyla dene, her adımdan sonra tekrar
çalıştır:

1. **Başka bir USB porta tak** — masaüstünde kasanın **arka** paneli
   (anakart üzeri), dizüstünde **şarj takılıyken**. Hub/uzatma varsa çıkar.
2. **Kabloyu değiştir** — ince damarlı "sadece şarj" kabloları motor akımında
   gerilim düşürür.
3. Adaptörde ayrı **5V girişi** varsa oradan besle.
4. Kafanın önünde nakliye bandı / koruyucu köpük varsa **çıkar**.

## Cihaz (Slamtec RPLIDAR C1)

| | |
|---|---|
| Menzil | 0.05–12 m (beyaz) / 0.05–6 m (siyah) |
| Tarama | 8–12 Hz (tipik 10) |
| Örnekleme | 5 kHz → tur başına ~500 nokta |
| Açısal çözünürlük | 0.72° |
| Arayüz | TTL UART, **460800 baud** |
| Doğruluk | 15 mm (çözünürlük 30 mm) |

> ⚠ **En sık yapılan hata:** C1 **460800** baud kullanır. İnternetteki
> RPLIDAR örneklerinin çoğu A1/A2 için yazılmış ve 115200 kullanır — o hızla
> port açılır ama **hiç veri gelmez**. `c1.py` doğru hızı varsayılan alır.

## Bu akşam yapılacaklar (robot gerekmez)

```bash
pip install pyserial opencv-python numpy

python3 test_c1.py                  # 1) donanımsız protokol testi -> 26/26
python3 goster.py --sahte           # 2) sentetik oda, arayüzü tanı
python3 goster.py                   # 3) LiDAR'ı USB'ye tak, canlı gör
```

3. adımda göreceklerin: cihaz modeli, seri no, sağlık durumu, sonra canlı
tarama. Odanın duvarları çıkmalı. LiDAR'ı elinle döndür, nokta bulutu dönsün.

**Pisti/depoyu kaydet, evde çalış:**
```bash
python3 goster.py --kayit depo1     # gez, çık -> depo1.npz
python3 goster.py --oynat depo1.npz # robot olmadan tekrar tekrar incele
```

## Odanın 2D haritası

```bash
python3 test_harita.py                 # önce donanımsız doğrula -> 20/20

python3 harita.py --sahte --slam       # LiDAR gelmeden sentetik odada dene
python3 harita.py --tek                # odanın ORTASINA koy, sabit dur
python3 harita.py --slam               # LiDAR'ı elinde yavaşça gezdir
python3 harita.py --oynat oda1.npz     # kayıttan harita çıkar
```

Çıktı: `harita.png` + `harita.npz` (ızgara + çözünürlük + poz geçmişi).

**`--tek`** odanın ortasından tek 360° tarama alır. Bu zaten bir haritadır —
SLAM'e gerek yok. Eşyaların ARKASI görünmez (gölge kalır), o kadar.

**`--slam`** her yeni taramayı biriken haritaya **ICP** ile oturtur; böylece
sensörün ne kadar hareket ettiğini görüntüden çıkarır. Tekerlek enkoderi
olmadan "odometri" tam olarak böyle üretilir — ve kayma da buradan gelir.

### Ölçülen doğruluk (sentetik oda, gerçek yörünge biliniyor)

| Senaryo | Sapma |
|---|---|
| 2.34 m düz | **0.8 cm** (ortalama 0.4 cm) |
| 90° dönüşlü güzergâh | 1.0 cm / **0.18°** |
| 3 cm ölçüm gürültüsü | 1.8 cm |
| **6.8 m kapalı güzergâh, 2 dönüş** | **24.4 cm** ← kayma burada başlıyor |
| Gezdikten sonra oda ölçüsü (6.0 × 4.0 m) | ±9 cm |

Son satır önemli: yol uzadıkça ve dönüş sayısı arttıkça hata **birikir**.
Küçük odada sorun değil, depoda olur. Çözümü döngü kapama (loop closure) ve
odometri — ikisi de `slam_toolbox`'ta var, bu basit sürümde yok.

### Haritan aynaysa

`harita.py` içinde `ACI_YONU = +1` var. Gerçek cihazda tarama açısı ters
yönde artıyorsa harita sağ/sol takas çıkar (boyutlar doğru, yerleşim ayna).
O zaman `ACI_YONU = -1` yap.

## PC mi, Jetson mu?

**Önce PC.** Gerekçe:

| | PC | Jetson Orin Nano |
|---|---|---|
| Kurulum | 5 dk | JetPack + ROS 2 derleme, saatler |
| RViz / görselleştirme | akıcı | ağır |
| Deneme döngüsü | hızlı | yavaş (SSH, kaynak sınırı) |
| Robota takılı olması gerekir mi | hayır | evet |

LiDAR USB'den beslenip USB'den konuşuyor — makineler arası taşımak 5 saniye.
ROS 2 kodu ikisinde de aynı; sonunda Jetson'a taşırken sadece yeniden derlersin.
**Jetson'ı, PC'de çalışan bir sistemin varken kur.**

## Sonraki adım: ROS 2 + haritalama

Bu klasördeki sürücü LiDAR'ı tanıman içindi. Gerçek haritalama için ROS 2:

```bash
# Ubuntu 22.04 -> ROS 2 Humble  |  Ubuntu 24.04 -> Jazzy
mkdir -p ~/ros2_ws/src && cd ~/ros2_ws/src
git clone -b ros2 https://github.com/Slamtec/rplidar_ros.git
cd ~/ros2_ws && colcon build --symlink-install
source install/setup.bash
sudo ~/ros2_ws/src/rplidar_ros/scripts/create_udev_rules.sh

ros2 launch rplidar_ros view_rplidar_c1_launch.py     # C1'e özel launch
```

Sonra haritalama:
```bash
sudo apt install ros-$ROS_DISTRO-slam-toolbox ros-$ROS_DISTRO-nav2-bringup
ros2 launch slam_toolbox online_async_launch.py
```

### Dürüst uyarı: SLAM tek başına LiDAR ile kırılgandır

`slam_toolbox` sadece lazer taramasıyla da çalışır (scan matching), **ama**
depo gibi uzun ve simetrik koridorlarda kayar — çünkü ardışık iki tarama
birbirinin aynısı olur ve algoritma "ne kadar ilerledim" sorusunu cevaplayamaz.

Sağlam bir harita için **odometri** lazım:
- **En iyisi:** tekerlek enkoderleri (Kelly sürücülerin hall çıkışı varsa oradan)
- **İdare eder:** IMU (yalnızca dönüşü düzeltir, mesafeyi değil)
- **Yoksa:** haritayı yavaş ve bol köşeli bir güzergâhta çıkar, tek seferde kullan

Sıralama önerisi: önce LiDAR'dan veri al (bu klasör) → ROS 2'de `/scan`
konusunu gör → odometri kaynağını çöz → sonra slam_toolbox. Odometri olmadan
SLAM'e girersen kaybolan zaman çok olur.
