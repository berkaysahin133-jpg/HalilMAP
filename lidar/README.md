# RPLIDAR C1 — başlangıç

```
c1.py        Bağımsız sürücü (sadece pyserial). ROS gerekmez.
goster.py    Canlı görünüm / kayıt / oynatma / sentetik oda
test_c1.py   Protokol testi — LİDAR TAKILI OLMADAN çalışır (16 kontrol)
```

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

python3 test_c1.py                  # 1) donanımsız protokol testi -> 16/16
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
