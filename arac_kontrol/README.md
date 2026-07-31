# RoboVizyon — Çizgi Takip + QR Görev Protokolü

Raspberry Pi 5 (görüntü işleme) ↔ Arduino (MCP4725 çift kanal DAC) ↔ Motor sürücüler.

```
arduino_dac_surucu.ino   Arduino firmware (I²C DAC + watchdog + rampa)
cizgi_takip.py           Pi 5 görüntü işleme + PID + durum makinesi
test_cizgi_takip.py      Donanımsız mantık testi (30 kontrol)
```

---

## ⚠️ İLK İŞ: Motor yönünü doğrula

Eski koddaki `TEMEL_HIZ = 1550` değeri, nötre (2048) göre `2546`'nın **tam simetriğiydi** —
yani araç seyir halinde geri gidiyordu. Yeni kodda tüm hızlar `-1.0 … +1.0` arasında
normalize edilir ve tek bir sabitle DAC'a çevrilir, bu yüzden hata tekrar edemez.

**Tekerlekler havadayken** (kriko/sehpa üstünde) şunu çalıştır:

```bash
python3 -c "
import sys; sys.path.insert(0,'.')
from cizgi_takip import MotorLink
import time
l = MotorLink()
l.gonder(0.35, 0.35); time.sleep(2); l.kapat()
"
```

| Gözlem | Yapılacak |
|---|---|
| İki teker de **ileri** döndü | `YON = +1` kalsın (varsayılan) |
| İki teker de **geri** döndü | `cizgi_takip.py` içinde `YON = -1` yap |
| Tekerler ters yönlerde döndü | DAC adreslerini (`0x60`/`0x61`) veya sürücü kablolarını kontrol et |

Sonra sol/sağ ayrımı:

```python
l.gonder(0.35, 0.0)   # SOL teker dönmeli, sağ durmalı
```

---

## Kurulum (Pi 5)

```bash
sudo apt install -y libzbar0 python3-opencv
pip install pyserial pyzbar numpy
sudo usermod -aG dialout $USER      # sonra logout/login
```

Arduino tarafı: `Adafruit MCP4725` kütüphanesi (Library Manager) → `arduino_dac_surucu.ino` yükle.

## Çalıştırma

```bash
python3 cizgi_takip.py              # pencereli (masaüstü / VNC)
python3 cizgi_takip.py --headless   # SSH veya systemd servisi
python3 cizgi_takip.py --kalibre    # motora komut gitmez, sadece görüntü + eşik ayarı
python3 test_cizgi_takip.py         # donanım olmadan mantık testi
```

Çıkış: pencere odaktayken **`q`**, ya da terminalde **Ctrl+C**. Her iki durumda da
`finally` + `atexit` motorları nötre indirir; ayrıca Arduino 250 ms komut kesintisinde
kendi başına durur.

---

## Görüntü işleme mimarisi

Kare 320×240 alınır, analiz 160×120'de yapılır. Üç yatay bant taranır:

| Bant | Kare oranı | Görevi |
|---|---|---|
| **YAKIN** | %72–98 | Direksiyon hatası (PID girişi) |
| **ORTA** | %46–70 | Eğrilik tahmini |
| **UZAK** | %20–44 | Ön-görüş (feed-forward) + hız kesme |

Her bant için:
1. Gauss bulanıklaştırma → **Otsu** ile uyarlanabilir eşik
2. Eşik `[35, 135]` aralığına kilitlenir ve kareler arası yumuşatılır (ani ışık değişiminde kaçmaz)
3. Koyu piksel oranı `%1–%55` dışındaysa ölçüm **geçersiz** sayılır (gölge / kapalı kamera koruması)
4. Morfolojik açma → en büyük kontur → centroid `-1.0 … +1.0` normalize

**Direksiyon** = PID(yakın.cx) + `FF_KAZANC × (uzak.cx − yakın.cx)`
**Hız** = `HIZ_SEYIR × (1 − YAVASLAMA × eğrilik)`, taban `HIZ_MIN`

Yani viraja girmeden önce tekerlek dönmeye başlar ve araç kendiliğinden yavaşlar.

## Durum makinesi

```
CIZGI_TAKIP ──köşe──► PIVOT_SOL / PIVOT_SAG ──çizgi ortalandı──► CIZGI_TAKIP
     │                        └──süre doldu──► CIZGI_ARA ──► CIZGI_TAKIP
     └──QR "11" doğrulandı──► QR_YAKLASIM ──► QR_FREN ──► PIVOT_QR ──► CIZGI_TAKIP
     └──çizgi 0.8 sn yok──► CIZGI_ARA
```

Pivotlar **kapalı çevrim**: çizgi merkeze oturunca biter (`KOSE_CIKIS`), süre sadece üst
sınırdır. Eski koddaki sabit 1.4 sn açık çevrim, akü voltajı düştükçe açıyı tutturamıyordu.

---

## Ayar sırası (piste çıkınca)

1. `--kalibre` ile bantların çizgiyi doğru gördüğünü ve `esik` değerinin oturduğunu doğrula
2. `HIZ_SEYIR`'i düşük başlat (0.35), PID'i oturt, sonra yükselt
3. `Kp` → salınım başlayana kadar artır, sonra %60'ına çek
4. `Kd` → salınımı sönümleyene kadar artır (fazlası tekerde titreme yapar)
5. `Ki` → en son, kalıcı yanal kaymayı silmek için
6. `KOSE_CX_ESIK` / `KOSE_EN_BOY` → L-virajda tetiklenip düz yolda tetiklenmemeli

## Değiştirilen davranışlar (eski koda göre)

- Eski "akıllı refleks" (maskede kareye benzeyen kontur → 90° dönüş) **kaldırıldı**.
  QR içeriği `pyzbar` ile doğrulanmadan hiçbir manevra tetiklenmez. Eski hâlinde
  gölge, bant yaması veya T-kavşak aracı yanlış yöne döndürebiliyordu.
- `time.time()` → `time.monotonic()` (Pi 5'te RTC yok; NTP senkronu `dt`'yi negatife
  düşürüp PID'i patlatabiliyordu)
- `CAP_PROP_BUFFERSIZE = 1` (V4L2 varsayılanı 4 kare biriktirip ~100 ms ölü zaman yaratıyordu)
- `cv2.waitKey` artık her karede çağrılıyor — pivot sırasında da `q` çalışır
- Arduino: `parseInt()` yerine bloklamayan ayrıştırıcı (1 sn timeout watchdog'u durduruyordu),
  I²C 400 kHz, watchdog 400→250 ms, rampa sınırlayıcı
