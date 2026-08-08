# RoboVizyon — Çizgi Takip + QR Görev Protokolü

Raspberry Pi 5 (görüntü işleme) ↔ Arduino (MCP4725 çift kanal DAC) ↔ Motor sürücüler.

```
arduino_dac_surucu.ino      Arduino firmware                          ← YÜKLE
cizgi_takip.py              Robotta çalışan kod (takım sürümü + FIX)  ← ÇALIŞTIR
cizgi_takip_v2_referans.py  Temiz oda sürümü — referans/karşılaştırma
test_cizgi_takip.py         Referans sürümün donanımsız testi (30 kontrol)
```

`cizgi_takip.py` takımın kendi kodudur; yapısı, durum isimleri ve ayar mantığı
aynen korunmuş, sadece `# [FIX n]` işaretli noktalar değiştirilmiştir.

---

## ⚠️ İLK İŞ: `YON` bayrağını belirle

Eski kodda **iki zıt yön konvansiyonu** aynı anda vardı:

| Kanıt | Ne diyor |
|---|---|
| `SAGA_PIVOT = (2730, 1320)` — sağa dönmek için sol ileri, sağ geri | **yüksek = ileri** |
| `NORMAL_SEYIR_HIZI = 1550`, `MAX_HIZ_SINIRI = 2350` "ters tork" | **düşük = ileri** |

İkisi aynı anda doğru olamaz. Hangisi gerçekse diğer sabit takımı ters çalışıyordu —
**dönüşten sonra çizginin kaybolmasının kök sebebi budur.**

Artık her şey nötre göre **ofset** olarak yazılı ve tek `YON` bayrağı tüm yönleri
birlikte çeviriyor. Tekerlekler **havadayken** belirle:

```bash
python3 -c "
import serial, time
a = serial.Serial('/dev/ttyUSB0', 115200); time.sleep(2)
for _ in range(60):
    a.write(b'<2550,2550>\n'); time.sleep(0.03)
a.write(b'<2048,2048>\n'); a.close()"
```

| Gözlem | Yapılacak |
|---|---|
| İki teker de **ileri** döndü | `YON = +1` bırak (varsayılan) |
| İki teker de **geri** döndü | `cizgi_takip.py` içinde `YON = -1` yap — hepsi bu |
| Tekerler ters yönlerde döndü | DAC adresleri (`0x60`/`0x61`) veya sürücü kabloları karışık |

Sonra sol/sağ ayrımı: `<2550,2048>` gönder → **sol** teker dönmeli.

---

## Kurulum (Pi 5)

```bash
sudo apt install -y libzbar0
pip install pyserial pyzbar numpy opencv-python
sudo usermod -aG dialout $USER      # sonra logout/login
```

Arduino IDE: `Adafruit MCP4725` kütüphanesini kur → `arduino_dac_surucu.ino` yükle.
**Bu firmware'i yüklemek şart** — eskisindeki `Serial.parseInt()` 1000 ms timeout ile
loop'u kilitliyor ve o süre boyunca watchdog çalışamıyor (pivot sırasında aşırı dönüş).

```bash
python3 cizgi_takip.py              # çalıştır ('q' ile çık)
python3 test_cizgi_takip.py         # referans sürümün mantık testi
```

---

## Yapılan düzeltmeler

| FIX | Sorun | Etki |
|---|---|---|
| **0** | İki zıt yön konvansiyonu | Dönüşten sonra çizgi kayboluyordu. Artık tek `YON` bayrağı. Pivotlar da simetrik hâle getirildi (eskisi −728/+672 idi, dönerken yana kaydırıyordu) |
| **1** | Sabit eşik `inRange(0, 85)` | Araç dönüp kamera farklı aydınlatmaya bakınca çizgi kayboluyordu → **Otsu** + aralık kilidi + kareler arası yumuşatma |
| **1b** | Eşik 85'ten yumuşayarak geliyordu | Karanlık sahnede ilk karelerde **tüm görüntü "çizgi"** oluyordu (`x=0, w=160`) → sahte L-viraj. Artık ilk karede doğrudan Otsu'ya oturuyor |
| **1c** | Maske makullük kontrolü yoktu | Koyu piksel oranı %1–55 dışındaysa maskeye güvenilmiyor (gölge / kapanan kamera / patlayan pozlama) |
| **2** | `DOKSAN_DERECE_SAG` açık çevrim 0.7 sn | Akü düştükçe eksik/fazla dönüyordu → **kapalı çevrim**: çizgi ortalanınca biter, süre sadece üst sınır |
| **3** | `CIZGI_DOGRULA` yerinde durup bakıyordu | Duran araç çizgiyi kadraja hiç sokamaz → **yavaşça dönerek arar**. Ayrıca tam çözünürlük yerine aynı 160×120 hattı ve **alt ROI** (tüm kare, QR'ın kendi siyahını "çizgi" sayıyordu) |
| **4** | `cx_tam` / bbox init yok | `M["m00"]==0` olunca bir önceki karenin bayat değeriyle karar veriliyordu |
| **5** | `waitKey` en alttaydı | Bütün manevra durumları `continue` ile çıktığı için **pivot boyunca `q` ölüydü** → döngü başına alındı |
| **6** | `time.time()` | Pi 5'te RTC yok; NTP senkronu saati geri sıçratıp `dt`'yi negatife düşürebiliyor → türev patlar. `time.monotonic()` |
| **7** | Seri akış kontrolü yoktu | Kamera hızında spam Arduino RX buffer'ını doldurup bayat komut uygulatıyordu → 50 Hz sınırı + heartbeat okuma |

**Arduino tarafı:** `parseInt()` → bloklamayan ayrıştırıcı, RX buffer'daki tüm paketler
okunup sadece en yenisi uygulanıyor, I²C 400 kHz, watchdog 400→250 ms, slew-rate limiter.

---

## Durum makinesi

```
CIZGI_TAKIP ──L-viraj──► VIRAJ_ILERI_x ──► KESKIN_VIRAJ_x ──┐
     │                                    (timeout) └──► CIZGI_DOGRULA ──┐
     ├──QR "11"──► QR_YAKLASIM ──► QR_GORULDU_FREN ──► DOKSAN_DERECE_SAG ─┤
     │                                          (timeout) └──► CIZGI_DOGRULA
     ├──çizgi zayıf/yok──► KURTARMA_MODU ─────────────────────────────────┤
     │                                                                    ▼
     └────────────────────────────────────────── CIZGI_YAKALANDI_FREN ────┘
```

Bütün pivotlar kapalı çevrim: alt ROI'deki çizgi merkeze (`65 ≤ cx ≤ 95`) oturunca biter.
Süreler yalnızca üst sınırdır. Zaman aşımında araç durmaz — `CIZGI_DOGRULA` ile
yavaşça dönerek arar, 2 sn bulamazsa güvenli duruşa geçer.

## Ayar sırası (piste çıkınca)

1. `YON` bayrağını yukarıdaki testle kesinleştir — **her şeyden önce bu**
2. `OFS_NORMAL`'i düşük başlat (300), PID'i oturt, sonra yükselt
3. `Kp` → salınım başlayana kadar artır, sonra %60'ına çek
4. `Kd` → salınımı sönümleyene kadar artır (fazlası tekerde titreme yapar)
5. `K_ACI` → çapraz çizgide öngörüyü ayarla
6. `VIRAJ_ILERI_SURESI` → kamera burunda olduğu için köşeye varış gecikmesi (0.4–1.0 sn)
7. `OFS_PIVOT` → pivot çizgiyi atlamayacak kadar yavaş, momentum yenecek kadar hızlı
