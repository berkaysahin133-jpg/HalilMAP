# JK BMS → kendi web arayüzün

```
jk_bms.py       Sürücü: protokol çözücü + BLE / seri / sahte okuyucu
sunucu.py       HTTP köprüsü: JSON API + SSE canlı akış + demo panel
test_jk_bms.py  Protokol testi — BATARYA OLMADAN çalışır (44 kontrol)
```

## ⚠ Önce bir yanlış varsayımı düzeltelim

**Telefondaki JK BMS uygulamasından veri çekemezsin.** O uygulama bir veri
kaynağı değil; senin gibi BMS'e bağlanan bir istemci. Ortada paylaşılan bir
sunucu ya da API yok.

Doğru yol: **BMS'e doğrudan bağlanıp aynı veriyi kendin okumak.** Uygulama
devreden çıkar. Bu klasör tam olarak bunu yapıyor.

## Bu akşam, batarya olmadan

```bash
python3 test_jk_bms.py        # 44/44 — protokol doğrulaması
python3 sunucu.py --sahte     # http://localhost:8770/
```

`--sahte` modu **gerçek bir JK BMS'ten alınmış çerçeveleri** oynatır ve
üzerine yavaş bir şarj/deşarj döngüsü bindirir. Web arayüzünü batarya elinde
olmadan bitirebilirsin.

## Gerçek bataryaya bağlanmak

| Yol | Komut | Ne zaman |
|---|---|---|
| **RS485 / TTL** | `python3 sunucu.py --seri /dev/ttyUSB0` | **Robotta bunu kullan** |
| **BLE** | `python3 sunucu.py --ble C8:47:8C:XX:XX:XX` | Masaüstü, hızlı deneme |

> **Robotta BLE kullanma.** Motor gürültüsü ve hareket BLE bağlantısını
> düşürür; bağlantı koptuğunda yeniden kurulması saniyeler alır. RS485
> soketi (4 pinli JST 1.25 mm) aslında **3.3 V TTL, 115200 baud** — bir
> USB-TTL dönüştürücüyle doğrudan Pi'ye/Jetson'a bağlanır.
>
> BLE MAC adresini bulmak: `pip install bleak` sonra
> `python3 -c "import asyncio,bleak; print(asyncio.run(bleak.BleakScanner.discover()))"`

## Kendi arayüzüne bağlamak

CORS açık (`Access-Control-Allow-Origin: *`), farklı porttan/dosyadan
çağırabilirsin.

```js
// Basit: her saniye sor
setInterval(async () => {
  const d = await (await fetch("http://localhost:8770/api/durum")).json();
  if (d.bagli) document.querySelector("#soc").textContent = d.veri.soc_yuzde;
}, 1000);

// Daha iyi: sunucu kendisi gönderir, tek bağlantı
new EventSource("http://localhost:8770/api/akis").onmessage = (e) => {
  const d = JSON.parse(e.data);
  if (!d.bagli) return;              // veri bayat — eski değeri gösterme
  document.querySelector("#soc").textContent = d.veri.soc_yuzde;
};
```

### Uçlar

| Uç | Döndürdüğü |
|---|---|
| `GET /` | Demo panel (kendi arayüzün hazır olana kadar) |
| `GET /api/durum` | Anlık JSON |
| `GET /api/akis` | SSE, saniyede bir kendiliğinden gelir |
| `GET /api/hucreler` | Hücre gerilimleri + dirençleri (büyük, ayrı tutuldu) |

### `/api/durum` yanıtı

```json
{
  "bagli": true, "veri_yasi_s": 0.8, "hata": null,
  "cihaz": {"model": "...", "yazilim_surumu": "...", "seri_no": "..."},
  "veri": {
    "durum": "SARJ",              "soc_yuzde": 84,
    "toplam_gerilim_v": 53.251,   "akim_a": 12.0,
    "guc_w": 639.0,               "sarj_gucu_w": 639.0, "desarj_gucu_w": 0.0,
    "kalan_kapasite_ah": 68.494,  "tam_kapasite_ah": 81.0,
    "kalan_sure_sa": 1.04,        "dongu_sayisi": 0, "soh_yuzde": 100,
    "hucre_sayisi": 16,           "hucre_gerilimleri": [3.327, ...],
    "min_hucre_v": 3.327,         "max_hucre_v": 3.329,
    "delta_hucre_v": 0.002,       "min_hucre_no": 1, "max_hucre_no": 2,
    "sicaklik_1_c": 19.0,         "sicaklik_2_c": 19.1,
    "mosfet_sicaklik_c": 21.0,    "dengeleme": false,
    "sarj_mosfet_acik": true,     "desarj_mosfet_acik": true,
    "sarj_fisi_takili": false,    "hatalar": []
  }
}
```

**`bagli` alanını mutlaka kontrol et.** BMS susarsa son değer ekranda
kalır ve "batarya %84" yazarken aslında veri 10 dakika eskimiş olabilir.

## Protokol

Yazılım sürümü ≥ 6.0 olan JK BMS'ler:

```
İstek  (20 bayt):  AA 55 90 EB <adres> <uzunluk> <değer:4> ...00... <CRC>
Yanıt (300 bayt):  55 AA EB 90 <tip> ... <CRC>
CRC             :  tüm baytların toplamının düşük 8 biti
Tipler          :  0x01 ayarlar · 0x02 hücre bilgisi · 0x03 cihaz · 0x05 kayıt
BLE             :  servis 0xFFE0, karakteristik 0xFFE1 (20'şer bayt gelir)
```

**Çerçeve sürümü:** `24S` (eski) / `32S` (donanım 11.0+). Alanlar kayar,
yanlış sürümle gerilim ve SOC saçma çıkar. `surum_tahmin_et()` bunu
kendiliğinden bulur — hücre gerilimlerinin toplamı paket gerilimine hangi
sürümde uyuyorsa o seçilir.

## Testler neyi kanıtlıyor

Test verisi uydurma değil: **gerçek bir JK BMS'ten alınmış 300 baytlık
çerçeveler.** En güçlü iki çapraz kontrol:

1. **Hücre gerilimlerinin toplamı = paket gerilimi alanı** → 53.256 V ve
   53.251 V, fark **5 mV**. Ofsetlerden biri yanlış olsa tutmazdı.
2. **Kalan/tam kapasite oranı = SOC alanı** → %84.6 ve %84.

İki bağımsız alan birbirini doğruluyorsa çözücü doğrudur.

Kaynak: alan konumları [syssi/esphome-jk-bms](https://github.com/syssi/esphome-jk-bms)
projesinden alınmış, gerçek cihaz çerçeveleriyle doğrulanmıştır.
