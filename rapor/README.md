# Hoca / danışman raporu

`HalilMAP_LiDAR_Durum_Raporu.xlsx` — LiDAR entegrasyonunun durum raporu.
10 sayfa: özet, donanım, doğrulama testleri, ölçülen doğruluk, harita
çıktıları, engel algılama, kodlar, sorun-çözüm, pazartesi planı, video planı.

## Yeniden üretmek

```bash
pip install openpyxl pillow
python rapor_olustur.py
```

Görseller `gorseller/` klasöründen okunur. Excel dosyası aynı klasöre yazılır.

## Kendi odanın haritasını koymak

`gorseller/` içindeki iki harita, algoritmanın doğruluğunu **ölçebilmek** için
kullanılan sentetik doğrulama odasına aittir (gerçek boyut 6,00 × 4,00 m) —
raporun 5. sayfasında bu açıkça yazıyor.

Kendi odanı/depoyu haritalayıp değiştir:

```bash
cd ../lidar
python harita.py --tek     --cikti oda   # oda ortasında sabit dur
python harita.py --slam    --cikti depo  # yavaşça gezdir
```

Her ikisi de `<ad>_sunum.png` üretir (ölçekli, metre ızgaralı, ölçülendirilmiş).
Bu dosyaları `gorseller/ornek_tek_sunum.png` ve `gorseller/ornek_slam_sunum.png`
üzerine kopyalayıp `rapor_olustur.py`'yi tekrar çalıştır — 5. sayfadaki uyarı
metnini de kendi odana göre güncelle.

## Güncellenmesi gereken yerler

| Sayfa | Ne zaman |
|---|---|
| 1. Özet | Entegrasyon bitince "PAZARTESİ" satırı "TAMAM" olacak |
| 4. Ölçülen Doğruluk | Gerçek odada ölçüm yapılırsa yeni satır eklenecek |
| 5. Harita Çıktıları | Kendi oda/depo haritası konulacak |
| 9. Pazartesi Planı | Adımlar bitince işaretlenecek |
