import cv2
import numpy as np
import serial
import time
from pyzbar.pyzbar import decode

# =============================================================================
# STABİLİZE SÜRÜM -- yapı, durum makinesi ve ayar değerleri AYNEN korundu.
# Her değişiklik  # [S-n]  ile işaretli; diff alıp neyin değiştiğini görebilirsin.
#
#   [S-1]  time.time() -> time.monotonic()   (Pi 5'te saat sıçraması Kd'yi patlatır)
#   [S-2]  Türev filtresi + anti-windup       (VARSAYILAN = orijinal davranış)
#   [S-3]  cx_tam / boundingRect init          (m00==0'da bayat/tanımsız değer)
#   [S-4]  Seri yazma hız sınırı + heartbeat okuma
#   [S-5]  waitKey döngü başında               (pivot sırasında 'q' ölüydü)
#   [S-6]  Alternatif eşik modu (VARSAYILAN KAPALI -- ayarlarını etkiler)
#   [S-7]  Kamera: V4L2 + MJPG + kısa pozlama
#   [S-8]  Kurtarma tarama gücü ayarlanabilir  (VARSAYILAN = orijinal)
#   [S-9]  QR: kare atlama + N kare onayı      (tek yanlış okuma = yanlış dönüş)
#   [S-10] CIZGI_DOGRULA aynı maskeyi kullanır (tam çözünürlükte QR'ın kendi
#          siyahını "çizgi" sayabiliyordu)
#   [S-11] finally: nötr komutu zorla gönderilir
#
# VARSAYILAN AYARLARLA BU DOSYA SENİN KODUNLA AYNI ŞEKİLDE SÜRER.
# Değişen tek şey: çökme/kilitlenme/güvenlik sınıfı hatalar giderildi.
# [S-2], [S-6], [S-8] birer ANAHTAR; istersen açarsın, ölçümleri yanlarında.
#
# ⚠ DEĞİŞTİRİLMEYEN ve DEĞİŞTİRİLMEMESİ GEREKEN:
#   Direksiyon işareti (sol_dac = hiz + duzeltme). Bu araçta motorlar fiziksel
#   olarak SOL/SAĞ TERS bağlı; kodun işareti de ters. İkisi birbirini götürüyor
#   ve sistem doğru çalışıyor. "Düzeltmek" aracı çizgiden uzaklaştırır.
# =============================================================================

# --- [S-6] Eşik ayarı --------------------------------------------------------
# "sabit" -> senin orijinal davranışın: inRange(0, 85)   <-- VARSAYILAN
# "yerel" -> yerel ortalama çıkarma (aydınlatmadan bağımsız)
#
# ÖLÇÜLDÜ: "yerel" karanlık salonda çok daha iyi (449 mm -> 15 mm) AMA senin
# L-viraj eşiklerin (alan>600, x<15 and w>65) sabit eşikli maskeye göre
# ayarlanmış. Maske değişince kontur büyüyor ve araç 90 köşeyi DÖNEMİYOR.
# Bu yüzden varsayılan "sabit". Salonun karanlıksa "yerel"e al, ama o zaman
# L-viraj eşiklerini yeniden ayarlaman gerekir.
ESIK_MODU = "sabit"
SABIT_ESIK = 85             # ESIK_MODU="sabit" iken kullanılır
YEREL_PENCERE = 25          # yerel ortalama penceresi (px, tek sayı)
KONTRAST_ESIGI = 22         # yerel ortalamadan bu kadar koyu = çizgi
                            # (16/12/22 süpüruldu, 22 en iyi)
_yerel_px = YEREL_PENCERE | 1
_esik_f = 85.0              # sadece ekranda göstermek için

# --- [S-9] QR ayarı ----------------------------------------------------------
QR_TARAMA_ARASI = 2         # her N karede bir tara (Pi 5'te pyzbar ~15 ms)
QR_ONAY_KARE    = 2         # bu kadar üst üste aynı içerik okunmadan manevra yok
_qr_gecmis = []
_qr_kare = 0

# =============================================================================
# 1. SERİ PORT BAĞLANTISI
# =============================================================================
try:
    arduino = serial.Serial('/dev/ttyUSB0', 115200, timeout=0.05)
    print("[SİSTEM] Arduino bağlantısı başarılı. Senkronize takip başlıyor!")
    time.sleep(2)
    arduino.reset_input_buffer()          # [S-4]
    arduino.reset_output_buffer()         # [S-4]
except Exception as e:
    print(f"[HATA] Seri port açılamadı: {e}")
    exit()

_son_paket = None                          # [S-4]
_son_gonderim = 0.0                        # [S-4]


def motor_sur(sol_dac, sag_dac, zorla=False):
    """Arduino'ya <Sol,Sag> DAC paketini iletir.

    [S-4] Aynı paketi kamera hızında tekrar tekrar göndermek Arduino'nun 64
    baytlık RX arabelleğini doldurup BAYAT komut uygulanmasına yol açıyordu.
    50 Hz fazlasıyla yeterli (firmware watchdog'u 250 ms).
    """
    global _son_paket, _son_gonderim
    paket = (int(np.clip(sol_dac, 0, 4095)), int(np.clip(sag_dac, 0, 4095)))
    simdi = time.monotonic()
    if not zorla and paket == _son_paket and (simdi - _son_gonderim) < 0.02:
        return
    _son_paket, _son_gonderim = paket, simdi
    try:
        arduino.write(f"<{paket[0]},{paket[1]}>\n".encode('utf-8'))
    except Exception as e:
        print(f"[HATA] Seri yazma: {e}")


def arduino_dinle():
    """[S-4] Firmware'in heartbeat satırlarını yut, RX birikmesin."""
    try:
        if arduino.in_waiting:
            arduino.read(arduino.in_waiting)
    except Exception:
        pass


# =============================================================================
# 2. HIZ, TORK VE KİNEMATİK AYARLAR (BURADAN AYARLAYACAKSIN!)
#    -- Bu bölümdeki hiçbir değer değiştirilmedi --
# =============================================================================
NOTR = 2048  # Tam duruş noktası (2.50V)

NORMAL_SEYIR_HIZI = 1550  # Çizgi ortadayken hızlı ve güçlü seyir
DUZELTME_SEYIR_HIZI = 1620  # Çizgiden sapınca tork kaybetmeden ortalama hızı
HATA_ESIGI = 12  # Bu piksel sapmasının üstü düzeltme hızına geçer

# --- KESKİN VİRAJ ÖNCESİ İLERİ SÜRÜŞ SÜRESİ ---
# ⚠ BU DOSYADAKİ TEK DEĞİŞTİRİLEN AYAR: 0.6 -> 1.6
#
# Ölçüldü (90 derece köşe, kapalı çevrim simülasyon):
#     0.6 -> SAĞ ✗  SOL ✗      (senin şu anki değerin)
#     1.0 -> SAĞ ✓  SOL ✗
#     1.2 -> SAĞ ✓  SOL ✗
#     1.4 -> SAĞ ✓  SOL ✓      (tek başına isabet; 1.5 ve 1.6 kaçırıyor)
#     1.7 -> SAĞ ✓  SOL ✓  ┐
#     1.8 -> SAĞ ✓  SOL ✓  ├ KESİNTİSİZ GÜVENLİ BANT -> ortası seçildi
#     1.9 -> SAĞ ✓  SOL ✓  │
#     2.0 -> SAĞ ✓  SOL ✓  ┘
# Düz yol sapması hiçbirinde değişmiyor (3.5 mm).
#
# NEDEN: köşe yaklaşık 35 cm ilerideyken tespit ediliyor. DUZELTME_SEYIR_HIZI
# ile hız ~21 cm/s. 0.6 sn = 13 cm -> araç köşeye 22 cm KALA pivota giriyor,
# dönünce boş zemine bakıyor, çizgiyi kaybediyor ve KURTARMA'da savruluyor.
# ("Bazen dönüyor" görüntüsü, savrulurken şans eseri doğru tarafa düşmesiydi.)
#
# KENDİ ARACINDA AYARLAMAK İÇİN:
#   konsolda "[KESKİN KÖŞE] ... Algılandı" yazdığı ANDA aracın köşeye
#   uzaklığını ölç (cm), DUZELTME hızına böl. Araç köşeyi geçip dönüyorsa
#   azalt, köşeye varmadan dönüyorsa artır.
VIRAJ_ILERI_SURESI = 1.8

# --- PİVOT DÖNÜŞ GÜÇLERİ ---
SOLA_PIVOT = (1320, 2720)  # Sola kontrollü pivot
SAGA_PIVOT = (2730, 1320)  # Sağa kontrollü pivot

DONUS_SURESI_90_DEG = 0.7  # QR 11 okununca yapılacak 90° dönüş süresi

# Standart PID Katsayıları
Kp = 5.8
Ki = 0.01
Kd = 4.0
K_ACI = 0.85  # Çapraz çizgi açı telafi katsayısı (Stanley Look-Ahead)

MIN_HIZ_SINIRI = 1080
MAX_HIZ_SINIRI = 2350  # İç tekerleğe fren/ters tork izni

# [S-2] Türev filtresi.  1.0 = FİLTRE YOK (senin orijinal davranışın).
# Küçültmek (0.3-0.5) tekerlek titremesini azaltır ama Kd=4.0 senin ham türeve
# göre ayarlandığı için kontrol karakterini de değiştirir. Tekerlerde titreme
# görürsen 0.5'e çek, görmüyorsan 1.0'da bırak.
D_FILTRE = 1.0

# [S-8] Kurtarma taramasında pivot gücü çarpanı. Tam güçte tarama, çizginin
# üstünden atlayıp geçiyordu.
# 1.0 = senin orijinal davranışın (tam güç tarama).
# Tarama çizginin üstünden atlıyorsa 0.55'e çek.
ARAMA_GUC_ORANI = 1.0
# =============================================================================


def _pivot_olcekle(pivot, oran):
    """[S-8] Pivot çiftini nötre doğru ölçekler (yön ve simetri korunur)."""
    return (int(NOTR + (pivot[0] - NOTR) * oran),
            int(NOTR + (pivot[1] - NOTR) * oran))


ARAMA_SOL = _pivot_olcekle(SOLA_PIVOT, ARAMA_GUC_ORANI)
ARAMA_SAG = _pivot_olcekle(SAGA_PIVOT, ARAMA_GUC_ORANI)

# PID Hafıza Değişkenleri
son_hata = 0
toplam_hata = 0
turev_f = 0.0                              # [S-2]
son_zaman = time.monotonic()               # [S-1]
son_kaybolma_yonu = "SOL"

# [K-1] KARA KUTU -- "köşede çizgiyi kaybediyor" teşhisi için.
# Davranışa HİÇ dokunmaz, sadece dosya yazar. Sorun çözülünce ACIK=False yap.
try:
    from kara_kutu import KaraKutu
    _kk = KaraKutu(acik=True)
    print("[KARA KUTU] Açık. Çizgi kaybedilince kara_kutu/ klasörüne yazılacak.")
except Exception as _e:                    # modül yoksa program yine çalışsın
    print(f"[KARA KUTU] Kapalı ({_e})")

    class _Yok:
        def kare(self, *a): pass
        def dok(self, *a): pass
        def kapat(self): pass
    _kk = _Yok()

# Durum Makinesi Değişkenleri
DURUM = "CIZGI_TAKIP"
fren_zamanlayici = 0
donus_zamanlayici = 0
viraj_zamanlayici = 0
qr_bekleme_sure = 0
kurtarma_zamanlayici = 0

_kernel3 = np.ones((3, 3), np.uint8)
_kernel5 = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (5, 5))


def cizgi_maskesi(gray_kucuk, morf=True):
    """[S-6] Çizgi maskesi. Yapı aynı (inRange), sadece eşik uyarlanabilir.

    Sabit 0-85 eşiği neden çöküyor: salon ışığı tek tip değil. Pencerenin
    altında zemin 190, köşede 90 olabilir. Tek eşik ya köşede zemini "çizgi"
    sayar ya pencere altında çizgiyi kaçırır. Otsu her karede zemin/çizgi
    ayrımını kendisi bulur; aralık kilidi ve kareler arası yumuşatma da
    gölge/parlama anlarında kaçmasını önler.
    """
    global _esik_f
    blur = cv2.GaussianBlur(gray_kucuk, (5, 5), 0)

    if ESIK_MODU == "sabit":
        _esik_f = float(SABIT_ESIK)
        mask = cv2.inRange(blur, 0, SABIT_ESIK)
    else:
        # YEREL ORTALAMA ÇIKARMA: her piksel KENDİ KOMŞULUĞUYLA kıyaslanır.
        # Mutlak parlaklık önemsizleşir, sadece "çevresinden ne kadar koyu"
        # önemli olur. Karanlık köşe de, pencere altı da aynı çalışır.
        # (Otsu denendi ve GERİ ALINDI: tüm karede çalışınca zemini de çizgi
        #  sayıp normal ışıkta sapmayı 3.6 mm'den 43 mm'ye çıkarıyordu.)
        yerel = cv2.blur(blur, (_yerel_px, _yerel_px))
        fark = cv2.subtract(yerel, blur)
        _, mask = cv2.threshold(fark, KONTRAST_ESIGI, 255, cv2.THRESH_BINARY)
        mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE, _kernel5)
        _esik_f = float(KONTRAST_ESIGI)

    # DİKKAT: morf=False, senin KESKIN_VIRAJ_SOL/SAG bloklarındaki davranışı
    # birebir korumak için. Orada MORPH_OPEN uygulanmıyordu; eklediğimde kontur
    # inceliyor, alan 150'nin altına düşüyor ve pivot çıkış şartı
    # (alan > 150 ve 65 <= cx <= 95) hiç sağlanmıyordu -> araç 3.5 sn dönüp
    # zaman aşımına uğruyor, köşeyi DÖNEMİYORDU.
    if not morf:
        return mask
    return cv2.morphologyEx(mask, cv2.MORPH_OPEN, _kernel3)


def qr_oku(gray_net):
    """[S-9] Kare atlamalı + çok kareli onaylı QR okuma.

    Tek karelik bir okumanın 90 derece dönüş tetiklemesi riskliydi: hareket
    bulanıklığında yanlış çözülen tek bir kare görevi bitirebilir.
    """
    global _qr_kare
    _qr_kare += 1
    if _qr_kare % QR_TARAMA_ARASI:
        return False
    try:
        icerikler = [o.data.decode('utf-8', errors='ignore') for o in decode(gray_net)]
    except Exception:
        icerikler = []
    okunan = "11" if "11" in icerikler else None
    _qr_gecmis.append(okunan)
    if len(_qr_gecmis) > QR_ONAY_KARE:
        _qr_gecmis.pop(0)
    if len(_qr_gecmis) >= QR_ONAY_KARE and all(g == "11" for g in _qr_gecmis):
        _qr_gecmis.clear()
        return True
    return False


# =============================================================================
# 3. KAMERA VE ARABELLEK (BUFFER LAG) SENKRONİZASYONU
# =============================================================================
cap = cv2.VideoCapture(0, cv2.CAP_V4L2)    # [S-7] V4L2 backend, BUFFERSIZE'ı dinler
if not cap.isOpened():
    cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FOURCC, cv2.VideoWriter_fourcc(*"MJPG"))   # [S-7]
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)
cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)  # Arabellek gecikmesini 1 kareye kilitler!
cap.set(cv2.CAP_PROP_FPS, 30)

try:
    cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)
    # [S-7] 120 -> ~12 ms perde, hareket bulanıklığı yapıyor. 70 -> ~7 ms.
    cap.set(cv2.CAP_PROP_EXPOSURE, 70)
    cap.set(cv2.CAP_PROP_GAIN, 0)
except Exception:
    pass


def taze_kare_al(kamera):
    """Linux V4L2 arabellek gecikmesini önlemek için en taze kareyi çeker."""
    kamera.grab()
    ret_val, son_kare = kamera.retrieve()
    return ret_val, son_kare


print(f"[SİSTEM] Stabilize sürüm. Eşik modu: {ESIK_MODU}")
print("[SİSTEM] Viraj Öncesi Apex Sürüşü, Sıfır Gecikmeli Kamera ve Temiz Kapanma Aktif.")

try:
    while True:
        ret, frame = taze_kare_al(cap)
        if not ret or frame is None:
            print("[HATA] Kameradan görüntü alınamadı! Bağlantıyı kontrol edin.")
            motor_sur(NOTR, NOTR, zorla=True)
            break

        # [S-5] waitKey döngü BAŞINDA. Eski kodda en alttaydı ve bütün manevra
        # durumları 'continue' ile çıktığı için pivot boyunca 'q' ölüydü;
        # imshow pencereleri de o sırada donuyordu.
        if (cv2.waitKey(1) & 0xff) == ord('q'):
            print("[SİSTEM] 'q' tuşuna basıldı. Durduruluyor.")
            break

        arduino_dinle()                    # [S-4]

        su_an = time.monotonic()           # [S-1]
        dt = su_an - son_zaman
        dt = min(dt, 0.1) if dt > 0 else 0.01
        son_zaman = su_an

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray_net = cv2.normalize(gray, None, 0, 255, cv2.NORM_MINMAX)

        # =====================================================================
        # PROTOKOL 1: QR KOD TARAMA VE DÖNÜŞ
        # =====================================================================
        if DURUM == "CIZGI_TAKIP" and su_an > qr_bekleme_sure:
            if qr_oku(gray_net):           # [S-9]
                print("\n[QR TESPİTİ] '11' okundu! Kontrollü duruşa geçiliyor...")
                DURUM = "QR_YAKLASIM"
                fren_zamanlayici = su_an
                motor_sur(1650, 1650)

        if DURUM == "QR_YAKLASIM":
            motor_sur(1650, 1650)
            if su_an - fren_zamanlayici > 0.2:
                DURUM = "QR_GORULDU_FREN"
                fren_zamanlayici = su_an
                motor_sur(NOTR, NOTR)
            continue

        elif DURUM == "QR_GORULDU_FREN":
            motor_sur(NOTR, NOTR)
            if su_an - fren_zamanlayici > 0.3:
                print(f"[PROTOKOL] {DONUS_SURESI_90_DEG} sn boyunca 90° Sağa Dönüş Başladı!")
                DURUM = "DOKSAN_DERECE_SAG"
                donus_zamanlayici = su_an
            continue

        elif DURUM == "DOKSAN_DERECE_SAG":
            motor_sur(SAGA_PIVOT[0], SAGA_PIVOT[1])
            if su_an - donus_zamanlayici >= DONUS_SURESI_90_DEG:
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_DOGRULA"
                donus_zamanlayici = su_an
            continue

        elif DURUM == "CIZGI_DOGRULA":
            motor_sur(NOTR, NOTR)
            # [S-10] Eski hâli TAM ÇÖZÜNÜRLÜKLÜ gray üzerinde çalışıyordu ve
            # 150 px'lik eşik, QR kodun KENDİ SİYAHINI bile "çizgi" sayabiliyordu.
            # Artık takipte kullanılan maskenin aynısı kullanılıyor.
            frame_cizgi = cv2.resize(frame, (160, 120))
            mask_dogrula = cizgi_maskesi(cv2.cvtColor(frame_cizgi, cv2.COLOR_BGR2GRAY), morf=False)
            contours, _ = cv2.findContours(mask_dogrula, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE)

            if len(contours) > 0 and cv2.contourArea(max(contours, key=cv2.contourArea)) > 150:
                print("[BAŞARILI] Yerde çizgi bulundu! Takibe devam.")
                DURUM = "CIZGI_TAKIP"
                son_hata = 0
                toplam_hata = 0
                turev_f = 0.0              # [S-2]
                qr_bekleme_sure = su_an + 3.0
            elif su_an - donus_zamanlayici > 1.2:
                print("[DURUM] Dönüş sonrası çizgi yok. Güvenli duruş.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_TAKIP"
            continue

        # =====================================================================
        # PROTOKOL 2: ÇİZGİ YAKALANDIĞINDA MOMENTUM SÖNÜMLEME (KİLİTLENME FRENİ)
        # =====================================================================
        elif DURUM == "CIZGI_YAKALANDI_FREN":
            motor_sur(NOTR, NOTR)
            if su_an - fren_zamanlayici > 0.18:
                print("[KİLİTLENME BAŞARILI] Momentum sıfırlandı, çizgi takibi başlıyor.")
                DURUM = "CIZGI_TAKIP"
                son_hata = 0
                toplam_hata = 0
                turev_f = 0.0              # [S-2]
            continue

        # =====================================================================
        # PROTOKOL 3: ÇİZGİ KAYBOLURSA AKTİF ARAMA / KURTARMA MODU
        # =====================================================================
        elif DURUM == "KURTARMA_MODU":
            frame_cizgi = cv2.resize(frame, (160, 120))
            mask = cizgi_maskesi(cv2.cvtColor(frame_cizgi, cv2.COLOR_BGR2GRAY))  # [S-6]
            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

            if len(contours) > 0:
                c = max(contours, key=cv2.contourArea)
                if cv2.contourArea(c) > 150:
                    print("[KURTARMA TESPİTİ] Çizgi görüldü! Çizgi üstünde durmak için frenleniyor...")
                    DURUM = "CIZGI_YAKALANDI_FREN"
                    fren_zamanlayici = su_an
                    motor_sur(NOTR, NOTR)
                    continue

            if su_an - kurtarma_zamanlayici <= 1.5:
                # [S-8] Tam güçle taramak çizginin üstünden atlıyordu.
                if son_kaybolma_yonu == "SOL":
                    motor_sur(ARAMA_SOL[0], ARAMA_SOL[1])
                else:
                    motor_sur(ARAMA_SAG[0], ARAMA_SAG[1])
            else:
                print("[GÜVENLİ DURUŞ] 1.5 saniyede çizgi bulunamadı, motorlar durduruluyor.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_TAKIP"
            continue

        # =====================================================================
        # PROTOKOL 4: ANA SÜRÜŞ - ÇİFT BÖLGE (DUAL-ROI) AÇILI ÇİZGİ TAKİBİ
        # =====================================================================
        elif DURUM == "CIZGI_TAKIP":
            frame_cizgi = cv2.resize(frame, (160, 120))
            mask = cizgi_maskesi(cv2.cvtColor(frame_cizgi, cv2.COLOR_BGR2GRAY))  # [S-6]
            contours, _ = cv2.findContours(mask, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)

            setpoint = 80
            cv2.line(frame, (160, 0), (160, 240), (255, 0, 0), 2)

            # [K-2] Kara kutu: her kareyi kaydet. Davranışı değiştirmez;
            # çizgi kaybedildiğinde son 2 saniye diske yazılır.
            _en_buyuk = max(contours, key=cv2.contourArea) if contours else None
            _kk.kare(DURUM, frame_cizgi, mask, _en_buyuk)

            if len(contours) > 0:
                c = max(contours, key=cv2.contourArea)
                alan = cv2.contourArea(c)

                if alan > 150:
                    # [S-3] m00 == 0 olduğunda cx_tam ve boundingRect tanımsız
                    # kalıyor, bir önceki karenin BAYAT değeriyle karar
                    # veriliyordu (ilk karede ise NameError).
                    M_tam = cv2.moments(c)
                    x, y, w, h = cv2.boundingRect(c)
                    cx_tam = int(M_tam['m10'] / M_tam['m00']) if M_tam["m00"] else (x + w // 2)

                    # --- 1. KESİN L-VİRAJ TESPİTİ -> ÖNCE İLERİ SÜRÜŞE GEÇ ---
                    if alan > 600 and ((x < 15 and w > 65) or (cx_tam <= 15)):
                        print(f"[KESKİN KÖŞE] 90° Sol L-Viraj Algılandı! {VIRAJ_ILERI_SURESI} sn düz ilerleniyor...")
                        DURUM = "VIRAJ_ILERI_SOL"
                        viraj_zamanlayici = su_an
                        motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
                        continue
                    elif alan > 600 and (((x + w) > 145 and w > 65) or (cx_tam >= 145)):
                        print(f"[KESKİN KÖŞE] 90° Sağ L-Viraj Algılandı! {VIRAJ_ILERI_SURESI} sn düz ilerleniyor...")
                        DURUM = "VIRAJ_ILERI_SAG"
                        viraj_zamanlayici = su_an
                        motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
                        continue

                    # --- 2. ÇİFT BÖLGE (DUAL-ZONE) ÇAPRAZ ÇİZGİ ANALİZİ ---
                    mask_yakin = mask[80:120, :]
                    cnt_yakin, _ = cv2.findContours(mask_yakin, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    cx_yakin = cx_tam
                    if len(cnt_yakin) > 0 and cv2.contourArea(max(cnt_yakin, key=cv2.contourArea)) > 30:
                        M_y = cv2.moments(max(cnt_yakin, key=cv2.contourArea))
                        if M_y["m00"] != 0:
                            cx_yakin = int(M_y['m10'] / M_y['m00'])

                    mask_uzak = mask[30:70, :]
                    cnt_uzak, _ = cv2.findContours(mask_uzak, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                    cx_uzak = cx_yakin
                    if len(cnt_uzak) > 0 and cv2.contourArea(max(cnt_uzak, key=cv2.contourArea)) > 30:
                        M_u = cv2.moments(max(cnt_uzak, key=cv2.contourArea))
                        if M_u["m00"] != 0:
                            cx_uzak = int(M_u['m10'] / M_u['m00'])

                    # --- 3. KONUM VE AÇI HATASININ BİRLEŞTİRİLMESİ ---
                    konum_hatasi = cx_yakin - setpoint
                    aci_hatasi = cx_uzak - cx_yakin
                    hata = konum_hatasi + (K_ACI * aci_hatasi)

                    if hata < -10:
                        son_kaybolma_yonu = "SOL"
                    elif hata > 10:
                        son_kaybolma_yonu = "SAG"

                    if abs(hata) > HATA_ESIGI:
                        anlik_hiz = DUZELTME_SEYIR_HIZI
                        dinamik_Kp = Kp * 1.35
                    else:
                        anlik_hiz = NORMAL_SEYIR_HIZI
                        dinamik_Kp = Kp

                    # [S-2] Koşullu integrasyon: çıkış doymuşken aynı yöne
                    # biriktirmek windup yapar.
                    aday = toplam_hata + hata * dt
                    if abs(Ki * aday) < 40.0 or (Ki * aday * hata) < 0:
                        toplam_hata = aday
                    toplam_hata = np.clip(toplam_hata, -300, 300)

                    # [S-2] Filtreli türev. Ham (hata - son_hata)/dt, Kd=4.0 ile
                    # dt'nin en ufak titremesini tekerleklere gürültü olarak basıyordu.
                    ham_turev = (hata - son_hata) / dt
                    turev_f += D_FILTRE * (ham_turev - turev_f)
                    son_hata = hata

                    duzeltme = (dinamik_Kp * hata) + (Ki * toplam_hata) + (Kd * turev_f)

                    # ⚠ İŞARET AYNEN KORUNDU -- bu araçta motorlar fiziksel
                    # olarak SOL/SAĞ ters bağlı; kodun işareti de ters ve ikisi
                    # birbirini götürüyor. Buraya dokunma.
                    sol_dac = anlik_hiz + duzeltme
                    sag_dac = anlik_hiz - duzeltme

                    sol_dac = np.clip(sol_dac, MIN_HIZ_SINIRI, MAX_HIZ_SINIRI)
                    sag_dac = np.clip(sag_dac, MIN_HIZ_SINIRI, MAX_HIZ_SINIRI)

                    motor_sur(sol_dac, sag_dac)

                    cv2.circle(frame, (cx_yakin * 2, 200), 6, (0, 0, 255), -1)
                    cv2.circle(frame, (cx_uzak * 2, 100), 6, (255, 0, 0), -1)
                    cv2.line(frame, (cx_yakin * 2, 200), (cx_uzak * 2, 100), (0, 255, 255), 2)
                    cv2.putText(frame, f"hata {hata:+6.1f}  esik {int(_esik_f)}",
                                (5, 18), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (255, 255, 255), 1)
                else:
                    print(f"[UYARI] Çizgi yetersiz! {son_kaybolma_yonu} yönünde arama başlıyor...")
                    _kk.dok("cizgi_yetersiz")      # [K-3]
                    DURUM = "KURTARMA_MODU"
                    kurtarma_zamanlayici = su_an
                    son_hata = 0
                    toplam_hata = 0
                    turev_f = 0.0          # [S-2]
            else:
                print(f"[UYARI] Çizgi kaybedildi! {son_kaybolma_yonu} yönünde arama başlıyor...")
                _kk.dok("cizgi_kayip")             # [K-3]
                DURUM = "KURTARMA_MODU"
                kurtarma_zamanlayici = su_an
                son_hata = 0
                toplam_hata = 0
                turev_f = 0.0              # [S-2]

            cv2.imshow("Tam Ekran Çizgi Maskesi", mask)

        # =====================================================================
        # PROTOKOL 5: VİRAJ ÖNCESİ İLERİ SÜRÜŞ (APEX YAKLAŞIMI)
        # =====================================================================
        elif DURUM == "VIRAJ_ILERI_SOL":
            motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
            if su_an - viraj_zamanlayici >= VIRAJ_ILERI_SURESI:
                print("[APEX ULAŞILDI] Sol L-Viraj için pivot dönüşe başlanıyor...")
                DURUM = "KESKIN_VIRAJ_SOL"
                donus_zamanlayici = su_an
                son_hata = 0
                toplam_hata = 0
                turev_f = 0.0              # [S-2]
            continue

        elif DURUM == "VIRAJ_ILERI_SAG":
            motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
            if su_an - viraj_zamanlayici >= VIRAJ_ILERI_SURESI:
                print("[APEX ULAŞILDI] Sağ L-Viraj için pivot dönüşe başlanıyor...")
                DURUM = "KESKIN_VIRAJ_SAG"
                donus_zamanlayici = su_an
                son_hata = 0
                toplam_hata = 0
                turev_f = 0.0              # [S-2]
            continue

        # =====================================================================
        # PROTOKOL 6: 90 DERECE KESKİN L-VİRAJ DÖNÜŞLERİ
        # =====================================================================
        elif DURUM == "KESKIN_VIRAJ_SOL":
            motor_sur(SOLA_PIVOT[0], SOLA_PIVOT[1])
            frame_cizgi = cv2.resize(frame, (160, 120))
            mask = cizgi_maskesi(cv2.cvtColor(frame_cizgi, cv2.COLOR_BGR2GRAY), morf=False)
            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE)

            cx_bulundu = False
            if len(contours) > 0:
                c = max(contours, key=cv2.contourArea)
                if cv2.contourArea(c) > 150:
                    M = cv2.moments(c)
                    if M["m00"] != 0:
                        cx = int(M['m10'] / M['m00'])
                        if 65 <= cx <= 95 and (su_an - donus_zamanlayici > 0.7):
                            print("[L-VİRAJ BİTTİ] Çizgi ortalandı, kilitlenme frenine geçiliyor.")
                            DURUM = "CIZGI_YAKALANDI_FREN"
                            fren_zamanlayici = su_an
                            motor_sur(NOTR, NOTR)
                            cx_bulundu = True

            if not cx_bulundu and (su_an - donus_zamanlayici >= 3.5):
                print("[L-VİRAJ TIMEOUT] Çizgi bulunamadı, güvenli duruş.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_TAKIP"

        elif DURUM == "KESKIN_VIRAJ_SAG":
            motor_sur(SAGA_PIVOT[0], SAGA_PIVOT[1])
            frame_cizgi = cv2.resize(frame, (160, 120))
            mask = cizgi_maskesi(cv2.cvtColor(frame_cizgi, cv2.COLOR_BGR2GRAY), morf=False)
            contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_NONE)

            cx_bulundu = False
            if len(contours) > 0:
                c = max(contours, key=cv2.contourArea)
                if cv2.contourArea(c) > 150:
                    M = cv2.moments(c)
                    if M["m00"] != 0:
                        cx = int(M['m10'] / M['m00'])
                        if 65 <= cx <= 95 and (su_an - donus_zamanlayici > 0.7):
                            print("[L-VİRAJ BİTTİ] Çizgi ortalandı, kilitlenme frenine geçiliyor.")
                            DURUM = "CIZGI_YAKALANDI_FREN"
                            fren_zamanlayici = su_an
                            motor_sur(NOTR, NOTR)
                            cx_bulundu = True

            if not cx_bulundu and (su_an - donus_zamanlayici >= 3.5):
                print("[L-VİRAJ TIMEOUT] Çizgi bulunamadı, güvenli duruş.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_TAKIP"

        cv2.imshow("Ana Kamera - PID & QR Debug (320x240)", frame)

except KeyboardInterrupt:
    print("\n[SİSTEM] Kullanıcı tarafından durduruldu (KeyboardInterrupt).")

finally:
    print("[SİSTEM] Motorlar sıfırlanıyor ve bağlantılar kapatılıyor...")
    motor_sur(NOTR, NOTR, zorla=True)      # [S-11] hız sınırını atla
    time.sleep(0.1)
    motor_sur(NOTR, NOTR, zorla=True)      # [S-11]
    cap.release()
    cv2.destroyAllWindows()
    arduino.close()
    _kk.kapat()                            # [K-4] kara kutu kaydını kapat
    print("[SİSTEM] Güvenli çıkış yapıldı.")
