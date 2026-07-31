#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RoboVizyon - Cizgi Takip + QR Gorev Protokolu   (Raspberry Pi 5)

Takimin calisan kodu + hedefli duzeltmeler. Yapisi, durum isimleri ve
ayar mantigi AYNEN korundu; sadece asagidaki [FIX] noktalari degisti.
Her degisiklik "# [FIX n]" ile isaretli, diff almak kolay olsun diye.

[FIX 0]  YON bayragi        : Kodda iki zit yon konvansiyonu vardi.
                              "SAGA_PIVOT=(2730,1320)" yuksek=ileri diyordu,
                              "NORMAL_SEYIR_HIZI=1550 / MAX_HIZ_SINIRI=2350
                              (ters tork)" ise dusuk=ileri diyordu. Ikisi ayni
                              anda dogru olamaz -> donusten sonra cizgi kayboluyordu.
                              Artik her sey notre gore OFSET olarak yazili,
                              tek YON bayragi ile isaret cevriliyor.
[FIX 1]  Uyarlanabilir esik : Sabit inRange(0,85) yerine Otsu. Donunce kamera
                              baska isiga bakinca cizgi kayboluyordu.
[FIX 2]  DOKSAN_DERECE_SAG  : Acik cevrim 0.7 sn -> KAPALI CEVRIM. Cizgi
                              ortalaninca biter, sure sadece ust sinir.
[FIX 3]  CIZGI_DOGRULA      : Yerinde durup bakmak yerine YAVAS DONEREK arar.
                              Ayrica tam cozunurluk yerine ayni 160x120 hatti
                              ve alt ROI kullanir (tum kare, QR'in kendi siyahini
                              "cizgi" saniyordu).
[FIX 4]  cx_tam / bbox init : M_tam["m00"]==0 oldugunda tanimsiz/bayat degerle
                              devam ediliyordu.
[FIX 5]  waitKey            : Dongunun basina alindi -> pivot/QR durumlarinda da
                              'q' calisir (continue'lar yuzunden olu kalmisti).
[FIX 6]  time.monotonic     : Pi 5'te RTC yok; NTP senkronu time.time()'i geri
                              sicratip dt'yi negatife dusurebiliyor -> turev patlar.
[FIX 7]  Seri akis kontrolu : Yazma hiz siniri + Arduino heartbeat'inin okunup
                              bosaltilmasi (RX birikirse bayat komut uygulanir).

ONEMLI: arduino_dac_surucu.ino'yu da yukle. Eski firmware'deki Serial.parseInt()
1000 ms timeout ile loop'u kilitliyor; yarim paket gelirse watchdog o sure
boyunca calisamiyor ve arac son komutla donmeye devam ediyor (asiri donus).
"""

import time

import cv2
import numpy as np
import serial
from pyzbar.pyzbar import decode

# =============================================================================
# 1. SERİ PORT BAĞLANTISI
# =============================================================================
try:
    arduino = serial.Serial('/dev/ttyUSB0', 115200, timeout=0.05, write_timeout=0.05)
    print("[SİSTEM] Arduino bağlantısı başarılı. Senkronize takip başlıyor!")
    time.sleep(2)
    arduino.reset_input_buffer()
    arduino.reset_output_buffer()
except Exception as e:
    print(f"[HATA] Seri port açılamadı: {e}")
    exit()

_son_gonderim = 0.0
_son_paket = None


def motor_sur(sol_dac, sag_dac, zorla=False):
    """Arduino'ya <Sol,Sag> DAC paketini iletir."""
    # [FIX 7] Aynı paketi kamera hızında spam etmek Arduino RX buffer'ını
    # doldurup bayat komut uygulanmasına yol açıyordu. 50 Hz yeterli
    # (firmware watchdog'u 250 ms).
    global _son_gonderim, _son_paket
    paket = (int(np.clip(sol_dac, 0, 4095)), int(np.clip(sag_dac, 0, 4095)))
    simdi = time.monotonic()
    if not zorla and paket == _son_paket and (simdi - _son_gonderim) < 0.02:
        return
    _son_paket, _son_gonderim = paket, simdi
    try:
        arduino.write(f"<{paket[0]},{paket[1]}>\n".encode('utf-8'))
    except serial.SerialException as e:
        print(f"[HATA] Seri yazma: {e}")


def arduino_dinle():
    """[FIX 7] Firmware'in 'OK,sol,sag' heartbeat'ini yutar, RX birikmesin."""
    try:
        if arduino.in_waiting:
            arduino.read(arduino.in_waiting)
    except serial.SerialException:
        pass


# =============================================================================
# 2. HIZ, TORK VE KİNEMATİK AYARLAR (BURADAN AYARLAYACAKSIN!)
# =============================================================================
NOTR = 2048  # Tam duruş noktası (2.50V)

# --- [FIX 0] YÖN KONVANSİYONU -- ÖNCE BUNU DOĞRULA -------------------------
# Tekerlekler HAVADAYKEN:  motor_sur(NOTR + 500, NOTR + 500)
#   İleri döndü -> YON = +1   (varsayılan)
#   Geri  döndü -> YON = -1
# Aşağıdaki her şey nötre göre OFSET; YON tek başına tüm yönleri çevirir.
YON = +1

# Ofsetler (senin çalışan değerlerinin nötre uzaklığı, korundu)
OFS_NORMAL   = 500   # eski 1550/2548
OFS_DUZELTME = 428   # eski 1620/2476
OFS_QR_YAVAS = 400   # eski 1650/2448
OFS_PIVOT    = 700   # eski 1320/2730 -> simetrik hale getirildi
OFS_MAX_ILERI = 970  # PID'in çıkabileceği en yüksek ileri güç
OFS_MAX_TERS  = 300  # iç tekerleğe izin verilen ters tork (fren etkisi)


def ileri(ofset):
    """Nötre göre ofseti gerçek DAC değerine çevirir (ileri yön)."""
    return int(np.clip(NOTR + YON * ofset, 0, 4095))


def geri(ofset):
    return int(np.clip(NOTR - YON * ofset, 0, 4095))


NORMAL_SEYIR_HIZI   = ileri(OFS_NORMAL)     # Çizgi ortadayken hızlı seyir
DUZELTME_SEYIR_HIZI = ileri(OFS_DUZELTME)   # Sapınca tork kaybetmeden ortala
QR_YAKLASMA_HIZI    = ileri(OFS_QR_YAVAS)
HATA_ESIGI = 12  # Bu piksel sapmasının üstü düzeltme hızına geçer

# Kamera burnun önünde olduğu için tekerlekler köşeye gelene kadar düz gitme süresi:
VIRAJ_ILERI_SURESI = 0.6  # 0.4 - 1.0 sn arası test ederek en iyi konumu bul!

# --- PİVOT DÖNÜŞ GÜÇLERİ ---
# [FIX 0] Artık YON'dan türetiliyor; ayrıca simetrik (eskisi -728/+672 idi,
# asimetri dönerken aracı yana kaydırıyordu).
SOLA_PIVOT = (geri(OFS_PIVOT), ileri(OFS_PIVOT))   # sol geri, sağ ileri
SAGA_PIVOT = (ileri(OFS_PIVOT), geri(OFS_PIVOT))   # sol ileri, sağ geri

# Arama sırasında kullanılan yavaş pivot (çizgiyi atlamamak için)
ARAMA_SOL = (geri(int(OFS_PIVOT * 0.55)), ileri(int(OFS_PIVOT * 0.55)))
ARAMA_SAG = (ileri(int(OFS_PIVOT * 0.55)), geri(int(OFS_PIVOT * 0.55)))

DONUS_SURESI_90_DEG = 1.5   # [FIX 2] artık ÜST SINIR; çizgi ortalanınca erken biter
QR_PIVOT_MIN_SURE   = 0.35  # bu süreden önce "çizgi bulundu" sayma (eski çizgi hâlâ kadrajda)

# Standart PID Katsayıları
Kp = 5.8
Ki = 0.01
Kd = 4.0
K_ACI = 0.85  # Çapraz çizgi açı telafi katsayısı (Stanley Look-Ahead)

# [FIX 0] Eski MIN_HIZ_SINIRI / MAX_HIZ_SINIRI kaldırıldı. Kırpma artık ofset
# uzayında (-OFS_MAX_TERS .. +OFS_MAX_ILERI) yapılıyor; böylece YON çevrilince
# sınırlar da otomatik doğru tarafa geçiyor. Ham DAC sınırı yazmak, yönü
# çevirdiğinde sessizce yanlış tarafı kırpıyordu.
# =============================================================================

# PID Hafıza Değişkenleri
son_hata = 0
toplam_hata = 0
son_zaman = time.monotonic()          # [FIX 6]
son_kaybolma_yonu = "SOL"

# Durum Makinesi Değişkenleri
DURUM = "CIZGI_TAKIP"
fren_zamanlayici = 0
donus_zamanlayici = 0
viraj_zamanlayici = 0
qr_bekleme_sure = 0
kurtarma_zamanlayici = 0
dogrula_yonu = "SAG"                  # [FIX 3] arama hangi yöne dönerek yapılacak

# [FIX 1] Uyarlanabilir eşik hafızası
esik_f = 85.0
esik_ilk = True                       # [FIX 1b] ilk karede yumuşatmadan otur
ESIK_TABAN, ESIK_TAVAN = 35, 135
KOYU_ORAN_MIN, KOYU_ORAN_MAX = 0.01, 0.55


# =============================================================================
# 3. GÖRÜNTÜ İŞLEME YARDIMCILARI
# =============================================================================
def esik_guncelle(gray_img):
    """[FIX 1] Otsu ile eşik bul, mantıklı aralığa kilitle, kareler arası yumuşat.

    Sabit 0-85 eşiği, araç dönüp kamera farklı aydınlatmaya baktığında
    çizgiyi tamamen kaybediyordu. Otsu her karede zemin/çizgi ayrımını
    kendisi bulur; aralık kilidi de gölge/parlama anlarında kaçmasını önler.
    """
    global esik_f, esik_ilk
    o, _ = cv2.threshold(gray_img, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    o = float(np.clip(o, ESIK_TABAN, ESIK_TAVAN))
    if esik_ilk:
        # [FIX 1b] Sabit 85'ten yumuşayarak gelmek, karanlık bir sahnede ilk
        # birkaç karede TÜM görüntüyü "çizgi" yapıyordu (x=0, w=160 -> sahte
        # L-viraj tetikleniyordu). İlk karede doğrudan Otsu'ya otur.
        esik_f, esik_ilk = o, False
    else:
        esik_f += 0.25 * (o - esik_f)
    return int(esik_f)


_kernel = np.ones((3, 3), np.uint8)


def cizgi_maskesi(frame_bgr):
    """320x240 kareyi 160x120'ye küçültüp uyarlanabilir maske üretir."""
    kucuk = cv2.resize(frame_bgr, (160, 120), interpolation=cv2.INTER_AREA)
    gri = cv2.GaussianBlur(cv2.cvtColor(kucuk, cv2.COLOR_BGR2GRAY), (5, 5), 0)
    esik = esik_guncelle(gri)
    maske = cv2.inRange(gri, 0, esik)
    maske = cv2.morphologyEx(maske, cv2.MORPH_OPEN, _kernel)

    # [FIX 1c] Makullük kontrolü: kare tamamen koyuysa (gölge, kamera kapandı,
    # pozlama patladı) veya bomboşsa maskeye GÜVENME. Bu koruma olmadan,
    # tüm kareyi kaplayan bir maske x=0/w=160 üretip sahte L-viraj tetikliyor.
    oran = float(np.count_nonzero(maske)) / maske.size
    if not (KOYU_ORAN_MIN <= oran <= KOYU_ORAN_MAX):
        return np.zeros_like(maske)
    return maske


def alt_roi_cx(maske, min_alan=80):
    """[FIX 3] Alt şeritteki (araca en yakın) çizginin cx'i. Yoksa None.

    Tüm kare yerine alt ROI kullanmak şart: dönüş sırasında geldiğimiz eski
    çizgi hâlâ kadrajın üstünde duruyor ve tüm-kare centroid'ini kaydırıyor.
    """
    roi = maske[80:120, :]
    cnt, _ = cv2.findContours(roi, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not cnt:
        return None
    c = max(cnt, key=cv2.contourArea)
    if cv2.contourArea(c) < min_alan:
        return None
    M = cv2.moments(c)
    if M["m00"] == 0:
        return None
    return int(M['m10'] / M['m00'])


# =============================================================================
# 4. KAMERA VE ARABELLEK (BUFFER LAG) SENKRONİZASYONU
# =============================================================================
cap = cv2.VideoCapture(0)
cap.set(cv2.CAP_PROP_FRAME_WIDTH, 320)
cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 240)
cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)  # Arabellek gecikmesini 1 kareye kilitler!
cap.set(cv2.CAP_PROP_FPS, 30)

try:
    cap.set(cv2.CAP_PROP_AUTO_EXPOSURE, 0.25)
    cap.set(cv2.CAP_PROP_EXPOSURE, 120)
    cap.set(cv2.CAP_PROP_GAIN, 0)
except Exception:
    pass


def taze_kare_al(kamera):
    """Linux V4L2 arabellek gecikmesini önlemek için en taze kareyi çeker."""
    kamera.grab()
    ret_val, son_kare = kamera.retrieve()
    return ret_val, son_kare


print(f"[SİSTEM] YON={YON:+d} | seyir={NORMAL_SEYIR_HIZI} | "
      f"pivot sag={SAGA_PIVOT} sol={SOLA_PIVOT}")
print("[SİSTEM] Kapalı çevrim QR dönüşü, uyarlanabilir eşik ve arama modu aktif.")

try:
    while True:
        ret, frame = taze_kare_al(cap)
        if not ret or frame is None:
            print("[HATA] Kameradan görüntü alınamadı! Bağlantıyı kontrol edin.")
            break

        # [FIX 5] waitKey döngünün BAŞINDA. Eski kodda en alttaydı ve bütün
        # manevra durumları 'continue' ile çıktığı için pivot boyunca 'q' ölüydü.
        if (cv2.waitKey(1) & 0xff) == ord('q'):
            print("[SİSTEM] 'q' tuşuna basıldı. Durduruluyor.")
            break

        arduino_dinle()                                   # [FIX 7]

        su_an = time.monotonic()                          # [FIX 6]
        dt = su_an - son_zaman
        dt = min(dt, 0.1) if dt > 0 else 0.01
        son_zaman = su_an

        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        gray_net = cv2.normalize(gray, None, 0, 255, cv2.NORM_MINMAX)

        # =====================================================================
        # PROTOKOL 1: QR KOD TARAMA VE DÖNÜŞ
        # =====================================================================
        if DURUM == "CIZGI_TAKIP" and su_an > qr_bekleme_sure:
            for obj in decode(gray_net):
                if obj.data.decode('utf-8') == "11":
                    print("\n[QR TESPİTİ] '11' okundu! Kontrollü duruşa geçiliyor...")
                    DURUM = "QR_YAKLASIM"
                    fren_zamanlayici = su_an
                    motor_sur(QR_YAKLASMA_HIZI, QR_YAKLASMA_HIZI)
                    break

        if DURUM == "QR_YAKLASIM":
            motor_sur(QR_YAKLASMA_HIZI, QR_YAKLASMA_HIZI)
            if su_an - fren_zamanlayici > 0.2:
                DURUM = "QR_GORULDU_FREN"
                fren_zamanlayici = su_an
                motor_sur(NOTR, NOTR)
            continue

        elif DURUM == "QR_GORULDU_FREN":
            motor_sur(NOTR, NOTR)
            if su_an - fren_zamanlayici > 0.3:
                print("[PROTOKOL] 90° Sağa Dönüş başladı (çizgi ortalanınca bitecek)")
                DURUM = "DOKSAN_DERECE_SAG"
                donus_zamanlayici = su_an
            continue

        elif DURUM == "DOKSAN_DERECE_SAG":
            # [FIX 2] KAPALI ÇEVRİM. Eskiden tam 0.7 sn körlemesine dönüp
            # duruyordu; akü voltajı düştükçe ya eksik ya fazla dönüyor,
            # sonra CIZGI_DOGRULA yerinde durup boş zemine bakıyordu.
            # Şimdi L-viraj mantığının aynısı: çizgi merkeze oturunca bitir.
            motor_sur(SAGA_PIVOT[0], SAGA_PIVOT[1])
            mask = cizgi_maskesi(frame)
            cx_alt = alt_roi_cx(mask)
            gecen = su_an - donus_zamanlayici

            if cx_alt is not None and 65 <= cx_alt <= 95 and gecen > QR_PIVOT_MIN_SURE:
                print(f"[PROTOKOL] Çizgi ortalandı ({gecen:.2f} sn) -> takibe dönülüyor")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_YAKALANDI_FREN"
                fren_zamanlayici = su_an
                qr_bekleme_sure = su_an + 3.0
            elif gecen >= DONUS_SURESI_90_DEG:
                print("[PROTOKOL] Süre doldu, çizgi ortalanmadı -> aranıyor")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_DOGRULA"
                dogrula_yonu = "SAG"
                donus_zamanlayici = su_an
            continue

        elif DURUM == "CIZGI_DOGRULA":
            # [FIX 3] Eskiden motor_sur(NOTR,NOTR) ile yerinde durup TAM
            # ÇÖZÜNÜRLÜKLÜ tüm kareye bakıyordu. İki sorun vardı:
            #   1) Duruyorsa çizgi kadraja hiç girmiyor -> asla bulamaz
            #   2) Tüm kare + 150px eşiği, QR kodun kendi siyahını "çizgi" sayıyor
            # Şimdi yavaşça dönerek arıyor ve alt ROI'ye bakıyor.
            mask = cizgi_maskesi(frame)
            cx_alt = alt_roi_cx(mask)

            if cx_alt is not None and 55 <= cx_alt <= 105:
                print("[BAŞARILI] Yerde çizgi bulundu! Takibe devam.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_YAKALANDI_FREN"
                fren_zamanlayici = su_an
                qr_bekleme_sure = su_an + 3.0
            elif su_an - donus_zamanlayici <= 2.0:
                p = ARAMA_SAG if dogrula_yonu == "SAG" else ARAMA_SOL
                motor_sur(p[0], p[1])
            else:
                print("[DURUM] Dönüş sonrası çizgi yok. Güvenli duruş.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_TAKIP"
                son_hata = 0
                toplam_hata = 0
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
            continue

        # =====================================================================
        # PROTOKOL 3: ÇİZGİ KAYBOLURSA AKTİF ARAMA / KURTARMA MODU
        # =====================================================================
        elif DURUM == "KURTARMA_MODU":
            mask = cizgi_maskesi(frame)                    # [FIX 1]
            cnt, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)

            if cnt and cv2.contourArea(max(cnt, key=cv2.contourArea)) > 150:
                print("[KURTARMA TESPİTİ] Çizgi görüldü! Çizgi üstünde durmak için frenleniyor...")
                DURUM = "CIZGI_YAKALANDI_FREN"
                fren_zamanlayici = su_an
                motor_sur(NOTR, NOTR)
                continue

            if su_an - kurtarma_zamanlayici <= 1.5:
                p = ARAMA_SOL if son_kaybolma_yonu == "SOL" else ARAMA_SAG
                motor_sur(p[0], p[1])
            else:
                print("[GÜVENLİ DURUŞ] 1.5 saniyede çizgi bulunamadı, motorlar durduruluyor.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_TAKIP"
            continue

        # =====================================================================
        # PROTOKOL 4: ANA SÜRÜŞ - ÇİFT BÖLGE (DUAL-ROI) AÇILI ÇİZGİ TAKİBİ
        # =====================================================================
        elif DURUM == "CIZGI_TAKIP":
            mask = cizgi_maskesi(frame)                    # [FIX 1]
            contours, _ = cv2.findContours(mask, cv2.RETR_LIST, cv2.CHAIN_APPROX_SIMPLE)

            setpoint = 80
            cv2.line(frame, (160, 0), (160, 240), (255, 0, 0), 2)

            if len(contours) > 0:
                c = max(contours, key=cv2.contourArea)
                alan = cv2.contourArea(c)

                if alan > 150:
                    # [FIX 4] m00==0 durumunda cx_tam/bbox tanımsız kalıyor ve
                    # bir önceki karenin bayat değeriyle karar veriliyordu.
                    M_tam = cv2.moments(c)
                    x, y, w, h = cv2.boundingRect(c)
                    cx_tam = int(M_tam['m10'] / M_tam['m00']) if M_tam["m00"] else (x + w // 2)

                    # --- 1. KESİN L-VİRAJ TESPİTİ -> ÖNCE İLERİ SÜRÜŞE GEÇ ---
                    if alan > 600 and ((x < 15 and w > 65) or (cx_tam <= 15)):
                        print(f"[KESKİN KÖŞE] 90° Sol L-Viraj! {VIRAJ_ILERI_SURESI} sn düz ilerleniyor...")
                        DURUM = "VIRAJ_ILERI_SOL"
                        viraj_zamanlayici = su_an
                        motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
                        continue
                    elif alan > 600 and (((x + w) > 145 and w > 65) or (cx_tam >= 145)):
                        print(f"[KESKİN KÖŞE] 90° Sağ L-Viraj! {VIRAJ_ILERI_SURESI} sn düz ilerleniyor...")
                        DURUM = "VIRAJ_ILERI_SAG"
                        viraj_zamanlayici = su_an
                        motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
                        continue

                    # --- 2. ÇİFT BÖLGE (DUAL-ZONE) ÇAPRAZ ÇİZGİ ANALİZİ ---
                    cx_yakin = alt_roi_cx(mask, min_alan=30)
                    if cx_yakin is None:
                        cx_yakin = cx_tam

                    cx_uzak = cx_yakin
                    mask_uzak = mask[30:70, :]
                    cnt_uzak, _ = cv2.findContours(mask_uzak, cv2.RETR_EXTERNAL,
                                                   cv2.CHAIN_APPROX_SIMPLE)
                    if cnt_uzak:
                        cu = max(cnt_uzak, key=cv2.contourArea)
                        if cv2.contourArea(cu) > 30:
                            M_u = cv2.moments(cu)
                            if M_u["m00"]:
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
                        anlik_ofset = OFS_DUZELTME
                        dinamik_Kp = Kp * 1.35
                    else:
                        anlik_ofset = OFS_NORMAL
                        dinamik_Kp = Kp

                    toplam_hata += hata * dt
                    toplam_hata = np.clip(toplam_hata, -300, 300)
                    turev = (hata - son_hata) / dt
                    son_hata = hata

                    duzeltme = (dinamik_Kp * hata) + (Ki * toplam_hata) + (Kd * turev)

                    # [FIX 0] Düzeltme ofset uzayında uygulanıp sonra DAC'a
                    # çevriliyor -> YON=-1 seçilirse yön otomatik dönüyor.
                    ofs_sol = np.clip(anlik_ofset + duzeltme, -OFS_MAX_TERS, OFS_MAX_ILERI)
                    ofs_sag = np.clip(anlik_ofset - duzeltme, -OFS_MAX_TERS, OFS_MAX_ILERI)
                    motor_sur(ileri(ofs_sol), ileri(ofs_sag))

                    cv2.circle(frame, (cx_yakin * 2, 200), 6, (0, 0, 255), -1)
                    cv2.circle(frame, (cx_uzak * 2, 100), 6, (255, 0, 0), -1)
                    cv2.line(frame, (cx_yakin * 2, 200), (cx_uzak * 2, 100), (0, 255, 255), 2)
                else:
                    print(f"[UYARI] Çizgi yetersiz! {son_kaybolma_yonu} yönünde arama başlıyor...")
                    DURUM = "KURTARMA_MODU"
                    kurtarma_zamanlayici = su_an
                    son_hata = 0
                    toplam_hata = 0
            else:
                print(f"[UYARI] Çizgi kaybedildi! {son_kaybolma_yonu} yönünde arama başlıyor...")
                DURUM = "KURTARMA_MODU"
                kurtarma_zamanlayici = su_an
                son_hata = 0
                toplam_hata = 0

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
            continue

        elif DURUM == "VIRAJ_ILERI_SAG":
            motor_sur(DUZELTME_SEYIR_HIZI, DUZELTME_SEYIR_HIZI)
            if su_an - viraj_zamanlayici >= VIRAJ_ILERI_SURESI:
                print("[APEX ULAŞILDI] Sağ L-Viraj için pivot dönüşe başlanıyor...")
                DURUM = "KESKIN_VIRAJ_SAG"
                donus_zamanlayici = su_an
                son_hata = 0
                toplam_hata = 0
            continue

        # =====================================================================
        # PROTOKOL 6: 90 DERECE KESKİN L-VİRAJ DÖNÜŞLERİ
        # =====================================================================
        elif DURUM in ("KESKIN_VIRAJ_SOL", "KESKIN_VIRAJ_SAG"):
            saga = (DURUM == "KESKIN_VIRAJ_SAG")
            p = SAGA_PIVOT if saga else SOLA_PIVOT
            motor_sur(p[0], p[1])

            mask = cizgi_maskesi(frame)                    # [FIX 1]
            cx = alt_roi_cx(mask, min_alan=80)             # [FIX 3] alt ROI
            gecen = su_an - donus_zamanlayici

            if cx is not None and 65 <= cx <= 95 and gecen > 0.7:
                print("[L-VİRAJ BİTTİ] Çizgi ortalandı, kilitlenme frenine geçiliyor.")
                DURUM = "CIZGI_YAKALANDI_FREN"
                fren_zamanlayici = su_an
                motor_sur(NOTR, NOTR)
            elif gecen >= 3.5:
                print("[L-VİRAJ TIMEOUT] Çizgi bulunamadı, aranıyor.")
                motor_sur(NOTR, NOTR)
                DURUM = "CIZGI_DOGRULA"
                dogrula_yonu = "SAG" if saga else "SOL"
                donus_zamanlayici = su_an
            continue

        cv2.imshow("Ana Kamera - PID & QR Debug (320x240)", frame)

except KeyboardInterrupt:
    print("\n[SİSTEM] Kullanıcı tarafından durduruldu (KeyboardInterrupt).")

finally:
    print("[SİSTEM] Motorlar sıfırlanıyor ve bağlantılar kapatılıyor...")
    motor_sur(NOTR, NOTR, zorla=True)
    time.sleep(0.1)
    motor_sur(NOTR, NOTR, zorla=True)
    cap.release()
    cv2.destroyAllWindows()
    arduino.close()
    print("[SİSTEM] Güvenli çıkış yapıldı.")
