#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JK BMS -> web arayuzu koprusu.  Sadece standart kutuphane, pip gerekmez.

    python3 sunucu.py --sahte              # BATARYA YOKKEN arayuzu gelistir
    python3 sunucu.py --seri /dev/ttyUSB0  # RS485/TTL soketinden (robotta bunu kullan)
    python3 sunucu.py --seri COM7
    python3 sunucu.py --ble C8:47:8C:XX:XX:XX
    python3 sunucu.py --sahte --port 8080

Ucler:
    GET /              demo panel (kendi arayuzun hazir olana kadar)
    GET /api/durum     anlik JSON
    GET /api/akis      Server-Sent Events -- saniyede bir kendiliginden gelir
    GET /api/hucreler  hucre gerilimleri + direncleri (buyuk, ayri tutuldu)

Kendi web arayuzune baglamak (CORS acik, farkli porttan cagirabilirsin):

    // 1) Basit: her saniye sor
    setInterval(async () => {
      const d = await (await fetch("http://localhost:8770/api/durum")).json();
      document.querySelector("#soc").textContent = d.veri.soc_yuzde + "%";
    }, 1000);

    // 2) Daha iyi: sunucu kendisi gonderir (SSE), tek baglanti
    new EventSource("http://localhost:8770/api/akis").onmessage = (e) => {
      const d = JSON.parse(e.data);
      if (!d.bagli) return;                 // veri bayat, gosterme
      document.querySelector("#soc").textContent = d.veri.soc_yuzde + "%";
    };
"""

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jk_bms

OKUYUCU = None


SAYFA = """<!doctype html>
<html lang="tr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Batarya Paneli</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
     background:#0f1115;color:#e8eaed;padding:24px}
h1{font-size:20px;font-weight:600;margin-bottom:2px}
.alt{color:#9aa0a6;font-size:13px;margin-bottom:20px}
.rozet{display:inline-block;padding:3px 12px;border-radius:20px;font-size:12px;
       font-weight:600;letter-spacing:.4px;vertical-align:middle;margin-left:8px}
.SARJ{background:#0d4d2b;color:#6ee7a0}
.DESARJ{background:#4d2a0d;color:#f0a868}
.BEKLEME{background:#26292f;color:#9aa0a6}
.KOPUK{background:#4d0d16;color:#ff8a9b}
.izgara{display:grid;grid-template-columns:repeat(auto-fit,minmax(158px,1fr));
        gap:12px;margin-bottom:22px}
.kart{background:#171a20;border:1px solid #262a32;border-radius:10px;padding:14px 16px}
.kart .et{color:#9aa0a6;font-size:11px;text-transform:uppercase;letter-spacing:.6px}
.kart .dg{font-size:26px;font-weight:600;margin-top:5px;font-variant-numeric:tabular-nums}
.kart .bt{font-size:14px;color:#9aa0a6;font-weight:400}
.soc-dis{height:26px;background:#22262d;border-radius:6px;overflow:hidden;margin-top:8px}
.soc-ic{height:100%;background:linear-gradient(90deg,#2e7d5b,#4ade80);
        transition:width .6s ease}
.bolum{font-size:13px;color:#9aa0a6;text-transform:uppercase;letter-spacing:.6px;
       margin:0 0 10px}
.hucreler{display:grid;grid-template-columns:repeat(auto-fit,minmax(104px,1fr));gap:8px}
.h{background:#171a20;border:1px solid #262a32;border-radius:7px;padding:8px 10px;
   font-variant-numeric:tabular-nums}
.h b{display:block;font-size:16px;font-weight:600}
.h span{font-size:10px;color:#9aa0a6}
.h.max{border-color:#3f7d4f}.h.min{border-color:#7d5a3f}
.uyari{background:#3a1218;border:1px solid #6b2029;color:#ff9aa8;padding:10px 14px;
       border-radius:8px;margin-bottom:16px;font-size:13px}
footer{margin-top:24px;color:#5f6469;font-size:12px}
code{background:#171a20;padding:2px 6px;border-radius:4px;color:#9aa0a6}
</style></head><body>
<h1>Batarya Paneli <span id="durum" class="rozet BEKLEME">-</span></h1>
<div class="alt" id="cihaz">bagleniyor...</div>
<div id="uyarilar"></div>
<div class="izgara">
  <div class="kart"><div class="et">Sarj durumu</div>
    <div class="dg"><span id="soc">-</span><span class="bt">%</span></div>
    <div class="soc-dis"><div class="soc-ic" id="socbar" style="width:0"></div></div></div>
  <div class="kart"><div class="et">Paket gerilimi</div>
    <div class="dg"><span id="v">-</span><span class="bt"> V</span></div></div>
  <div class="kart"><div class="et">Akim</div>
    <div class="dg"><span id="a">-</span><span class="bt"> A</span></div></div>
  <div class="kart"><div class="et">Guc</div>
    <div class="dg"><span id="w">-</span><span class="bt"> W</span></div></div>
  <div class="kart"><div class="et">Kalan kapasite</div>
    <div class="dg"><span id="ah">-</span><span class="bt"> Ah</span></div></div>
  <div class="kart"><div class="et">Tahmini sure</div>
    <div class="dg"><span id="sure">-</span><span class="bt"> sa</span></div></div>
  <div class="kart"><div class="et">Sicaklik</div>
    <div class="dg"><span id="t">-</span><span class="bt"> &deg;C</span></div></div>
  <div class="kart"><div class="et">Hucre farki</div>
    <div class="dg"><span id="delta">-</span><span class="bt"> mV</span></div></div>
  <div class="kart"><div class="et">Saglik / dongu</div>
    <div class="dg"><span id="soh">-</span><span class="bt">% / <span id="dongu">-</span></span></div></div>
</div>
<p class="bolum">Hucreler</p>
<div class="hucreler" id="hucreler"></div>
<footer>Veri: <code>/api/durum</code> &middot; canli akis: <code>/api/akis</code>
 &middot; son guncelleme <span id="zaman">-</span></footer>
<script>
const $ = (s) => document.querySelector(s);
function ciz(d) {
  const r = $("#durum");
  if (!d.bagli) {
    r.textContent = "BAGLANTI YOK"; r.className = "rozet KOPUK";
    $("#cihaz").textContent = d.hata ? ("hata: " + d.hata) : "veri bekleniyor...";
    return;
  }
  const v = d.veri;
  r.textContent = v.durum; r.className = "rozet " + v.durum;
  $("#cihaz").textContent = (d.cihaz ? d.cihaz.model + "  |  yazilim " +
      d.cihaz.yazilim_surumu + "  |  " : "") + v.hucre_sayisi + "S  |  calisma " +
      v.calisma_suresi;
  $("#soc").textContent = v.soc_yuzde;
  $("#socbar").style.width = v.soc_yuzde + "%";
  $("#v").textContent = v.toplam_gerilim_v.toFixed(2);
  $("#a").textContent = (v.akim_a > 0 ? "+" : "") + v.akim_a.toFixed(1);
  $("#w").textContent = Math.round(v.guc_w);
  $("#ah").textContent = v.kalan_kapasite_ah.toFixed(1);
  $("#sure").textContent = v.kalan_sure_sa === null ? "-" : v.kalan_sure_sa.toFixed(1);
  $("#t").textContent = v.sicaklik_1_c.toFixed(1);
  $("#delta").textContent = Math.round(v.delta_hucre_v * 1000);
  $("#soh").textContent = v.soh_yuzde;
  $("#dongu").textContent = v.dongu_sayisi;
  $("#uyarilar").innerHTML = (v.hatalar || []).length
      ? '<div class="uyari"><b>BMS uyarisi:</b> ' + v.hatalar.join(" &middot; ") + "</div>" : "";
  $("#hucreler").innerHTML = v.hucre_gerilimleri
      .map((x, i) => [x, i]).filter(([x]) => x > 0)
      .map(([x, i]) => {
        const c = i + 1 === v.max_hucre_no ? " max" : i + 1 === v.min_hucre_no ? " min" : "";
        return '<div class="h' + c + '"><span>hucre ' + (i + 1) + "</span><b>" +
               x.toFixed(3) + " V</b></div>";
      }).join("");
  $("#zaman").textContent = new Date().toLocaleTimeString("tr-TR");
}
const akis = new EventSource("/api/akis");
akis.onmessage = (e) => ciz(JSON.parse(e.data));
akis.onerror = () => { $("#durum").textContent = "SUNUCU YOK";
                       $("#durum").className = "rozet KOPUK"; };
</script></body></html>
"""


class Isleyici(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass                                   # erisim kaydini sustur

    def _basliklar(self, tip, uzunluk=None, akis=False):
        self.send_response(200)
        self.send_header("Content-Type", tip)
        # Kendi web arayuzun baska bir porttan/dosyadan cagirabilsin diye:
        self.send_header("Access-Control-Allow-Origin", "*")
        if akis:
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
        elif uzunluk is not None:
            self.send_header("Content-Length", str(uzunluk))
        self.end_headers()

    def _json(self, nesne):
        govde = json.dumps(nesne, ensure_ascii=False).encode("utf-8")
        self._basliklar("application/json; charset=utf-8", len(govde))
        self.wfile.write(govde)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.end_headers()

    def do_GET(self):
        yol = self.path.split("?")[0].rstrip("/") or "/"

        if yol == "/":
            govde = SAYFA.encode("utf-8")
            self._basliklar("text/html; charset=utf-8", len(govde))
            self.wfile.write(govde)

        elif yol == "/api/durum":
            self._json(OKUYUCU.durum())

        elif yol == "/api/hucreler":
            # Hucre dizileri /api/durum'dan cikarilmisti; tam liste burada.
            with OKUYUCU._kilit:
                d = dict(OKUYUCU._son) if OKUYUCU._son else None
            self._json({"hucre_gerilimleri": d["hucre_gerilimleri"] if d else [],
                        "hucre_dirençleri": d.get("hucre_dirençleri", []) if d else []})

        elif yol == "/api/akis":
            self._basliklar("text/event-stream; charset=utf-8", akis=True)
            try:
                while True:
                    veri = json.dumps(OKUYUCU.durum(), ensure_ascii=False)
                    self.wfile.write(f"data: {veri}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(1.0)
            except (BrokenPipeError, ConnectionResetError):
                pass                            # tarayici sekmesi kapandi

        else:
            self.send_error(404, "yok")


def main():
    global OKUYUCU
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--sahte", action="store_true",
                   help="batarya YOKKEN gercek cerceveleri oynatir")
    g.add_argument("--seri", metavar="PORT", help="RS485/TTL soketi (robotta bunu kullan)")
    g.add_argument("--ble", metavar="ADRES", help="BLE MAC adresi (bleak gerekir)")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--surum", default="oto", choices=["oto", "24S", "32S"])
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--adres", default="0.0.0.0",
                    help="0.0.0.0 = agdaki diger cihazlar da gorebilir")
    args = ap.parse_args()

    if args.sahte:
        print("[KAYNAK] SAHTE -- gercek cihazdan alinmis cerceveler oynatiliyor")
        OKUYUCU = jk_bms.SahteOkuyucu()
    elif args.seri:
        print(f"[KAYNAK] seri {args.seri} @ {args.baud}")
        OKUYUCU = jk_bms.SeriOkuyucu(args.seri, args.baud, surum=args.surum)
    else:
        print(f"[KAYNAK] BLE {args.ble}")
        OKUYUCU = jk_bms.BleOkuyucu(args.ble, surum=args.surum)

    sunucu = ThreadingHTTPServer((args.adres, args.port), Isleyici)
    sunucu.daemon_threads = True
    print(f"\n  Panel      : http://localhost:{args.port}/")
    print(f"  JSON       : http://localhost:{args.port}/api/durum")
    print(f"  Canli akis : http://localhost:{args.port}/api/akis")
    print("\n  Durdurmak icin Ctrl+C\n")

    def kayit():
        while True:
            time.sleep(5)
            d = OKUYUCU.durum()
            if d["veri"]:
                v = d["veri"]
                print(f"  SOC %{v['soc_yuzde']:3d}  {v['toplam_gerilim_v']:6.2f} V  "
                      f"{v['akim_a']:+7.1f} A  {v['guc_w']:+8.1f} W  "
                      f"{v['sicaklik_1_c']:4.1f} C  [{v['durum']}]")
            else:
                print(f"  veri yok  ({d.get('hata') or 'bekleniyor'})")

    threading.Thread(target=kayit, daemon=True).start()
    try:
        sunucu.serve_forever()
    except KeyboardInterrupt:
        print("\n[KAPANIYOR]")
    finally:
        OKUYUCU.kapat()
    return 0


if __name__ == "__main__":
    sys.exit(main())
