#!/usr/bin/env bash
# =============================================================================
#  Jetson Orin Nano  ->  Claude Code kurulumu  (yedek yol)
#
#  Normalde su iki komut yeter:
#      curl -fsSL https://claude.ai/install.sh | bash
#      source ~/.bashrc
#
#  Bu betik o yol tutmazsa devreye giren yedegi de icerir (nvm + Node 20 + npm)
#  ve PATH ayarini kendisi yapar.
#
#      chmod +x jetson_claude_kur.sh
#      ./jetson_claude_kur.sh
#
#  sudo ile CALISTIRMA. Gerektigi yerde kendisi soracak.
# =============================================================================
set -uo pipefail

basli() { echo -e "\n==============================================================\n  $1\n=============================================================="; }
ok()    { echo "  [OK]   $1"; }
bilgi() { echo "  [..]   $1"; }
uyari() { echo "  [!]    $1"; }
hata()  { echo "  [HATA] $1"; }

# -----------------------------------------------------------------------------
basli "1/3  Sistem"
echo "  mimari : $(uname -m)"
[ -f /etc/nv_tegra_release ] && echo "  jetpack: $(head -1 /etc/nv_tegra_release)"
if [ -f /etc/os-release ]; then . /etc/os-release; echo "  sistem : $PRETTY_NAME"; fi
echo "  disk   : $(df -h / | awk 'NR==2{print $4}') bos"

# Yarim kalmis bir dpkg islemi APT'yi tamamen kilitler:
#   "dpkg was interrupted, you must manually run 'sudo dpkg --configure -a'"
# Bu durumda hicbir paket kurulamaz, once onu duzelt.
if ! sudo dpkg --audit >/dev/null 2>&1 || \
   sudo apt-get check 2>&1 | grep -qi "dpkg was interrupted"; then
    uyari "yarim kalmis paket kurulumu bulundu -> onariliyor"
    sudo dpkg --configure -a || uyari "dpkg onarimi tam bitmedi, devam ediliyor"
fi

# NOT: 'Ignoring file ...list.save ... invalid filename extension' satirlari
# HATA DEGIL. APT, .list disi uzantili dosyalari gormezden gelir; dogru davranis.

if ! command -v curl >/dev/null 2>&1; then
    if command -v wget >/dev/null 2>&1; then
        bilgi "curl yok ama wget var -- wget kullanilacak"
        INDIR="wget -qO-"
    else
        bilgi "curl kuruluyor (sudo sifresi istenebilir)"
        sudo apt-get update -qq && sudo apt-get install -y curl || {
            hata "curl kurulamadi. Once sunu calistir:  sudo dpkg --configure -a"
            hata "sonra:  sudo apt update && sudo apt install -y curl"
            exit 1; }
        INDIR="curl -fsSL"
    fi
else
    INDIR="curl -fsSL"
fi
ok "indirme araci: ${INDIR%% *}"

# -----------------------------------------------------------------------------
basli "2/3  Claude Code"

if command -v claude >/dev/null 2>&1; then
    ok "zaten kurulu: $(claude --version 2>/dev/null || echo '?')"
else
    bilgi "resmi kurulum betigi deneniyor (bagimsiz ikili, Node gerekmez)"
    if $INDIR https://claude.ai/install.sh | bash; then
        ok "kuruldu"
    else
        uyari "olmadi -> npm yoluna geciliyor"
        # nvm kullaniyoruz: 'sudo npm -g' izin hatalari kurulumun 1 numarali
        # takilma sebebi, nvm ile o sorun hic olusmuyor.
        if ! command -v node >/dev/null 2>&1 || \
           [ "$(node -v 2>/dev/null | sed 's/v\([0-9]*\).*/\1/')" -lt 18 ] 2>/dev/null; then
            bilgi "Node.js 20 kuruluyor (nvm)"
            $INDIR https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
            export NVM_DIR="$HOME/.nvm"
            # shellcheck disable=SC1091
            [ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"
            nvm install 20 && nvm alias default 20
        fi
        command -v node >/dev/null 2>&1 || { hata "Node kurulamadi"; exit 1; }
        ok "node $(node -v)"
        npm install -g @anthropic-ai/claude-code || { hata "npm kurulumu basarisiz"; exit 1; }
    fi
fi

# Kurulum ~/.local/bin ya da ~/.claude/bin altina gidebilir; PATH'e ekle
for D in "$HOME/.local/bin" "$HOME/.claude/bin"; do
    if [ -d "$D" ] && [[ ":$PATH:" != *":$D:"* ]]; then
        export PATH="$D:$PATH"
        grep -qF "$D" "$HOME/.bashrc" 2>/dev/null || \
            echo "export PATH=\"$D:\$PATH\"" >> "$HOME/.bashrc"
        bilgi "PATH'e eklendi: $D"
    fi
done

if ! command -v claude >/dev/null 2>&1; then
    hata "claude komutu bulunamadi."
    echo "         Yeni terminal ac ve dene:  source ~/.bashrc && claude --version"
    exit 1
fi
ok "claude $(claude --version 2>/dev/null || echo kurulu)"

# -----------------------------------------------------------------------------
basli "3/3  Siradaki adimlar"
cat <<'SON'

  1) Yeni terminal ac (PATH icin):     source ~/.bashrc

  2) Proje klasorunde baslat:          cd ~/HalilMAP && claude

  3) Ilk acilista giris istenecek. Ekrandaki baglantiyi tarayicida ac
     (Jetson'da tarayici yoksa telefondan/PC'den de olur), onayla,
     cikan kodu terminale yapistir.

  PyCharm kullanacaksan:
     Settings > Plugins > Marketplace > "Claude Code" > Install
     Sonra PyCharm'in terminalinde:  claude

  GUVENLIK: ilk denemelerde araci TEKERLEKLERI YERDEN KESIK sehpaya al.
  Kod calistiginda motorlar donebilir.

SON
