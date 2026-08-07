#!/usr/bin/env bash
# Arduino firmware'inin ACIL STOP mantigini KART OLMADAN test eder.
# Arduino API'si taklit edilir, .ino dogrudan derlenir.
#     ./calistir.sh
set -e
D="$(cd "$(dirname "$0")" && pwd)"
sed 's|#include <Wire.h>||; s|#include <Adafruit_MCP4725.h>||' \
    "$D/../arduino_dac_surucu.ino" > "$D/govde_test.inc"
g++ -std=c++17 -w -I"$D" -o "$D/acil" "$D/acil_test.cpp"
"$D/acil"

g++ -std=c++17 -w -I"$D" -o "$D/enk" "$D/enkoder_test.cpp"
"$D/enk"
