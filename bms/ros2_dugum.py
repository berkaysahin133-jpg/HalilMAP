#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JK BMS -> ROS 2  (sensor_msgs/BatteryState)

NE ZAMAN BUNU KULLANIRSIN
    Robot ROS 2'ye gectiginde. O zaman rosbridge_server + roslibjs ile web
    arayuzun bu konuya dogrudan abone olur ve BMS icin ayrica bir sey yazman
    gerekmez.

NE ZAMAN GEREKMEZ
    Su an. ROS 2 kurulu degilse sunucu.py zaten calisiyor (JSON + SSE, pip
    gerektirmiyor). Sadece batarya gostergesi icin ROS 2 kurmak, bir bardak
    su icin baraj yapmaktir.

BU DOSYANIN ASIL AMACI
    Mimari iddiayi kanitlamak: jk_bms.py bir KUTUPHANE, ROS'a bagli degil.
    ROS'a gecis bir yeniden yazim degil, su 60 satirlik sarmalayici.
    Ayni sey c1.py (LiDAR) ve guvenlik.py icin de gecerli.

CALISTIRMA (ROS 2 kurulu bir makinede)
    ros2 run ... ya da dogrudan:
        python3 ros2_dugum.py --ros-args -p seri:=/dev/ttyUSB0
        python3 ros2_dugum.py --ros-args -p sahte:=true      # batarya olmadan

    Sonra web tarafi:
        ros2 launch rosbridge_server rosbridge_websocket_launch.xml
        # tarayicida roslibjs ile ws://<robot-ip>:9090 uzerinden /batarya

DIKKAT: Bu dosya ROS 2 KURULU OLMAYAN bir makinede test EDILEMEDI.
Sozdizimi dogrulandi, alan adlari sensor_msgs/BatteryState tanimina gore
yazildi. ROS 2'li makinede ilk calistirmada dogrula.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jk_bms

try:
    import rclpy
    from rclpy.node import Node
    from sensor_msgs.msg import BatteryState
    from std_msgs.msg import Float32, String
except ImportError:
    print(__doc__)
    print("\n[HATA] ROS 2 (rclpy) bulunamadi. Bu dosya ROS 2 kurulu bir "
          "makinede calisir.\n       ROS'suz kullanim icin:  python3 sunucu.py --sahte")
    sys.exit(1)


class BmsDugumu(Node):
    def __init__(self):
        super().__init__("jk_bms")
        self.declare_parameter("seri", "")
        self.declare_parameter("ble", "")
        self.declare_parameter("sahte", False)
        self.declare_parameter("baud", 115200)
        self.declare_parameter("hz", 1.0)

        seri = self.get_parameter("seri").value
        ble = self.get_parameter("ble").value
        sahte = self.get_parameter("sahte").value

        if sahte:
            self.okuyucu = jk_bms.SahteOkuyucu()
            self.get_logger().info("SAHTE kaynak (gercek cerceveler oynatiliyor)")
        elif seri:
            self.okuyucu = jk_bms.SeriOkuyucu(seri, self.get_parameter("baud").value)
            self.get_logger().info(f"seri {seri}")
        elif ble:
            self.okuyucu = jk_bms.BleOkuyucu(ble)
            self.get_logger().info(f"BLE {ble}")
        else:
            raise RuntimeError("seri, ble ya da sahte parametrelerinden biri gerekli")

        self.yay = self.create_publisher(BatteryState, "batarya", 10)
        self.yay_sicaklik = self.create_publisher(Float32, "batarya/sicaklik", 10)
        self.yay_hata = self.create_publisher(String, "batarya/hatalar", 10)
        hz = float(self.get_parameter("hz").value)
        self.create_timer(1.0 / max(0.1, hz), self.gonder)

    def gonder(self):
        d = self.okuyucu.durum()
        if not d["bagli"] or not d["veri"]:
            return
        v = d["veri"]

        m = BatteryState()
        m.header.stamp = self.get_clock().now().to_msg()
        m.header.frame_id = "batarya"
        m.voltage = float(v["toplam_gerilim_v"])
        m.temperature = float(v["sicaklik_1_c"])
        # ROS gelenegi JK ile ayni: desarjda akim NEGATIF
        m.current = float(v["akim_a"])
        m.charge = float(v["kalan_kapasite_ah"])
        m.capacity = float(v["tam_kapasite_ah"])
        m.design_capacity = float(v["tam_kapasite_ah"])
        m.percentage = float(v["soc_yuzde"]) / 100.0        # ROS 0..1 ister
        m.present = True
        m.cell_voltage = [float(x) for x in v["hucre_gerilimleri"] if x > 0]
        m.cell_temperature = [float(v["sicaklik_1_c"]), float(v["sicaklik_2_c"])]
        m.location = "arac"
        m.serial_number = (d["cihaz"] or {}).get("seri_no", "")

        if v["durum"] == "SARJ":
            m.power_supply_status = BatteryState.POWER_SUPPLY_STATUS_CHARGING
        elif v["durum"] == "DESARJ":
            m.power_supply_status = BatteryState.POWER_SUPPLY_STATUS_DISCHARGING
        elif v["soc_yuzde"] >= 100:
            m.power_supply_status = BatteryState.POWER_SUPPLY_STATUS_FULL
        else:
            m.power_supply_status = BatteryState.POWER_SUPPLY_STATUS_NOT_CHARGING

        m.power_supply_health = (BatteryState.POWER_SUPPLY_HEALTH_GOOD
                                 if not v["hatalar"]
                                 else BatteryState.POWER_SUPPLY_HEALTH_UNKNOWN)
        # LiFePO4 paket; hucre gerilimi 3.2-3.3 V bandindaysa LIFE dogrudur
        m.power_supply_technology = BatteryState.POWER_SUPPLY_TECHNOLOGY_LIFE

        self.yay.publish(m)
        self.yay_sicaklik.publish(Float32(data=float(v["mosfet_sicaklik_c"])))
        if v["hatalar"]:
            self.yay_hata.publish(String(data=" | ".join(v["hatalar"])))


def main():
    rclpy.init()
    dugum = BmsDugumu()
    try:
        rclpy.spin(dugum)
    except KeyboardInterrupt:
        pass
    finally:
        dugum.okuyucu.kapat()
        dugum.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
