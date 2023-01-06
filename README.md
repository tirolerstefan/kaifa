# Kaifa MA309 Smart Meter Logger

## Overview

This script was made to read out the new Smart Meter "Kaifa MA309" used by Austrian power grid operators.<br>
Tested with KSM-West (Vorarlbergnetz e.g. VKW).

Specification of the interface:
https://www.tinetz.at/fileadmin/user_upload/Kundenservice/pdf/Beschreibung_Kundenschnittstelle_Smart_Meter_TINETZ.pdf

Discussion about this script:
https://www.photovoltaikforum.com/thread/157476-stromz%C3%A4hler-kaifa-ma309-welches-mbus-usb-kabel/?pageNo=2#post2350873

Useful description of TiNetz frames:
https://www.gurux.fi/node/18232

This script was only tested with the above meter and the mentioned suppliers.

## Required Hardware

![Picture of wiring](img/connection.png)

1. RJ12 6P6C Plug

    e.g. https://www.amazon.de/6P6C-Stecker-6-polige-Schraubklemmen-Adapterstecker-CCTV-Adapterstecker/dp/B07KFGS3BF
<br><br>
    **Note**: you have to cut off the plastic shell of the RJ12 plug to fit it into the socket of the MA309.
<br><br>
2. MBUS Slave module like this:

    https://www.amazon.de/JOYKK-USB-zu-MBUS-Slave-Modul-Master-Slave-Kommunikation-Debugging-Bus%C3%BCberwachung/dp/B07PDH2ZBV

## Config

Create a file `meter.json` to configure your serial connection 
parameters and your AES key.

A template file `meter_template.json` can be recycled for this.

```
{
  "loglevel": "logging.DEBUG",
  "port": "/dev/ttyUSB0",
  "baudrate": 2400,
  "parity": "serial.PARITY_EVEN",
  "stopbits": "serial.STOPBITS_ONE",
  "bytesize": "serial.EIGHTBITS",
  "key_hex_string": "",
  "supplier": "KSMWest",
  "file_export_enabled": true,
  "file_export_abspath": "/etc/kaifareader/export.txt",
  "mqtt_enabled": false,
  "mqtt_server": "192.168.0.99",
  "mqtt_port": 1883,
  "mqtt_user": "",
  "mqtt_password": "",
  "mqtt_basetopic": "kaifareader",
  "influxdb_enabled": false,
  "influxdb_url": "http://192.168.0.99:8086",
  "influxdb_token": "",
  "influxdb_org": "local",
  "influxdb_bucket": "kaifareader",
  "influxdb_measurement": "smartmeter"
}
```

The AES key format is "hex string", e.g. `a4f2d...`

Please provide your electricity supplier by the field "supplier". Because each supplier uses its own security standard, 
the telegrams differ. This script was tested with suppliers:
- KSMWest
- EVN

### Export

**File**

Currently, the export to a file readable by Solarview (http://solarview.info/)
is supported.

- The config key `file_export_enabled` has to be set to `true`
- The config key `file_export_abspath` has to be set to the absolute file path

**MQTT**

- The config key `mqtt_enabled` has to be set to `true`
- The config keys `mqtt_server`, `mqtt_port`,
  `mqtt_user`, `mqtt_password` and `mqtt_basetopic`
  have to be set.

**influxdb v2**

- The config key `influxdb_enabled` has to be set to `true`
- The config keys `influxdb_url`, `influxdb_token`,
  `influxdb_org`, `influxdb_bucket` and `influxdb_measurement`
  have to be set.
  
## Run on docker

```
docker run -d \
    --name=kaifareader \
    --restart unless-stopped \
    -v kaifareader-config:/etc/kaifareader \
    --device=/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_A10MLN5Z-if00-port0:/dev/ttyUSB0 \
    phil1pp/kaifareader
```