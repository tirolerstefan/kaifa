# Kaifa MA309 Smart Meter Logger

## Overview

This script was made to read out the new Smart Meter "Kaifa MA309"
used by Austrian power grid operators, here tested with TINETZ and EVN.

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
  "loglevel": "logging.INFO",
  "logfile": "/var/log/kaifareader/kaifa.log",
  "port": "/dev/ttyUSB0",
  "baudrate": 2400,
  "parity": "serial.PARITY_NONE",
  "stopbits": "serial.STOPBITS_ONE",
  "bytesize": "serial.EIGHTBITS",
  "key_hex_string": "",
  "interval": 1,
  "supplier": "TINETZ",
  "export_format": "SOLARVIEW",
  "export_file_abspath": "/var/run/kaifareader/kaifa.txt",
  "export_mqtt_server": "mymqtt.examplebroker.com",
  "export_mqtt_port": 1883,
  "export_mqtt_user": "mymqttuser",
  "export_mqtt_password": "supersecretmqttpass",
  "export_mqtt_basetopic": "kaifareader",
  "wanted_values": [
    "VoltageL1",
    "VoltageL2",
    "VoltageL3",
    "CurrentL1",
    "CurrentL2",
    "CurrentL3",
    "RealPowerIn",
    "RealPowerOut",
    "RealEnergyIn",
    "RealEnergyOut",
    "ReactiveEnergyIn",
    "ReactiveEnergyOut",
    "Factor"
  ]
}
```

The AES key format is "hex string", e.g. `a4f2d...`

Please provide your electricity supplier by the field "supplier". Because each supplier uses its own security standard, 
the telegrams differ. This script was tested with suppliers:
- TINETZ
- EVN

Make sure to only select the values you need from the list in `wanted_values` by deleting the elements you don't want. 
The logfile will show the related OBIS-Values when run in `logging.INFO`.

`interval` must be `<5` seconds, `1` second is recommended tho.


### Export

**Solarview**

Currently, the export to a file readable by Solarview (http://solarview.info/)
is supported.

- The config key `export_format` has to be set to `SOLARVIEW`
- The config key `export_file_abspath` has to be set to the absolute file path

**MQTT**

- The config key `export_format` has to be set to `MQTT`
- The config keys `export_mqtt_server`, `export_mqtt_port`,
  `export_mqtt_user`, `export_mqtt_password` and `export_mqtt_basetopic`
  have to be set.

## Installation

### Systemd automatic service

This installs and automatically starts a systemd service.

Install the debian package 

`sudo dpkg -i kaifareader_...deb`

If there are problems on missing packages, execute afterwards:

`sudo apt -f install`

## Start

### Automatically, if service is installed and running

Startup done, automatically.

Status of the service:

`sudo systemctl status kaifareader`

Start manually (e.g. after manually stopped)

`sudo systemctl start kaifareader`

### Manually

#### Foreground

`python3 kaifa.py`

#### Background

`nohup python3 kaifa.py &`

## Stop

### If service is installed and running

`sudo systemctl stop kaifareader`

### Foreground

Press CTRL+C

### Background

Possible by killing the process

