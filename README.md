# kaifa
Read out Kaifa smart meter 

## Config

Create a file `meter.json` to configure your serial connection 
parameters and your AES key.

A template file `meter_template.json` can be recycled for this.

The AES key format is "hex string", e.g. `a4f2d...`

### Export

Currently, the export to a file readable by Solarview (http://solarview.info/)
is supported.

- The config key `export_format` has to be set to `SOLARVIEW`
- The config key `export_file_abspath` has to be set to the absolute file path

## Start

### Foreground

`python3 kaifa.py`

### Background

`nohup python3 kaifa.py &`

## Stop

### Foreground

Press CTRL+C

### Background

Possible by killing the process

