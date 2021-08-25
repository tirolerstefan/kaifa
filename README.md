# kaifa
Read out Kaifa smart meter 

## Config

Create a file `meter.json` to configure your serial connection 
parameters and your AES key.

A template file `meter_template.json` can be recycled for this.

The AES key format is "hex string", e.g. `a4f2d...`

## Start

  python3 kaifa.py

