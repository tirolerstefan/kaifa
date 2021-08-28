#/usr/bin/python3

import sys
import os
import time
import serial
import binascii
from Cryptodome.Cipher import AES
import json
import signal
import logging
from logging.handlers import RotatingFileHandler

#
# Trap CTRL+C
#
def signal_handler(sig, frame):
    print('Aborted by user with Ctrl+C!')
    g_ser.close()
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# global logging object will be initialized after config is parsed
g_log = None


class Logger:
    def __init__(self, logfile, level):
        self._logfile = logfile
        self._level = level
        self._logger = None

    def init(self):
        self._logger = logging.getLogger('kaifa')
        handler = RotatingFileHandler(self._logfile, maxBytes=1000, backupCount=1)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._logger.setLevel(self._level)

    def set_level(self, level):
        self._level = level
        self._logger.setLevel(level)

    def log_debug(self, s):
        self._logger.debug(s)

    def log_info(self, s):
        self._logger.info(s)

    def log_error(self, s):
        self._logger.error(s)


class Constants:
    config_file = "meter.json"
    frame1_start_bytes = b'\x68\xfa\xfa\x68'  # 68 FA FA 68
    frame2_start_bytes = b'\x68\x72\x72\x68'  # 68 72 72 68
    export_format_solarview = "SOLARVIEW"


class Config:
    def __init__(self, file):
        self._file = file

    def load(self):
        try:
            with open(self._file, "r") as f:
                self._config = json.load(f)
        except Exception as e:
            print("Error loading config file {}".format(self._file))
            return False
        return True

    def get_config(self):
        return self._config

    # returns log level of logging facility (e.g. logging.DEBUG)
    def get_loglevel(self):
        return eval(self._config["loglevel"])

    def get_logfile(self):
        return self._config["logfile"]

    def get_port(self):
        return self._config["port"]

    def get_baud(self):
        return self._config["baudrate"]

    def get_parity(self):
        return eval(self._config["parity"])

    def get_stopbits(self):
        return eval(self._config["stopbits"])

    def get_bytesize(self):
        return eval(self._config["bytesize"])

    def get_key_hex_string(self):
        return self._config["key_hex_string"]

    def get_interval(self):
        return self._config["interval"]

    def get_export_format(self):
        if not "export_format" in self._config:
            return None
        else:
            return self._config["export_format"]

    def get_export_file_abspath(self):
        if not "export_file_abspath" in self._config:
            return None
        else:
            return self._config["export_file_abspath"]


class Obis:
    OBIS_1_8_0 = b'0100010800ff'   # Bytecode of Positive active energy (A+) total [Wh]
    OBIS_1_8_0_S = '1.8.0'         # String of Positive active energy (A+) total [Wh]
    OBIS_2_8_0 = b'0100020800ff'   # Bytecode of Negative active energy (A-) total [Wh]
    OBIS_2_8_0_S = '2.8.0'         # String of Negative active energy (A-) total [Wh]


class Exporter:
    def __init__(self, file, exp_format):
        self._file = file
        self._format = exp_format
        self._export_map = {}

    def set_value(self, obis_string, value):
        self._export_map[obis_string] = value

    def _write_out_solarview(self, file):
        file.write("/?!\n")       # Start bytes
        file.write("/KAIFA\n")    # Meter ID

        for key in self._export_map.keys():
            # e.g. 1.8.0(005305.034*kWh)
            file.write("{}({:010.3F}*kWh)\n".format(key, self._export_map[key]))

        file.write("!\n")         # End byte

    def write_out(self):
        try:
            with open(self._file, "w") as f:
                if self._format == Constants.export_format_solarview:
                    self._write_out_solarview(f)
        except Exception as e:
            g_log.log_error("Error writing to file {}: {}".format(self._file, str(e)))
            return False

        return True


# class Decrypt
# with help of @micronano
# https://www.photovoltaikforum.com/thread/157476-stromz%C3%A4hler-kaifa-ma309-welches-mbus-usb-kabel/?postID=2341069#post2341069
class Decrypt:

    def __init__(self, frame1, frame2, key_hex_string):
        key = binascii.unhexlify(key_hex_string)  # convert to binary stream
        systitle = frame1[11:19]  # systitle at byte 12, length 8
        # print(systitle)
        ic = frame1[23:27]   # invocation counter at byte 24, length 4
        iv = systitle + ic   # initialization vector
        data_frame1 = frame1[27:len(frame1) - 2]  # start at byte 28, excluding 2 bytes at end: checksum byte, end byte 0x16
        data_frame2 = frame2[9:len(frame2) - 2]   # start at byte 10, excluding 2 bytes at end: checksum byte, end byte 0x16
        # print(binascii.hexlify(data_t1))
        # print(binascii.hexlify(data_t2))
        data_encrypted = data_frame1 + data_frame2
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        self._data_decrypted = cipher.decrypt(data_encrypted)
        self._data_decrypted_hex = binascii.hexlify(self._data_decrypted)

        g_log.log_debug(self._data_decrypted_hex)

        # init OBIS values
        self._act_energy_pos_kwh = 0
        self._act_energy_neg_kwh = 0

    def parse_all(self):
        # use 0906 as separator, because we are only interested in the octet-strings (09)
        # which have a 06 byte obis code (e.g. 0906 0100010800ff 0600514c1c02020f00161e0203)
        l = self._data_decrypted_hex.split(b'0906')

        for d in l:
            # print(d)
            # e.g. 0906 01 00 01 08 00 ff  06 0050933c 0202 0f 00 16 1e
            #           |-- OBIS CODE --|     |- Wh -|
            if d[0:12] == Obis.OBIS_1_8_0:
                self._act_energy_pos_kwh=int.from_bytes(binascii.unhexlify(d[14:22]), 'big') / 1000
            if d[0:12] == Obis.OBIS_2_8_0:
                self._act_energy_neg_kwh = int.from_bytes(binascii.unhexlify(d[14:22]), 'big') / 1000

    def get_act_energy_plus_kwh(self):
        return self._act_energy_pos_kwh

    def get_act_energy_neg_kwh(self):
        return self._act_energy_neg_kwh


#
# Script Start
#

g_cfg = Config(Constants.config_file)

if not g_cfg.load():
    print("Could not load config file")
    sys.exit(10)

g_log = Logger(g_cfg.get_logfile(), g_cfg.get_loglevel())

try:
    g_log.init()
except Exception as e:
    print("Could not initialize logging system: " + str(e))
    sys.exit(20)


g_ser = serial.Serial(
        port = g_cfg.get_port(),
        baudrate = g_cfg.get_baud(),
        parity = g_cfg.get_parity(),
        stopbits = g_cfg.get_stopbits(),
        bytesize = g_cfg.get_bytesize(),
        timeout = g_cfg.get_interval())


frame1 = b''
frame2 = b''
stream = b''

while True:
    stream += g_ser.readline()
    #print(binascii.hexlify(stream))

    frame1_start_pos = stream.find(Constants.frame1_start_bytes)
    frame2_start_pos = stream.find(Constants.frame2_start_bytes)

    # do we have any of the start bytes in this stream?
    # otherwise, continue listening on serial port and accumulate stream
    if (frame1_start_pos != -1) and (frame2_start_pos != -1):
        # do we have a frame2 start byte before a frame1 start byte? -> we parse telegram 1 (68 FA FA 68)
        if frame2_start_pos > frame1_start_pos:
            frame1 = stream[frame1_start_pos:frame2_start_pos]
            g_log.log_debug("TELEGRAM1:\n{}\n".format(binascii.hexlify(frame1)))
            stream = stream[frame2_start_pos:len(stream)]
            continue
        # do we have a frame1 start byte before a frame2 start byte? -> we parse telegram 2 (68 72 72 68)
        elif frame1_start_pos > frame2_start_pos:
            frame2 = stream[frame2_start_pos:frame1_start_pos]
            g_log.log_debug("TELEGRAM2:\n{}\n".format(binascii.hexlify(frame2)))

            # decrypt, when we have both - frame 1 and frame 2
            if frame1 != b'':
                dec = Decrypt(frame1, frame2, g_cfg.get_key_hex_string())
                # print("DECRYPTED DATA:\n{}\n{}\n".format(data,binascii.hexlify(data)))
                dec.parse_all()
                g_log.log_info("1.8.0: {}".format(dec.get_act_energy_plus_kwh()))
                g_log.log_info("2.8.0: {}".format(dec.get_act_energy_neg_kwh()))
                # export
                if g_cfg.get_export_format() is not None:
                    exp = Exporter(g_cfg.get_export_file_abspath(), g_cfg.get_export_format())
                    exp.set_value(Obis.OBIS_1_8_0_S, dec.get_act_energy_plus_kwh())
                    exp.set_value(Obis.OBIS_2_8_0_S, dec.get_act_energy_neg_kwh())
                    if not exp.write_out():
                        g_log.log_error("Could not export data")
                        sys.exit(50)
            frame1 = b''
            frame2 = b''
            stream = stream[frame1_start_pos:len(stream)]
            continue

g_ser.close()


