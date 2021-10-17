#/usr/bin/python3

import sys
import re
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


# create signal handler
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
        handler = RotatingFileHandler(self._logfile, maxBytes=1024*1024*2, backupCount=1)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._logger.setLevel(self._level)

    def set_level(self, level):
        self._level = level
        self._logger.setLevel(level)

    def debug(self, s):
        self._logger.debug(s)

    def info(self, s):
        self._logger.info(s)

    def error(self, s):
        self._logger.error(s)


class Constants:
    config_file = "/etc/kaifareader/meter.json"
    frame1_start_bytes = b'\x68\xfa\xfa\x68'  # 68 FA FA 68
    frame2_start_bytes = b'\x68\x14\x14\x68'  # 68 14 14 68
    frame1_start_bytes_hex = '68fafa68'
    frame2_start_bytes_hex = '68141468'
    export_format_solarview = "SOLARVIEW"


class Config:
    def __init__(self, file):
        self._file = file
        self._config = {}

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
            g_log.error("Error writing to file {}: {}".format(self._file, str(e)))
            return False

        return True


# class Decrypt
# with help of @micronano
# https://www.photovoltaikforum.com/thread/157476-stromz%C3%A4hler-kaifa-ma309-welches-mbus-usb-kabel/?postID=2341069#post2341069
class Decrypt:

    def __init__(self, frame1, frame2, key_hex_string):
        g_log.debug("Decrypt: FRAME1:\n{}".format(binascii.hexlify(frame1)))
        g_log.debug("Decrypt: FRAME2:\n{}".format(binascii.hexlify(frame2)))
        key = binascii.unhexlify(key_hex_string)  # convert to binary stream
        systitle = frame1[11:19]  # systitle at byte 12, length 8
        g_log.debug("SYSTITLE: {}".format(binascii.hexlify(systitle)))
        ic = frame1[23:27]   # invocation counter at byte 24, length 4
        g_log.debug("IC: {} / {}".format(binascii.hexlify(ic), int.from_bytes(ic,'big')))
        iv = systitle + ic   # initialization vector
        g_log.debug("IV: {}".format(binascii.hexlify(iv)))
        data_frame1 = frame1[26:len(frame1) - 2]  # start at byte 27, excluding 2 bytes at end: checksum byte, end byte 0x16
        data_frame2 = frame2[9:len(frame2) - 2]   # start at byte 10, excluding 2 bytes at end: checksum byte, end byte 0x16
        g_log.debug("DATA FRAME1\n{}".format(binascii.hexlify(data_frame1)))
        g_log.debug("DATA FRAME1\n{}".format(binascii.hexlify(data_frame2)))
        # print(binascii.hexlify(data_t1))
        # print(binascii.hexlify(data_t2))
        data_encrypted = data_frame1 + data_frame2
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        self._data_decrypted = cipher.decrypt(data_encrypted)
        self._data_decrypted_hex = binascii.hexlify(self._data_decrypted)

        g_log.debug(self._data_decrypted_hex)

        # init OBIS values
        self._act_energy_pos_kwh = 0
        self._act_energy_neg_kwh = 0

    def parse_all(self):
        # use 0906 as separator, because we are only interested in the octet-strings (09)
        # which have a 06 byte obis code (e.g. 0906 0100010800ff 0600514c1c02020f00161e0203)
        l = self._data_decrypted_hex.split(b'0906')

        g_log.debug(l)

        for d in l:
            g_log.debug(d)
            # e.g. 0906 01 00 01 08 00 ff  06 0050933c 0202 0f 00 16 1e
            #           |-- OBIS CODE --|     |- Wh -|
            if d[0:12] == Obis.OBIS_1_8_0:
                self._act_energy_pos_kwh=int.from_bytes(binascii.unhexlify(d[14:22]), 'big') / 1000
            if d[0:12] == Obis.OBIS_2_8_0:
                self._act_energy_neg_kwh = int.from_bytes(binascii.unhexlify(d[14:22]), 'big') / 1000

    def get_act_energy_pos_kwh(self):
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


# main task endless loop
while True:
    stream = b''      # filled by serial device
    frame1 = b''      # parsed telegram1
    frame2 = b''      # parsed telegram2

    frame1_start_pos = -1          # pos of start bytes of telegram 1 (in stream)
    frame2_start_pos = -1          # pos of start bytes of telegram 2 (in stream)
    next_frame1_start_pos = -1     # pos of start bytes of NEXT telegram 1 (in stream)

    # "telegram fetching loop" (as long as we have found two full telegrams)
    # frame1 = first telegram (68fafa68), frame2 = second telegram (68727268)
    # we need to wait for the "next" frame 1 to be sure that frame2 has completely arrived
    while True:
        stream += g_ser.readline()

        frame1_start_pos = stream.find(Constants.frame1_start_bytes)
        frame2_start_pos = stream.find(Constants.frame2_start_bytes)

        if frame2_start_pos != -1:
            next_frame1_start_pos = stream.find(Constants.frame1_start_bytes, frame2_start_pos)

        g_log.debug("pos: {} | {} | {}".format(frame1_start_pos, frame2_start_pos, next_frame1_start_pos))

        if (frame1_start_pos != -1) and (frame2_start_pos != -1) and (next_frame1_start_pos != -1):
            # frame2_start_pos could be smaller than frame1_start_pos
            if frame2_start_pos < frame1_start_pos:
                # start over with the stream from frame1 pos
                stream = stream[frame1_start_pos:len(stream)]
                continue

            # we have found at least two complete telegrams
            regex = binascii.unhexlify('28'+Constants.frame1_start_bytes_hex+'7c'+Constants.frame2_start_bytes_hex+'29')  # re = '(..|..)'
            l = re.split(regex, stream)
            l = list(filter(None, l))  # remove empty elements
            # l after split (here in following example in hex)
            # l = ['68fafa68', '53ff00...faecc16', '68727268', '53ff...3d16', '68fafa68', '53ff...d916', '68727268', '53ff.....']

            g_log.debug(binascii.hexlify(stream))
            g_log.debug(l)

            # take the first two matching telegrams
            for i, el in enumerate(l):
                if el == Constants.frame1_start_bytes:
                    frame1 = l[i] + l[i+1]
                    frame2 = l[i+2] + l[i+3]
                    break

            # check for weird result -> exit
            if (len(frame1) == 0) or (len(frame2) == 0):
                g_log.error("Frame1 or Frame2 is empty: {} | {}".format(frame1, frame2))
                sys.exit(30)

            g_log.debug("TELEGRAM1:\n{}\n".format(binascii.hexlify(frame1)))
            g_log.debug("TELEGRAM2:\n{}\n".format(binascii.hexlify(frame2)))

            break

    dec = Decrypt(frame1, frame2, g_cfg.get_key_hex_string())
    dec.parse_all()

    g_log.info("1.8.0: {}".format(dec.get_act_energy_pos_kwh()))
    g_log.info("2.8.0: {}".format(dec.get_act_energy_neg_kwh()))

    # export
    if g_cfg.get_export_format() is not None:
        exp = Exporter(g_cfg.get_export_file_abspath(), g_cfg.get_export_format())
        exp.set_value(Obis.OBIS_1_8_0_S, dec.get_act_energy_pos_kwh())
        exp.set_value(Obis.OBIS_2_8_0_S, dec.get_act_energy_neg_kwh())
        if not exp.write_out():
            g_log.error("Could not export data")
            sys.exit(50)




