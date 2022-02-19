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
import paho.mqtt.client as mqtt

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


class Supplier:
    name = None
    frame1_start_bytes_hex = '68fafa68'
    frame1_start_bytes = b'\x68\xfa\xfa\x68'  # 68 FA FA 68
    frame2_end_bytes = b'\x16'
    ic_start_byte = None
    enc_data_start_byte = None


class SupplierTINETZ(Supplier):
    name = "TINETZ"
    frame2_start_bytes_hex = '68727268'
    frame2_start_bytes = b'\x68\x72\x72\x68'  # 68 72 72 68
    ic_start_byte = 23
    enc_data_start_byte = 27


class SupplierEVN(Supplier):
    name = "EVN"
    frame2_start_bytes_hex = '68141468'
    frame2_start_bytes = b'\x68\x14\x14\x68'  # 68 14 14 68
    ic_start_byte = 22
    enc_data_start_byte = 26


class Constants:
    config_file = "/etc/kaifareader/meter.json"
    export_format_solarview = "SOLARVIEW"

class DataType:
    NullData = 0x00
    Boolean = 0x03
    BitString = 0x04
    DoubleLong = 0x05
    DoubleLongUnsigned = 0x06
    OctetString = 0x09
    VisibleString = 0x0A
    Utf8String = 0x0C
    BinaryCodedDecimal = 0x0D
    Integer = 0x0F
    Long = 0x10
    Unsigned = 0x11
    LongUnsigned = 0x12
    Long64 = 0x14
    Long64Unsigned = 0x15
    Enum = 0x16
    Float32 = 0x17
    Float64 = 0x18
    DateTime = 0x19
    Date = 0x1A
    Time = 0x1B
    Array = 0x01
    Structure = 0x02
    CompactArray = 0x13

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

    def get_supplier(self):
        return str(self._config["supplier"])

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

    def get_export_mqtt_server(self):
        if not "export_mqtt_server" in self._config:
            return None
        else:
            return self._config["export_mqtt_server"]

    def get_export_mqtt_port(self):
        if not "export_mqtt_port" in self._config:
            return None
        else:
            return self._config["export_mqtt_port"]

    def get_export_mqtt_user(self):
        if not "export_mqtt_user" in self._config:
            return None
        else:
            return self._config["export_mqtt_user"]

    def get_export_mqtt_password(self):
        if not "export_mqtt_password" in self._config:
            return None
        else:
            return self._config["export_mqtt_password"]

    def get_export_mqtt_basetopic(self):
        if not "export_mqtt_basetopic" in self._config:
            return None
        else:
            return self._config["export_mqtt_basetopic"]


class Obis:
    def to_bytes(code):
        return bytes([int(a) for a in code.split(".")])
    VoltageL1 = to_bytes("01.0.32.7.0.255")
    VoltageL2 = to_bytes("01.0.52.7.0.255")
    VoltageL3 = to_bytes("01.0.72.7.0.255")
    CurrentL1 = to_bytes("1.0.31.7.0.255")
    CurrentL2 = to_bytes("1.0.51.7.0.255")
    CurrentL3 = to_bytes("1.0.71.7.0.255")
    RealPowerIn = to_bytes("1.0.1.7.0.255")
    RealPowerOut = to_bytes("1.0.2.7.0.255")
    RealEnergyIn = to_bytes("1.0.1.8.0.255")
    RealEnergyIn_S = '1.8.0'   # String of Positive active energy (A+) total [Wh] (needed for export)
    RealEnergyOut = to_bytes("1.0.2.8.0.255")
    RealEnergyOut_S = '2.8.0'   # String of Negative active energy (A-) total [Wh] (needed for export)
    ReactiveEnergyIn = to_bytes("1.0.3.8.0.255")
    ReactiveEnergyOut = to_bytes("1.0.4.8.0.255")
    Factor = to_bytes("01.0.13.7.0.255")


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

    def __init__(self, supplier: Supplier, frame1, frame2, key_hex_string):
        g_log.debug("Decrypt: FRAME1:\n{}".format(binascii.hexlify(frame1)))
        g_log.debug("Decrypt: FRAME2:\n{}".format(binascii.hexlify(frame2)))
        key = binascii.unhexlify(key_hex_string)  # convert to binary stream
        systitle = frame1[11:19]  # systitle at byte 12, length 8
        g_log.debug("SYSTITLE: {}".format(binascii.hexlify(systitle)))
        ic = frame1[supplier.ic_start_byte:supplier.ic_start_byte+4]   # invocation counter length 4
        g_log.debug("IC: {} / {}".format(binascii.hexlify(ic), int.from_bytes(ic,'big')))
        iv = systitle + ic   # initialization vector
        g_log.debug("IV: {}".format(binascii.hexlify(iv)))
        data_frame1 = frame1[supplier.enc_data_start_byte:len(frame1) - 2]  # start at byte 26 or 27 (dep on supplier), excluding 2 bytes at end: checksum byte, end byte 0x16
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
        decrypted = self._data_decrypted
        pos = 0
        total = len(decrypted)
        self.obis = {}
        while pos < total:
            if decrypted[pos] != DataType.OctetString:
                pos += 1
                continue
            if decrypted[pos + 1] != 6:
                pos += 1
                continue
            obis_code = decrypted[pos + 2 : pos + 2 + 6]
            data_type = decrypted[pos + 2 + 6]
            pos += 2 + 6 + 1

            g_log.debug("OBIS code {} DataType {}".format(binascii.hexlify(obis_code),data_type))
            if data_type == DataType.DoubleLongUnsigned:
                value = int.from_bytes(decrypted[pos : pos + 4], "big")
                scale = decrypted[pos + 4 + 3]
                if scale > 128: scale -= 256
                pos += 2 + 8
                self.obis[obis_code] = value*(10**scale)
                g_log.debug("DLU: {}, {}, {}".format(value, scale, value*(10**scale)))
                #print(obis)
            elif data_type == DataType.LongUnsigned:
                value = int.from_bytes(decrypted[pos : pos + 2], "big")
                scale = decrypted[pos + 2 + 3]
                if scale > 128: scale -= 256
                pos += 8
                self.obis[obis_code] = value*(10**scale)
                g_log.debug("LU: {}, {}, {}".format(value, scale, value*(10**scale)))
            elif data_type == DataType.OctetString:
                octet_len = decrypted[pos]
                octet = decrypted[pos + 1 : pos + 1 + octet_len]
                pos += 1 + octet_len + 2
                self.obis[obis_code] = octet
                g_log.debug("OCTET: {}, {}".format(octet_len, octet))

    def get_act_energy_pos_kwh(self):
        if Obis.RealEnergyIn in self.obis:
            return self.obis[Obis.RealEnergyIn] / 1000
        else:
            return None

    def get_act_energy_neg_kwh(self):
        if Obis.RealEnergyOut in self.obis:
            return self.obis[Obis.RealEnergyOut] / 1000
        else:
            return None


def mqtt_on_connect(client, userdata, flags, rc):
    if rc == 0:
        g_log.info("MQTT: Client connected; rc={}".format(rc))
    else:
        g_log.error("MQTT: Client bad RC; rc={}".format(rc))

def mqtt_on_disconnect(client, userdata, rc):
    g_log.info("MQTT: Client disconnected; rc={}".format(rc))
    if rc != 0:
        g_log.info("MQTT: Trying auto-reconnect; rc={}".format(rc))
    else:
        g_log.error("MQTT: Client bad RC; rc={}".format(rc))

#
# Script Start
#

serial_read_chunk_size=100

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

if g_cfg.get_supplier().upper() == SupplierTINETZ.name:
    g_supplier = SupplierTINETZ()
elif g_cfg.get_supplier().upper() == SupplierEVN.name:
    g_supplier = SupplierEVN()
else:
    raise Exception("Supplier not supported: {}".format(g_cfg.get_supplier()))

# connect to mqtt broker
if g_cfg.get_export_format() == 'MQTT':
    try:
        mqtt_client = mqtt.Client("kaifareader", clean_session=False)
        mqtt_client.on_connect = mqtt_on_connect
        mqtt_client.on_disconnect = mqtt_on_disconnect
        mqtt_client.username_pw_set(g_cfg.get_export_mqtt_user(), g_cfg.get_export_mqtt_password())
        mqtt_client.connect(g_cfg.get_export_mqtt_server(), port=g_cfg.get_export_mqtt_port())
        mqtt_client.loop_start()
    except Exception as e:
        print("Failed to connect: " + str(e))
        sys.exit(40)

# main task endless loop
while True:
    stream = b''      # filled by serial device
    frame1 = b''      # parsed telegram1
    frame2 = b''      # parsed telegram2

    frame1_start_pos = -1          # pos of start bytes of telegram 1 (in stream)
    frame2_start_pos = -1          # pos of start bytes of telegram 2 (in stream)

    # "telegram fetching loop" (as long as we have found two full telegrams)
    # frame1 = first telegram (68fafa68), frame2 = second telegram (68727268)
    while True:

        # Read in chunks. Each chunk will wait as long as specified by
        # serial timeout. As the meters we tested send data every 5s the
        # timeout must be <5. Lower timeouts make us fail quicker. 
        byte_chunk = g_ser.read(size=serial_read_chunk_size)
        stream += byte_chunk
        frame1_start_pos = stream.find(g_supplier.frame1_start_bytes)
        frame2_start_pos = stream.find(g_supplier.frame2_start_bytes)

        # fail as early as possible if we find the segment is not complete yet. 
        if (
           (stream.find(g_supplier.frame1_start_bytes) < 0) or
           (stream.find(g_supplier.frame2_start_bytes) <= 0) or
           (stream[-1:] != g_supplier.frame2_end_bytes) or
           (len(byte_chunk) == serial_read_chunk_size)
           ):  
            g_log.debug("pos: {} | {}".format(frame1_start_pos, frame2_start_pos))
            g_log.debug("incomplete segment: {} ".format(stream))
            g_log.debug("received chunk: {} ".format(byte_chunk))
            continue

        g_log.debug("pos: {} | {}".format(frame1_start_pos, frame2_start_pos))

        if (frame2_start_pos != -1):
            # frame2_start_pos could be smaller than frame1_start_pos
            if frame2_start_pos < frame1_start_pos:
                # start over with the stream from frame1 pos
                stream = stream[frame1_start_pos:len(stream)]
                continue

            # we have found at least two complete telegrams
            regex = binascii.unhexlify('28'+g_supplier.frame1_start_bytes_hex+'7c'+g_supplier.frame2_start_bytes_hex+'29')  # re = '(..|..)'
            l = re.split(regex, stream)
            l = list(filter(None, l))  # remove empty elements
            # l after split (here in following example in hex)
            # l = ['68fafa68', '53ff00...faecc16', '68727268', '53ff...3d16', '68fafa68', '53ff...d916', '68727268', '53ff.....']

            g_log.debug(binascii.hexlify(stream))
            g_log.debug(l)

            # take the first two matching telegrams
            for i, el in enumerate(l):
                if el == g_supplier.frame1_start_bytes:
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

    dec = Decrypt(g_supplier, frame1, frame2, g_cfg.get_key_hex_string())
    dec.parse_all()

    g_log.info("1.8.0: {}".format(str(dec.get_act_energy_pos_kwh())))
    g_log.info("2.8.0: {}".format(str(dec.get_act_energy_neg_kwh())))

    # export solarview
    if g_cfg.get_export_format() == 'SOLARVIEW':
        exp = Exporter(g_cfg.get_export_file_abspath(), g_cfg.get_export_format())
        exp.set_value(Obis.RealEnergyIn_S, dec.get_act_energy_pos_kwh())
        exp.set_value(Obis.RealEnergyOut_S, dec.get_act_energy_neg_kwh())
        if not exp.write_out():
            g_log.error("Could not export data")
            sys.exit(50)

    # export mqtt
    if g_cfg.get_export_format() == 'MQTT':
        mqtt_pub_ret = mqtt_client.publish("{}/RealEnergyIn_S".format(g_cfg.get_export_mqtt_basetopic()), dec.get_act_energy_pos_kwh())
        g_log.debug("MQTT: Publish message: rc: {} mid: {}".format(mqtt_pub_ret[0], mqtt_pub_ret[1]))
        mqtt_pub_ret = mqtt_client.publish("{}/RealEnergyOut_S".format(g_cfg.get_export_mqtt_basetopic()), dec.get_act_energy_neg_kwh())
        g_log.debug("MQTT: Publish message: rc: {} mid: {}".format(mqtt_pub_ret[0], mqtt_pub_ret[1]))

