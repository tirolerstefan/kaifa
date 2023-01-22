#/usr/bin/python3

import sys
import re
import serial
import binascii
from Cryptodome.Cipher import AES
import json
import signal
import logging
import paho.mqtt.client as mqtt
from influxdb_client import Point, InfluxDBClient, WriteOptions

# global logging object will be initialized after config is parsed
g_log = None

#
# Trap docker STOP
#
def signal_handler(sig, frame):
    #print('Container stopped!')
    g_log.error("Container stopped!")
    g_ser.close()
    sys.exit(0)

# create signal handler
signal.signal(signal.SIGTERM, signal_handler)

class Logger:
    def __init__(self, level):
        self._level = level
        self._logger = None

    def init(self):
        self._logger = logging.getLogger('kaifa')
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter('%(asctime)s [%(levelname)s]:  %(message)s')
        handler.setFormatter(formatter)
        self._logger.addHandler(handler)
        self._logger.setLevel(logging.DEBUG)
        self._logger.info("KAIFA smart meter reader started")
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

class SupplierKSMWest(Supplier):
    name = "KSMWest" #Kooperation Smart Meter West
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

    def get_supplier(self):
        return str(self._config["supplier"])

    def get_file_export_enabled(self):
        if not "file_export_enabled" in self._config:
            return None
        else:
            return self._config["file_export_enabled"]

    def get_file_export_abspath(self):
        if not "file_export_abspath" in self._config:
            return None
        else:
            return self._config["file_export_abspath"]

    def get_file_export_values(self):
        if not "file_export_values" in self._config:
            return None
        else:
            return self._config["file_export_values"]

    def get_mqtt_enabled(self):
        if not "mqtt_enabled" in self._config:
            return None
        else:
            return self._config["mqtt_enabled"]

    def get_mqtt_server(self):
        if not "mqtt_server" in self._config:
            return None
        else:
            return self._config["mqtt_server"]

    def get_mqtt_port(self):
        if not "mqtt_port" in self._config:
            return None
        else:
            return self._config["mqtt_port"]

    def get_mqtt_user(self):
        if not "mqtt_user" in self._config:
            return None
        else:
            return self._config["mqtt_user"]

    def get_mqtt_password(self):
        if not "mqtt_password" in self._config:
            return None
        else:
            return self._config["mqtt_password"]

    def get_mqtt_basetopic(self):
        if not "mqtt_basetopic" in self._config:
            return None
        else:
            return self._config["mqtt_basetopic"]

    def get_mqtt_values(self):
        if not "mqtt_values" in self._config:
            return None
        else:
            return self._config["mqtt_values"]

    def get_influxdb_enabled(self):
        if not "influxdb_enabled" in self._config:
            return None
        else:
            return self._config["influxdb_enabled"]

    def get_influxdb_url(self):
        if not "influxdb_url" in self._config:
            return None
        else:
            return self._config["influxdb_url"]

    def get_influxdb_token(self):
        if not "influxdb_token" in self._config:
            return None
        else:
            return self._config["influxdb_token"]

    def get_influxdb_org(self):
        if not "influxdb_org" in self._config:
            return None
        else:
            return self._config["influxdb_org"]

    def get_influxdb_bucket(self):
        if not "influxdb_bucket" in self._config:
            return None
        else:
            return self._config["influxdb_bucket"]

    def get_influxdb_measurement(self):
        if not "influxdb_measurement" in self._config:
            return None
        else:
            return self._config["influxdb_measurement"]

    def get_influxdb_values(self):
        if not "influxdb_values" in self._config:
            return None
        else:
            return self._config["influxdb_values"]

class Obis:
    def to_bytes(code):
        return bytes([int(a) for a in code.split(".")])
    VoltageL1 = {
        "pos": "32.7.0",
        "byte": to_bytes("01.0.32.7.0.255"),
        "desc_name": "Voltage L1",
        "unit": "V",
        "mod": "round(self.obis[d['byte']],2)",
        "field_name": "VoltageL1_V"
    }
    VoltageL2 = {
        "pos": "52.7.0",
        "byte": to_bytes("01.0.52.7.0.255"),
        "desc_name": "Voltage L2",
        "unit": "V",
        "mod": "round(self.obis[d['byte']],2)",
        "field_name": "VoltageL2_V"
    }
    VoltageL3 = {
        "pos": "72.7.0",
        "byte": to_bytes("01.0.72.7.0.255"),
        "desc_name": "Voltage L3",
        "unit": "V",
        "mod": "round(self.obis[d['byte']],2)",
        "field_name": "VoltageL3_V"
    }
    CurrentL1 = {
        "pos": "31.7.0",
        "byte": to_bytes("1.0.31.7.0.255"),
        "desc_name": "Current L1",
        "unit": "A",
        "mod": "round(self.obis[d['byte']],2)",
        "field_name": "CurrentL1_A"
    }
    CurrentL2 = {
        "pos": "51.7.0",
        "byte": to_bytes("1.0.51.7.0.255"),
        "desc_name": "Current L2",
        "unit": "A",
        "mod": "round(self.obis[d['byte']],2)",
        "field_name": "CurrentL2_A"
    }
    CurrentL3 = {
        "pos": "71.7.0",
        "byte": to_bytes("1.0.71.7.0.255"),
        "desc_name": "Current L3",
        "unit": "A",
        "mod": "round(self.obis[d['byte']],2)",
        "field_name": "CurrentL3_A"
    }
    RealPowerIn = {
        "pos": "1.7.0",
        "byte": to_bytes("1.0.1.7.0.255"),
        "desc_name": "Instantaneous Power In",
        "unit": "W",
        "mod": None,
        "field_name": "InstantaneousPowerIn_W"
    }
    RealPowerOut = {
        "pos": "2.7.0",
        "byte": to_bytes("1.0.2.7.0.255"),
        "desc_name": "Instantaneous Power Out",
        "unit": "W",
        "mod": None,
        "field_name": "InstantaneousPowerOut_W"
    }
    RealEnergyIn = {
        "pos": "1.8.0",
        "byte": to_bytes("1.0.1.8.0.255"),
        "desc_name": "Active Energy In",
        "unit": "Wh",
        "mod": None,
        "field_name": "ActiveEnergyIn_Wh"
    }
    RealEnergyOut = {
        "pos": "2.8.0",
        "byte": to_bytes("1.0.2.8.0.255"),
        "desc_name": "Active Energy Out",
        "unit": "Wh",
        "mod": None,
        "field_name": "ActiveEnergyOut_Wh"
    }
    ReactiveEnergyInductive = {
        "pos": "3.8.0",
        "byte": to_bytes("1.0.3.8.0.255"),
        "desc_name": "Reactive Energy Inductive",
        "unit": "W",
        "mod": None,
        "field_name": "ReactiveEnergyInductive_var"
    }
    ReactiveEnergyCapacitive = {
        "pos": "4.8.0",
        "byte": to_bytes("1.0.4.8.0.255"),
        "desc_name": "Reactive Energy Capacitive",
        "unit": "W",
        "mod": None,
        "field_name": "ReactiveEnergyCapacitive_var"
    }
    PowerFactor = {
        "pos": "13.7.0",
        "byte": to_bytes("01.0.13.7.0.255"),
        "desc_name": "Power Factor",
        "unit": "",
        "mod": "round(self.obis[d['byte']],3)",
        "field_name": "PowerFactor"
    }
    DateAndTime = {
        "pos": "0.1.0",
        "byte": to_bytes("0.0.1.0.0.255"),
        "desc_name": "Date and Time",
        "unit": "",
        "mod": None,
        "field_name": "DateAndTime"
    }
    DeviceNumber = {
        "pos": "0.96.1",
        "byte": to_bytes("0.0.96.1.0.255"),
        "desc_name": "Device Number",
        "unit": "",
        "mod": None,
        "field_name": "DeviceNumber"
    }
    DeviceName = {
        "pos": "0.42.0",
        "byte": to_bytes("0.0.42.0.0.255"),
        "desc_name": "Device Name",
        "unit": "",
        "mod": None,
        "field_name": "DeviceName"
    }

class Exporter:
    def __init__(self, file):
        self._file = file
        self._export_map = {}

    def set_value(self, obis_string, value, unit):
        self._export_map[obis_string] = {}
        self._export_map[obis_string]["value"] = value
        self._export_map[obis_string]["unit"] = unit

    def _write_out_solarview(self, file):
        file.write("/?!\n")       # Start bytes
        file.write("/KAIFA\n")    # Meter ID

        for key in self._export_map.keys():
            # e.g. 1.8.0(005305.034*kWh)
            file.write("{}({:010.3F}*{})\n".format(key,self._export_map[key]['value'], self._export_map[key]['unit']))

        file.write("!\n")         # End byte

    def write_out(self):
        try:
            with open(self._file, "w") as f:
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

    def parse_all(self):
        try:
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
            return True
        except Exception as e:
            g_log.error("Failed to decrypt data: " + str(e))
            return False

    def get_generic_name(self, name):
        d = getattr(Obis, name)
        if 'desc_name' in d:
            return d['desc_name']
        else:
            return None

    def get_generic_position(self, name):
        d = getattr(Obis, name)
        if 'pos' in d:
            return d['pos']
        else:
            return None

    def get_generic_unit(self, name):
        d = getattr(Obis, name)
        if 'unit' in d:
            return d['unit']
        else:
            return None

    def get_generic_value(self, name):
        d = getattr(Obis, name)
        if d['byte'] in self.obis:
            if d['mod'] != None:
                return(eval(d['mod']))
            else:
                return self.obis[d['byte']]
        else:
            return None

    def get_generic_field_name(self, name):
        d = getattr(Obis, name)
        if 'field_name' in d:
            return d['field_name']
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
serial_timeout=1

g_cfg = Config(Constants.config_file)

if not g_cfg.load():
    print("Could not load config file")
    sys.exit(10)

g_log = Logger(g_cfg.get_loglevel())

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
        timeout = serial_timeout)

if g_cfg.get_supplier().lower() == SupplierKSMWest.name.lower():
    g_supplier = SupplierKSMWest()
elif g_cfg.get_supplier().lower() == SupplierEVN.name.lower():
    g_supplier = SupplierEVN()
else:
    raise Exception("Supplier not supported: {}".format(g_cfg.get_supplier()))

# connect to mqtt broker
if g_cfg.get_mqtt_enabled():
    try:
        mqtt_client = mqtt.Client("kaifareader", clean_session=False)
        mqtt_client.on_connect = mqtt_on_connect
        mqtt_client.on_disconnect = mqtt_on_disconnect
        mqtt_client.username_pw_set(g_cfg.get_mqtt_user(), g_cfg.get_mqtt_password())
        mqtt_client.connect(g_cfg.get_mqtt_server(), port=g_cfg.get_mqtt_port(), keepalive=7)
        mqtt_client.loop_start()
    except Exception as e:
        print("Failed to connect to mqtt server: " + str(e))
        sys.exit(40)

# connect to influxdb
if g_cfg.get_influxdb_enabled():
    try:
        influxdb_client = InfluxDBClient(url=g_cfg.get_influxdb_url(), token=g_cfg.get_influxdb_token(), org=g_cfg.get_influxdb_org())
        influxdb_write_api = influxdb_client.write_api()
        g_log.info("influxdb: Client connected")
    except Exception as e:
        print("Failed to connect to influxdb: " + str(e))
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
        if (frame1_start_pos < 0 or frame2_start_pos <= 0 or stream[-1:] != g_supplier.frame2_end_bytes):
            g_log.debug("pos: {} | {}".format(frame1_start_pos, frame2_start_pos))
            g_log.debug("incomplete segment: {} ".format(binascii.hexlify(stream).upper()))
            g_log.debug("received chunk: {} ".format(binascii.hexlify(byte_chunk).upper()))
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
    if not dec.parse_all():
        continue

    for key, value in g_cfg.get_file_export_values().items():
        if value and dec.get_generic_value(key) != None:
            g_log.info("{0:6}: {1:26}: {2:10}".format(dec.get_generic_position(key),dec.get_generic_name(key)+" ("+dec.get_generic_unit(key)+")",str(dec.get_generic_value(key))))

    # file export
    if g_cfg.get_file_export_enabled():
        exp = Exporter(g_cfg.get_file_export_abspath())
        for key, value in g_cfg.get_file_export_values().items():
            if value and dec.get_generic_value(key) != None:
                exp.set_value(dec.get_generic_position(key), dec.get_generic_value(key), dec.get_generic_unit(key))
        if not exp.write_out():
            g_log.error("Could not export data")
            sys.exit(50)

    # export mqtt
    if g_cfg.get_mqtt_enabled():
        for key, value in g_cfg.get_mqtt_values().items():
            if value and dec.get_generic_value(key) != None:
                mqtt_pub_ret = mqtt_client.publish("{}/{}".format(g_cfg.get_mqtt_basetopic(),dec.get_generic_field_name(key)), dec.get_generic_value(key))
                g_log.debug("MQTT: Publish message: rc: {} mid: {}".format(mqtt_pub_ret[0], mqtt_pub_ret[1]))

    # export influxdb
    if g_cfg.get_influxdb_enabled():
        p = Point(g_cfg.get_influxdb_measurement())
        fields = 0
        for key, value in g_cfg.get_influxdb_values().items():
            if value and dec.get_generic_value(key) != None:
                p.field(dec.get_generic_field_name(key), dec.get_generic_value(key))
                fields += 1
        if fields > 0:
            influxdb_write_api.write(bucket=g_cfg.get_influxdb_bucket(), org=g_cfg.get_influxdb_org(), record=p)
            g_log.debug("influxdb: Published values")
