# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
# bt_record.py - Bluetooth Configuration Record
#

import logging
log = logging.getLogger(__name__)

import io
import struct
from uuid import UUID
from record import Record
from error import *

class BluetoothConfigRecord(Record):
    def __init__(self, record=None):
        Record.__init__(self, 'application/vnd.bluetooth.ep.oob')
        self.device_address = '00:00:00:00:00:00'
        self.eir = dict()
        if record is not None:
            if not record.type == self.type:
                raise ValueError("record type mismatch")
            self.name = record.name
            self.data = record.data

    @property
    def data(self):
        f = io.BytesIO()
        f.write(str(bytearray(reversed(self._bdaddr))))
        for key, value in self.eir.iteritems():
            f.write(chr(1 + len(value)) + chr(key) + str(value))
        oob_length = 2 + f.tell()
        f.seek(0,0)
        return struct.pack('<H', oob_length) + f.read()
    
    @data.setter
    def data(self, string):
        log.debug("parse '{0}' record".format(self.type))
        if len(string) > 0:
            f = io.BytesIO(string)
            oob_length = struct.unpack_from('<H', f.read(2))[0]
            log.debug("bluetooth oob length {0}".format(oob_length))
            if oob_length > len(string):
                log.warning("OOB data length exceeds payload length")
                oob_length = len(string)
            self._bdaddr = bytearray(reversed(f.read(6)))
            while f.tell() < oob_length:
                eir_length = ord(f.read(1))
                eir_type = ord(f.read(1))
                self.eir[eir_type] = f.read(eir_length-1)
    
    @property
    def device_address(self):
        """Bluetooth device address. A string of hexadecimal
        characters with 8-bit quantities spearated by colons and the
        most significant byte first. For example, the device address
        ``'01:23:45:67:89:AB'`` corresponds to ``0x0123456789AB``."""
        return ':'.join(["{0:02X}".format(x) for x in self._bdaddr])

    @device_address.setter
    def device_address(self, value):
        self._bdaddr = bytearray(value.replace(':', '').decode("hex"))
        assert len(self._bdaddr) == 6

    @property
    def local_device_name(self):
        """Bluetooth Local Name encoded as sequence of characters in
        the given order. Received as complete (EIR type 0x09) or
        shortened (EIR type 0x08) local name. Transmitted as complete
        local name. Set to None if not received or not to be
        transmitted."""
        try: return self.eir[0x09]
        except KeyError: return self.eir.get(0x08, None)

    @local_device_name.setter
    def local_device_name(self, value):
        self.eir[0x09] = value
        
    @property
    def simple_pairing_hash(self):
        """Simple Pairing Hash C. Received and transmitted as EIR type
        0x0E. Set to None if not received or not to be transmitted.
        Raises nfc.ndef.DecodeError if the received value or
        nfc.ndef.EncodeError if the assigned value is not a sequence
        of 16 octets."""
        try:
            if len(self.eir[0x0E]) != 16:
                raise DecodeError("wrong length of simple pairing hash")
            return bytearray(self.eir[0x0E])
        except KeyError:
            return None

    @simple_pairing_hash.setter
    def simple_pairing_hash(self, value):
        if value is None:
            self.eir.pop(0x0E, None)
        else:
            if len(value) != 16:
                raise EncodeError("wrong length of simple pairing hash")
            self.eir[0x0E] = str(bytearray(value))

    @property
    def simple_pairing_rand(self):
        """Simple Pairing Randomizer R. Received and transmitted as
        EIR type 0x0F. Set to None if not received or not to be
        transmitted. Raises nfc.ndef.DecodeError if the received value
        or nfc.ndef.EncodeError if the assigned value is not a
        sequence of 16 octets."""
        try:
            if len(self.eir[0x0F]) != 16:
                raise DecodeError("wrong length of simple pairing hash")
            return bytearray(self.eir[0x0F])
        except KeyError:
            return None

    @simple_pairing_rand.setter
    def simple_pairing_rand(self, value):
        if value is None:
            self.eir.pop(0x0F, None)
        else:
            if len(value) != 16:
                raise EncodeError("wrong length of simple pairing randomizer")
            self.eir[0x0F] = str(bytearray(value))

    @property
    def service_class_uuid_list(self):
        """Listq of Service Class UUIDs. Set and retrieved as a list
        of complete 128-bit UUIDs. Decoded from and encoded as EIR
        types 0x02/0x03 (16-bit partial/complete UUIDs), 0x04/0x05
        (32-bit partial/complete UUIDs), 0x06/0x07 (128-bit
        partial/complete UUIDs)."""
        L = list()
        try: uuid_list = self.eir[0x03]
        except KeyError: uuid_list = self.eir.get(0x02, '')
        for x in struct.unpack("<"+"H"*(len(uuid_list)/2), uuid_list):
            L.append("{0:08x}-0000-1000-8000-00805f9b34fb".format(x))
        try: uuid_list = self.eir[0x05]
        except KeyError: uuid_list = self.eir.get(0x04, '')
        for x in struct.unpack("<"+"L"*(len(uuid_list)/4), uuid_list):
            L.append("{0:08x}-0000-1000-8000-00805f9b34fb".format(x))
        try: uuid_list = self.eir[0x07]
        except KeyError: uuid_list = self.eir.get(0x06, '')
        for i in range(0, len(uuid_list), 16):
            L.append(str(UUID(bytes_le=uuid_list[i:i+16])))
        return L

    @service_class_uuid_list.setter
    def service_class_uuid_list(self, value):
        bt_uuid = UUID("00000000-0000-1000-8000-00805f9b34fb")
        for item in value:
            uuid = UUID(item)
            if uuid.bytes[4:16] == bt_uuid.bytes[4:16]:
                if uuid.bytes[0:2] == "\x00\x00":
                    self.eir[0x03] = self.eir.setdefault(0x03, '') + \
                        uuid.bytes[2:4][::-1]
                else:
                    self.eir[0x05] = self.eir.setdefault(0x05, '') + \
                        uuid.bytes[0:4][::-1]
            else:
                self.eir[0x07] = self.eir.setdefault(0x07, '') + \
                    uuid.bytes_le

    @property
    def class_of_device(self):
        """Class of Device encoded as unsigned long integer. Received
        and transmitted as EIR type 0x0D in little endian byte
        order. Set to None if not received or not to be
        transmitted."""
        try: return int(self.eir[0x0D][::-1].encode("hex"), 16)
        except KeyError: return None

    @class_of_device.setter
    def class_of_device(self, value):        
        self.eir[0x0D] = struct.pack('<L', value)[0:3]
        
    def pretty(self, indent=0):
        lines = list()
        if self.name:
            lines.append(("identifier", repr(self.name)))
        lines.append(("device address", self.device_address))
        if self.local_device_name:
            lines.append(("device name", self.local_device_name))
        if self.class_of_device:
            cod = self.class_of_device
            if cod & 0x003 == 0:
                lines.append(("device class", decode_class_of_device(cod)))
                msc = [major_service_class[mask]
                       for mask in sorted(major_service_class)
                       if self.class_of_device >> 13 & mask]
                lines.append(("major service", ", ".join(msc)))
            else:
                lines.append(("class of device", "{0:b}".format(cod)))
        if self.simple_pairing_hash:
            simple_pairing_hash = str(self.simple_pairing_hash)
            lines.append(("pubkey hash", simple_pairing_hash.encode("hex")))
        if self.simple_pairing_rand:
            simple_pairing_rand = str(self.simple_pairing_rand)
            lines.append(("randomizer", simple_pairing_rand.encode("hex")))
        for service_class_uuid in self.service_class_uuid_list:
            try: service_class = service_class_uuid_map[service_class_uuid]
            except KeyError: service_class = service_class_uuid
            lines.append(("service class", service_class))
        for key, value in self.eir.items():
            if key not in (3, 5, 7, 8, 9, 13, 14, 15):
                lines.append(("EIR 0x%02x" % key, repr(value)))
        
        indent = indent * ' '
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])

def decode_class_of_device(cod):
    mdc, sdc = cod >> 8 & 0x1f, cod >> 2 & 0x3f
    if mdc == 0:
        mdc = "Miscellaneous"
        sdc = "{0:06b}".format(sdc)
    elif mdc == 1:
        mdc = "Computer"
        minor_device_class = (
            "Uncategorized",
            "Desktop workstation",
            "Server-class computer",
            "Laptop",
            "Handheld PC/PDA (clam shell)",
            "Palm sized PC/PDA",
            "Wearable computer (Watch sized)")
        try: sdc = minor_device_class[sdc]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 2:
        mdc = "Phone"
        minor_device_class = (
            "Uncategorized",
            "Cellular",
            "Cordless",
            "Smart phone",
            "Wired modem or voice gateway",
            "Common ISDN Access")
        try: sdc = minor_device_class[sdc]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 3:
        mdc = "Access Point"
        minor_device_class = (
            "fully available",
            "1 - 17% utilized",
            "17 - 33% utilized",
            "33 - 50% utilized",
            "50 - 67% utilized",
            "67 - 83% utilized",
            "83 - 99% utilized",
            "no service available")
        try: sdc = minor_device_class[sdc >> 3]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 4:
        mdc = "Audio/Video"
        minor_device_class = (
            "Uncategorized",
            "Wearable Headset Device",
            "Hands-free Device",
            "Reserved",
            "Microphone",
            "Loudspeaker",
            "Headphones",
            "Portable Audio",
            "Car audio",
            "Set-top box",
            "HiFi Audio Device",
            "VCR",
            "Video Camera",
            "Camcorder",
            "Video Monitor",
            "Video Display and Loudspeaker",
            "Video Conferencing",
            "Reserved",
            "Gaming/Toy")
        try: sdc = minor_device_class[sdc]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 5:
        mdc = "Peripheral"
        minor_device_class = (
            "uncategorized",
            "joystick",
            "gamepad",
            "remote control",
            "sensing device",
            "digitizer tablet",
            "card reader",
            "digital pen",
            "handheld scanner",
            "handheld pointer")
        kbd_mouse = ("", " keyboard", " mouse", " keyboard/mouse")[sdc >> 4]
        try: sdc = minor_device_class[sdc & 0x0f]
        except IndexError: sdc = "{0:06b}".format(sdc)
        sdc = sdc + kbd_mouse
    elif mdc == 6:
        mdc = "Imaging"
        minor_device_class = {
            0b0001: "display",
            0b0010: "camera",
            0b0100: "scanner",
            0b1000: "printer"}
        sdc = ', '.join([minor_device_class[mask]
                         for mask in minor_device_class
                         if sdc >> 2 & mask])
    elif mdc == 7:
        mdc = "Wearable"
        minor_device_class = (
            "Wrist Watch",
            "Pager",
            "Jacket",
            "Helmet",
            "Glasses")
        try: sdc = minor_device_class[sdc & 0x0f]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 8:
        mdc = "Toy"
        minor_device_class = (
            "Robot",
            "Vehicle",
            "Doll / Action Figure",
            "Controller",
            "Game")
        try: sdc = minor_device_class[sdc & 0x0f]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 9:
        mdc = "Health"
        minor_device_class = (
            "Undefined",
            "Blood Pressure Monitor",
            "Thermometer",
            "Weighing Scale",
            "Glucose Meter",
            "Pulse Oximeter",
            "Heart/Pulse Rate Monitor",
            "Health Data Display",
            "Step Counter",
            "Body Composition Analyzer",
            "Peak Flow Monitor",
            "Medication Monitor",
            "Knee Prosthesis",
            "Ankle Prosthesis",
            "Generic Health Manager",
            "Personal Mobility Device")
        try: sdc = minor_device_class[sdc & 0x0f]
        except IndexError: sdc = "{0:06b}".format(sdc)
    elif mdc == 31:
        mdc = "Uncategorized"
        sdc = "{0:06b}".format(sdc)
    else:
        mdc = "{0:05b}".format(mdc)
        sdc = "{0:06b}".format(sdc)
        
    return "{0} ({1})".format(mdc, sdc)

major_service_class = {
    0b00000000001: "Limited Discoverable Mode",
    0b00000000010: "reserved (bit 14)",
    0b00000000100: "reserved (bit 15)",
    0b00000001000: "Positioning",
    0b00000010000: "Networking",
    0b00000100000: "Rendering",
    0b00001000000: "Capturing",
    0b00010000000: "Object Transfer",
    0b00100000000: "Audio",
    0b01000000000: "Telephony",
    0b10000000000: "Information"}

service_class_uuid_map = {
    "00001000-0000-1000-8000-00805f9b34fb": "Service Discovery Server",
    "00001001-0000-1000-8000-00805f9b34fb": "Browse Group Descriptor",
    "00001101-0000-1000-8000-00805f9b34fb": "Serial Port",
    "00001102-0000-1000-8000-00805f9b34fb": "LAN Access Using PPP",
    "00001103-0000-1000-8000-00805f9b34fb": "Dialup Networking",
    "00001104-0000-1000-8000-00805f9b34fb": "IrMC Sync",
    "00001105-0000-1000-8000-00805f9b34fb": "OBEX Object Push",
    "00001106-0000-1000-8000-00805f9b34fb": "OBEX File Transfer",
    "00001107-0000-1000-8000-00805f9b34fb": "IrMC Sync Command",
    "00001108-0000-1000-8000-00805f9b34fb": "Headset",
    "00001109-0000-1000-8000-00805f9b34fb": "Cordless Telephony",
    "0000110a-0000-1000-8000-00805f9b34fb": "Audio Source",
    "0000110b-0000-1000-8000-00805f9b34fb": "Audio Sink",
    "0000110c-0000-1000-8000-00805f9b34fb": "A/V Remote Control Target",
    "0000110d-0000-1000-8000-00805f9b34fb": "Advanced Audio Distribution",
    "0000110e-0000-1000-8000-00805f9b34fb": "A/V Remote Control",
    "0000110f-0000-1000-8000-00805f9b34fb": "A/V Remote Control Controller",
    "00001110-0000-1000-8000-00805f9b34fb": "Intercom",
    "00001111-0000-1000-8000-00805f9b34fb": "Fax",
    "00001112-0000-1000-8000-00805f9b34fb": "Headset - Audio Gateway (AG)",
    "00001113-0000-1000-8000-00805f9b34fb": "WAP",
    "00001114-0000-1000-8000-00805f9b34fb": "WAP Client",
    "00001115-0000-1000-8000-00805f9b34fb": "PANU",
    "00001116-0000-1000-8000-00805f9b34fb": "NAP",
    "00001117-0000-1000-8000-00805f9b34fb": "GN",
    "00001118-0000-1000-8000-00805f9b34fb": "Direct Printing",
    "00001119-0000-1000-8000-00805f9b34fb": "Reference Printing",
    "0000111a-0000-1000-8000-00805f9b34fb": "Basic Imaging Profile",
    "0000111b-0000-1000-8000-00805f9b34fb": "Imaging Responder",
    "0000111c-0000-1000-8000-00805f9b34fb": "Imaging Automatic Archive",
    "0000111d-0000-1000-8000-00805f9b34fb": "Imaging Referenced Objects",
    "0000111e-0000-1000-8000-00805f9b34fb": "Handsfree",
    "0000111f-0000-1000-8000-00805f9b34fb": "Handsfree Audio Gateway",
    "00001120-0000-1000-8000-00805f9b34fb": "Direct Printing Reference",
    "00001121-0000-1000-8000-00805f9b34fb": "Reflected UI",
    "00001122-0000-1000-8000-00805f9b34fb": "Basic Printing",
    "00001123-0000-1000-8000-00805f9b34fb": "Printing Status",
    "00001124-0000-1000-8000-00805f9b34fb": "Human Interface Device",
    "00001125-0000-1000-8000-00805f9b34fb": "Hardcopy Cable Replacement",
    "00001126-0000-1000-8000-00805f9b34fb": "HCR Print",
    "00001127-0000-1000-8000-00805f9b34fb": "HCR Scan",
    "00001128-0000-1000-8000-00805f9b34fb": "Common ISDN Access",
    "0000112d-0000-1000-8000-00805f9b34fb": "SIM Access",
    "0000112e-0000-1000-8000-00805f9b34fb": "Phonebook Access - PCE",
    "0000112f-0000-1000-8000-00805f9b34fb": "Phonebook Access - PSE",
    "00001130-0000-1000-8000-00805f9b34fb": "Phonebook Access",
    "00001131-0000-1000-8000-00805f9b34fb": "Headset - HS",
    "00001132-0000-1000-8000-00805f9b34fb": "Message Access Server",
    "00001133-0000-1000-8000-00805f9b34fb": "Message Notification Server",
    "00001134-0000-1000-8000-00805f9b34fb": "Message Access Profile",
    "00001135-0000-1000-8000-00805f9b34fb": "GNSS",
    "00001136-0000-1000-8000-00805f9b34fb": "GNSS Server",
    "00001200-0000-1000-8000-00805f9b34fb": "PnP Information",
    "00001201-0000-1000-8000-00805f9b34fb": "Generic Networking",
    "00001202-0000-1000-8000-00805f9b34fb": "Generic File Transfer",
    "00001203-0000-1000-8000-00805f9b34fb": "Generic Audio",
    "00001204-0000-1000-8000-00805f9b34fb": "Generic Telephony",
    "00001205-0000-1000-8000-00805f9b34fb": "UPNP Service",
    "00001206-0000-1000-8000-00805f9b34fb": "UPNP IP Service",
    "00001300-0000-1000-8000-00805f9b34fb": "ESDP UPNP IP PAN",
    "00001301-0000-1000-8000-00805f9b34fb": "ESDP UPNP IP LAP",
    "00001302-0000-1000-8000-00805f9b34fb": "ESDP UPNP L2CAP",
    "00001303-0000-1000-8000-00805f9b34fb": "Video Source",
    "00001304-0000-1000-8000-00805f9b34fb": "Video Sink",
    "00001305-0000-1000-8000-00805f9b34fb": "Video Distribution",
    "00001400-0000-1000-8000-00805f9b34fb": "HDP",
    "00001401-0000-1000-8000-00805f9b34fb": "HDP Source",
    "00001402-0000-1000-8000-00805f9b34fb": "HDP Sink",
    }

