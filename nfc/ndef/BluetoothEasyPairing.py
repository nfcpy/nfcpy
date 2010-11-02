# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
#
# BluetoothEasyPairing.py - parse or generate bluetooth configuration data
#
import nfc.ndef
import struct
import re

class BluetoothConfigData(object):
    def __init__(self, device_address=None):
        if device_address is None:
            self.bdaddr = '\x00\x00\x00\x00\x00\x00'
        else:
            self.device_address = device_address
        self._cod = None
        self._sp_hash = None
        self._sp_rand = None
        self._short_name = None
        self._long_name = None

    @property
    def device_address(self):
        return ':'.join(['%02x' % ord(x) for x in self._bdaddr])

    @device_address.setter
    def device_address(self, value):
        if not type(value) == type(str()):
            raise ValueError("device address value must be a string")
        if not re.match(r'([\da-fA-F]{2}:){5}[\da-fA-F]{2}$', value):
            raise ValueError("device address format is '00:00:00:00:00:00'")
        self._bdaddr = ''.join([x for x in value.replace(':','').decode('hex')])


    @property
    def class_of_device(self):
        # just return the raw 3 byte string as received
        return self._cod

    @class_of_device.setter
    def class_of_device(self, value):
        # no check here, you'll need to know what to encode
        self._cod = value

    @property
    def simple_pairing_hash(self):
        return [ord(x) for x in list(self._sp_hash)] if self._sp_hash else []

    @simple_pairing_hash.setter
    def simple_pairing_hash(self, value):
        if type(tuple(value)) == type(tuple()) and len(value) == 16:
            self._sp_hash = ''.join([chr(x) for x in value])
        else: raise ValueError("hash must be a list of 16 bytes")

    @property
    def simple_pairing_randomizer(self):
        return [ord(x) for x in list(self._sp_rand)] if self._sp_rand else []

    @simple_pairing_randomizer.setter
    def simple_pairing_randomizer(self, value):
        if type(tuple(value)) == type(tuple()) and len(value) == 16:
            self._sp_rand = ''.join([chr(x) for x in value])
        else: raise ValueError("randomizer must be a list of 16 bytes")

    @property
    def short_name(self):
        return self._short_name if self._short_name else ""

    @short_name.setter
    def short_name(self, value):
        if not type(value) == type(str()):
            raise ValueError("short name value must be a string")
        self._short_name = value

    @property
    def long_name(self):
        return self._long_name if self._long_name else ""

    @long_name.setter
    def long_name(self, value):
        if not type(value) == type(str()):
            raise ValueError("long name value must be a string")
        self._long_name = value

    def tostring(self):
        string = self._bdaddr
        if self._cod:
            string += chr(0x04) + '\x0D' + self._cod
        if self._sp_hash:
            string += chr(0x11) + '\x0E' + self._sp_hash
        if self._sp_rand:
            string += chr(0x11) + '\x0F' + self._sp_rand
        if self._short_name:
            string += chr(len(self._short_name)+1) + '\x08' + self._short_name
        if self._long_name:
            string += chr(len(self._long_name)+1) + '\x09' + self._long_name
        return struct.pack('<H', 2 + len(string)) + string

    @staticmethod
    def fromstring(string):
        cfg = BluetoothConfigData()
        oob_length, = struct.unpack_from('<H', string)
        cfg._bdaddr = string[2:8]
        offset = 8
        while offset < oob_length - 8:
            eir_length = ord(string[offset])
            eir_type = ord(string[offset+1])
            if eir_type == 0x0D and eir_length == 4:
                # class of device
                cfg._cod = string[offset+2:offset+5]
                offset += 5
            elif eir_type == 0x0E and eir_length == 17:
                # simple pairing hash
                cfg._sp_hash = string[offset+2:offset+18]
                offset += 18
            elif eir_type == 0x0F and eir_length == 17:
                # simple pairing randomizer
                cfg._sp_rand = string[offset+2:offset+18]
                offset += 18
            elif eir_type == 0x08:
                # short user friendly name
                cfg._short_name = string[offset+2:offset+eir_length+1]
                offset += eir_length+1
            elif eir_type == 0x09:
                # long user friendly name
                cfg._long_name = string[offset+2:offset+eir_length+1]
                offset += eir_length+1
            else:
                offset += 1 + eir_length
        return cfg

