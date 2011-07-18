# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://www.osor.eu/eupl
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
# WiFiSimpleConfig.py - parse or generate Wi-Fi configuration data
#

import nfc.ndef
import struct
import re

class WiFiConfigData(object):
    authentication_types = {
        'Open'              : 0x0001,
        'WPA-Personal'      : 0x0002,
        'Shared'            : 0x0004, 
        'WPA-Enterprise'    : 0x0008,
        'WPA2-Enterprise'   : 0x0010,
        'WPA2-Personal'     : 0x0020,
        'WPA/WPA2-Personal' : 0x0022
    }
    _auth_type_values = \
        dict([(v,k) for k,v in authentication_types.iteritems()])

    encryption_types = {
        'None'              : 0x0001,
        'WEP'               : 0x0002,
        'TKIP'              : 0x0004, 
        'AES'               : 0x0008,
        'AES/TKIP'          : 0x000c,
    }
    _encr_type_values = \
        dict([(v,k) for k,v in encryption_types.iteritems()])

    def __init__(self, ssid='', key='', mac_address='00:00:00:00:00:00'):
        self._version = (2, 0)
        self.ssid = ssid
        self.authentication = "WPA-Personal"
        self.encryption = "AES"
        self.network_key = key
        self.mac_address = mac_address
        self._other = list()

    @property
    def version(self):
        return self._version

    @property
    def ssid(self):
        return self._ssid

    @ssid.setter
    def ssid(self, value):
        if type(value) != type(str()):
            raise ValueError("ssid value must be a string")
        self._ssid = value

    @property
    def mac_address(self):
        return ':'.join(['%02x' % ord(x) for x in self._mac_addr])

    @mac_address.setter
    def mac_address(self, value):
        if not type(value) == type(str()):
            raise ValueError("mac_address value must be a string")
        if not re.match(r'([\da-fA-F]{2}:){5}[\da-fA-F]{2}$', value):
            raise ValueError("mac_address format is '00:00:00:00:00:00'")
        self._mac_addr = value.replace(':','').decode('hex')

    @property
    def authentication(self):
        return self._auth_type

    @authentication.setter
    def authentication(self, value):
        if not type(value) == type(str()):
            raise ValueError("value must be a string")
        if not value in WiFiConfigData.authentication_types:
            raise ValueError("must be one of authentication_types")
        self._auth_type = value

    @property
    def encryption(self):
        return self._encr_type

    @encryption.setter
    def encryption(self, value):
        if not type(value) == type(str()):
            raise ValueError("value must be a string")
        if not value in WiFiConfigData.encryption_types:
            raise ValueError("must be one of encryption_types")
        self._encr_type = value

    @property
    def network_key(self):
        return self._key

    @network_key.setter
    def network_key(self, value):
        if not type(value) == type(str()):
            raise ValueError("value must be a string")
        self._key = value

    @property
    def other_attributes(self):
        return self._other

    def tostring(self):
        string  = struct.pack('>2HB', 0x1026, 1, 0x0001)
        string += struct.pack('>2H', 0x1045, len(self.ssid)) + self.ssid
        string += struct.pack('>3H', 0x1003, 0x0002, 
            WiFiConfigData.authentication_types[self.authentication])
        string += struct.pack('>3H', 0x100F, 0x0002, 
            WiFiConfigData.encryption_types[self.encryption])
        string += struct.pack('>2H', 0x1027, len(self._key)) + self._key
        string += struct.pack('>2H6s', 0x1020, 6, self._mac_addr)
        string  = struct.pack('>2H', 0x100E, len(string)) + string
        return '\x10\x4A\x00\x01\x10' + string + '\x10\x67\x00\x01\x20'

    @staticmethod
    def fromstring(string):
        def TLV(string):
            Type, Length = struct.unpack_from('>2H', string)
            Value = string[4:4+Length]
            return Type, Length, Value, string[4+Length:]
            
        cfg = WiFiConfigData()

        # first attribute must be a Version TLV with value 1.0
        Type, Length, Value, string = TLV(string)
        if Type != 0x104A or Length != 1 or Value != '\x10':
            raise ValueError("expected Version1 attribute")
        cfg._version = (1, 0)

        # second attribute must be a Credential TLV
        Type, Length, credential, string = TLV(string)
        if Type != 0x100E:
            raise ValueError("expected Credential attribute")

        while len(credential):
            Type, Length, Value, credential = TLV(credential)
            if Type == 0x1045:
                cfg.ssid = Value
            elif Type == 0x1003:
                Value, = struct.unpack('>H', Value)
                cfg.authentication = WiFiConfigData._auth_type_values[Value]
            elif Type == 0x100F:
                Value, = struct.unpack('>H', Value)
                cfg.encryption = WiFiConfigData._encr_type_values[Value]
            elif Type == 0x1027:
                cfg.network_key = Value
            elif Type == 0x1020:
                cfg._mac_addr = Value

        if len(string):
            Type, Length, Value, string = TLV(string)
            if Type == 0x1067 and Length == 1:
                cfg._version = (ord(Value) >> 4, ord(Value) & 0x0F)
            else:
                cfg._other.append((Type, Value))

        while len(string):
            Type, Length, Value, string = TLV(string)
            cfg._other.append((Type, Value))

        return cfg

class WiFiPasswordData(object):
    def __init__(self):
        self._version = (2, 0)
        self._pkhash = None
        self._passid = None
        self._devpwd = None
        self._other = list()

    @property
    def version(self):
        return self._version

    @property
    def public_key_hash(self):
        return self._pkhash

    @public_key_hash.setter
    def public_key_hash(self, value):
        if not type(value) == type(str()):
            raise ValueError("public key hash must be a string")
        if not len(value) == 20:
            raise ValueError("public key hash length must be 20 byte")
        self._pkhash = value

    @property
    def device_password_id(self):
        return self._passid

    @device_password_id.setter
    def device_password_id(self, value):
        if not type(value) == type(int()):
            raise ValueError("device password id must be an integer")
        if not (value > 0x000F and value <= 0xFFFF):
            raise ValueError("device password id range is 16-65536")
        self._passid = value

    @property
    def device_password(self):
        return self._devpwd

    @device_password.setter
    def device_password(self, value):
        if not type(value) == type(str()):
            raise ValueError("device password must be a string")
        if not (len(value) >= 16 and len(value) <= 32):
            raise ValueError("device password must be 16 to 32 characters")
        self._devpwd = value

    @property
    def other_attributes(self):
        return self._other

    def tostring(self):
        string  = '\x10\x4A\x00\x01\x10'
        string += struct.pack('>HH', 0x102C, 22 + len(self._devpwd))
        string += self._pkhash + struct.pack('>H', self._passid) + self._devpwd
        string += struct.pack('>HHB', 0x1067, 1, 0x20)
        for opt in self._other:
            string += struct.pack('>HH', opt[0], len(opt[1])) + opt[1]
        return string

    @staticmethod
    def fromstring(string):
        def TLV(string):
            Type, Length = struct.unpack_from('>2H', string)
            Value = string[4:4+Length]
            return Type, Length, Value, string[4+Length:]
            
        pwd = WiFiPasswordData()

        # first attribute must be a Version TLV with value 1.0
        Type, Length, Value, string = TLV(string)
        if Type != 0x104A or Length != 1 or Value != '\x10':
            raise ValueError("expected Version1 attribute")
        pwd._version = (1, 0)

        # second attribute must be a OOB Device Password TLV
        Type, Length, Value, string = TLV(string)
        if Type != 0x102C:
            raise ValueError("expected OOB Device Password")
        if Length < 22+16 or Length > 58:
            raise ValueError("invalid OOB Device Password")
        pwd._pkhash = Value[0:20]
        pwd._passid = struct.unpack_from('>H', Value, 20)[0]
        pwd._devpwd = Value[22:]

        if len(string):
            Type, Length, Value, string = TLV(string)
            if Type == 0x1067 and Length == 1:
                pwd._version = (ord(Value) >> 4, ord(Value) & 0x0F)
            else:
                pwd._other.append((Type, Value))

        while len(string):
            Type, Length, Value, string = TLV(string)
            pwd._other.append((Type, Value))

        return pwd
