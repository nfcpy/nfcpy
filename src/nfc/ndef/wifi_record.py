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
#
# WiFiSimpleConfig.py - parse or generate Wi-Fi configuration data
#

import logging
log = logging.getLogger(__name__)

import binascii
import io
import struct
from .record import Record
from .error import DecodeError, EncodeError

VERSION1     = b"\x10\x4A"
CREDENTIAL   = b"\x10\x0e"
AUTH_TYPE    = b"\x10\x03"
CRYPT_TYPE   = b"\x10\x0F"
MAC_ADDRESS  = b"\x10\x20"
NETWORK_IDX  = b"\x10\x26"
NETWORK_KEY  = b"\x10\x27"
NETWORK_NAME = b"\x10\x45"
OOB_PASSWORD = b"\x10\x2C"
VENDOR_EXT   = b"\x10\x49"
VENDOR_WFA   = b"\x00\x37\x2A"
VERSION2     = b"\x00"
KEY_SHAREABLE = b"\x02"

auth_type_names = {
    b'\x00\x01': b'Open',
    b'\x00\x02': b'WPA-Personal',
    b'\x00\x04': b'Shared',
    b'\x00\x08': b'WPA-Enterprise',
    b'\x00\x10': b'WPA2-Enterprise',
    b'\x00\x20': b'WPA2-Personal',
    b'\x00\x22': b'WPA/WPA2-Personal'
    }

crypt_type_names = {
        b'\x00\x01': b'None',
        b'\x00\x02': b'WEP',
        b'\x00\x04': b'TKIP',
        b'\x00\x08': b'AES',
        b'\x00\x0C': b'AES/TKIP'
    }

auth_type_keys = \
    dict([(v, k) for k, v in auth_type_names.items()])

crypt_type_keys = \
    dict([(v, k) for k, v in crypt_type_names.items()])
    
class WifiConfigRecord(Record):
    def __init__(self, record=None):
        Record.__init__(self, b'application/vnd.wfa.wsc')
        self._version = b'\x20'
        self._credentials = list()
        self._other = list()
        if record:
            if not record.type == self.type:
                raise ValueError("record type mismatch")
            self.name = record.name
            self.data = record.data
        else:
            self._credentials.append({
                    b'network-name': b'',
                    b'authentication' : b'Open',
                    b'encryption' : b'None',
                    b'network-key' : b'',
                    b'mac-address' : b'ff:ff:ff:ff:ff:ff'
                    })

    @property
    def data(self):
        f = io.BytesIO()

        if len(self.credentials) == 0:
            log.warning("no credential(s) in wifi config record")
            
        for credential in self.credentials:
            write_attribute(f, CREDENTIAL, self._write_credential(credential))
        
        vendor_wfa = [(VERSION2, self._version)]
        vendor_wfa.extend([(k, v) for k, v in self.other if len(k) == 1])
        write_attribute(f, VENDOR_EXT, VENDOR_WFA + write_elements(vendor_wfa))

        for k, v in [(k, v) for k, v in self.other if len(k) > 1]:
            write_attribute(f, k, v)
        
        f.seek(0, 0)
        return f.read()
    
    @data.setter
    def data(self, string):
        log.debug("parse '{0}' record".format(self.type))
        if len(string) > 0:
            attributes = parse_attributes(string)
            log.debug("wifi attributes: " + repr(attributes))
            for k, v in attributes:
                if k in (VERSION1, VERSION2):
                    self._version = v
                elif k == CREDENTIAL:
                    self._credentials.append(self._parse_credential(v))
                else:
                    self._other.append((k, v))
            if len(self._credentials) == 0:
                raise DecodeError("missing credential attribute")

    @property
    def version(self):
        """The WiFi Simple Configuration version, coded as a
        'major.minor' string"""
        version = ord(self._version)
        return "{0}.{1}".format(version >> 4, version & 0xF)

    @version.setter
    def version(self, value):
        try:
            major, minor = map(int, value.split('.'))
        except:
            raise TypeError("not a 'major.minor' version string")
        if major < 2 or major > 15:
            raise ValueError("major number must be in range(2,16)")
        if minor < 0 or minor > 15:
            raise ValueError("minor number must be in range(0,16)")
        self._version = struct.pack("B", (major << 4) | (minor & 0xF))

    @property
    def credentials(self):
        """A list of WiFi credentials. Each credential is a dictionary
        with any of the possible keys ``'network-name'``,
        ``'network-key'``, ``'shareable'``, ``'authentication'``,
        ``'encryption'``, ``'mac-address'``, and ``'other'``."""
        return self._credentials
        
    @property
    def credential(self):
        """The first WiFi credential. Same as
        ``WifiConfigRecord().credentials[0]``."""
        return self.credentials[0]
        
    @property
    def other(self):
        """A list of WiFi attribute (key, value) pairs other than
        version and credential(s). Keys are two character strings for
        standard WiFi attributes, one character strings for
        subelements within a WFA vendor extension attribute, and three
        character strings for other vendor ecxtension attributes."""
        return self._other

    def _parse_credential(self, s):
        attributes = parse_attributes(s)
        credential = dict()
        for k, v in attributes:
            if k == NETWORK_IDX:
                pass # attribute 'network index' is deprecated
            elif k == NETWORK_NAME:
                credential[b"network-name"] = v
            elif k == NETWORK_KEY:
                credential[b"network-key"] = v
            elif k == KEY_SHAREABLE:
                credential[b'shareable'] = bool(ord(v))
            elif k == AUTH_TYPE:
                credential[b'authentication'] = \
                    auth_type_names.get(v, binascii.hexlify(v))
            elif k == CRYPT_TYPE:
                credential[b'encryption'] = \
                    crypt_type_names.get(v, binascii.hexlify(v))
            elif k == MAC_ADDRESS:
                credential[b'mac-address'] = \
                    b':'.join([binascii.hexlify(c) for c in v])
            else:
                credential.setdefault(b'other', []).append((k, v))
        return credential

    def _write_credential(self, credential):
        f = io.BytesIO()
        try:
            network_name = credential[b'network-name']
            auth_type = credential[b'authentication']
            crypt_type = credential[b'encryption']
            network_key = credential[b'network-key']
            mac_address = credential[b'mac-address']
            shareable = credential.get(b'shareable', None)
            other = credential.get(b'other', list())
        except KeyError:
            raise EncodeError("missing required credential attribute")

        try: auth_type = auth_type_keys[auth_type]
        except KeyError: auth_type = binascii.unhexlify(auth_type)
        try: crypt_type = crypt_type_keys[crypt_type]
        except KeyError: crypt_type = binascii.unhexlify(crypt_type)
        mac_address = binascii.unhexlify(mac_address.replace(b':', b''))

        write_attribute(f, NETWORK_IDX, b'\x01')
        write_attribute(f, NETWORK_NAME, network_name)
        write_attribute(f, AUTH_TYPE, auth_type)
        write_attribute(f, CRYPT_TYPE, crypt_type)
        write_attribute(f, NETWORK_KEY, network_key)
        write_attribute(f, MAC_ADDRESS, mac_address)

        vendor_wfa = [(k, v) for k, v in other if len(k) == 1]
        if shareable is not None:
            vendor_wfa = [(KEY_SHAREABLE, struct.pack("B", int(shareable)))] + vendor_wfa
        if len(vendor_wfa) > 0:
            write_attribute(f, VENDOR_EXT, VENDOR_WFA + 
                            write_elements(vendor_wfa))

        for k, v in [(k, v) for k, v in other if len(k) > 1]:
            write_attribute(f, k, v)

        f.seek(0, 0)
        return f.read()

    def pretty(self, indent=0):
        lines = list()
        if self.name:
            lines.append(("identifier", repr(self.name)))
        lines.append(("version", self.version))
        for credential in self.credentials:
            shareable = str(credential.get(b'shareable', False))
            lines.append(("network name", credential[b'network-name']))
            lines.append(("network key", credential[b'network-key']))
            lines.append(("authentication", credential[b'authentication']))
            lines.append(("encryption", credential[b'encryption']))
            lines.append(("mac address", credential[b'mac-address']))
            lines.append(("shareable", shareable))
        for key, value in self.other:
            lines.append((key, value))
        
        indent = indent * ' '
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])
    
class WifiPasswordRecord(Record):
    def __init__(self, record=None):
        Record.__init__(self, b'application/vnd.wfa.wsc')
        self._version = b'\x20'
        self._passwords = list()
        self._other = list()
        if record:
            if not record.type == self.type:
                raise ValueError("record type mismatch")
            self.name = record.name
            self.data = record.data
        else:
            self._passwords.append({
                    b'public-key-hash': 20 * b'\x00',
                    b'password-id' : 0,
                    b'password' : b'',
                    })

    @property
    def data(self):
        f = io.BytesIO()
        write_attribute(f, VERSION1, b'\x10')

        for password in self.passwords:
            write_attribute(f, OOB_PASSWORD, self._write_password(password))
        
        vendor_wfa = [(VERSION2, self._version)]
        vendor_wfa.extend([(k, v) for k, v in self.other if len(k) == 1])
        write_attribute(f, VENDOR_EXT, VENDOR_WFA + write_elements(vendor_wfa))

        for k, v in [(k, v) for k, v in self.other if len(k) > 1]:
            write_attribute(f, k, v)
        
        f.seek(0, 0)
        return f.read()
    
    @data.setter
    def data(self, string):
        log.debug("parse '{0}' record".format(self.type))
        if len(string) > 0:
            attributes = parse_attributes(string)
            log.debug("wifi attributes: " + repr(attributes))
            for k, v in attributes:
                if k in (VERSION1, VERSION2):
                    self._version = v
                elif k == OOB_PASSWORD:
                    self._passwords.append(self._parse_password(v))
                else:
                    self._other.append((k, v))
            if len(self._passwords) == 0:
                raise DecodeError("missing password attribute")

    @property
    def version(self):
        """The WiFi Simple Configuration version, coded as a
        'major.minor' string"""
        version = ord(self._version)
        return "{0}.{1}".format(version >> 4, version & 0xF)

    @version.setter
    def version(self, value):
        try:
            major, minor = map(int, value.split('.'))
        except:
            raise TypeError("not a 'major.minor' version string")
        if major < 2 or major > 15:
            raise ValueError("major number must be in range(2,16)")
        if minor < 0 or minor > 15:
            raise ValueError("minor number must be in range(0,16)")
        self._version = struct.pack("B", (major << 4) | (minor & 0xF))

    @property
    def passwords(self):
        """A list of WiFi out-of-band device passwords. Each password
        is a dictionary with the keys ``'public-key-hash'``,
        ``'password-id'``, and ``'password'``."""
        return self._passwords
        
    @property
    def password(self):
        """The first WiFi device password. Same as
        ``WifiPasswordRecord().passwords[0]``."""
        return self.passwords[0]
        
    @property
    def other(self):
        """A list of WiFi attribute (key, value) pairs other than
        version and device password. Keys are two character strings
        for standard WiFi attributes, one character strings for
        subelements within a WFA vendor extension attribute, and three
        character strings for other vendor extension attributes."""
        return self._other

    def _parse_password(self, s):
        if len(s) < 22:
            raise DecodeError("wifi oob password less than 22 byte")
        password = dict()
        password[b'public-key-hash'] = s[0:20]
        password[b'password-id'] = struct.unpack('>H', s[20:22])[0]
        password[b'password'] = s[22:]
        return password

    def _write_password(self, password):
        f = io.BytesIO()
        try:
            pkhash = password[b'public-key-hash']
            pwd_id = password[b'password-id']
            passwd = password[b'password']
        except KeyError:
            raise EncodeError("missing required attributes in oob password")
        if len(pkhash) != 20:
            raise EncodeError("public key hash must be 20 octets")
        f.write(pkhash + struct.pack('>H', pwd_id) + passwd)
        f.seek(0, 0)
        return f.read()
        
    def pretty(self, indent=0):
        lines = list()
        if self.name:
            lines.append(("identifier", repr(self.name)))
        lines.append(("version", self.version))
        for password in self.passwords:
            public_key_hash = binascii.hexlify(password[b'public-key-hash'])
            lines.append(("public key hash", public_key_hash))
            lines.append(("password id", str(password[b'password-id'])))
            lines.append(("device password", password[b'password']))
        for key, value in self.other:
            lines.append((key, value))
        
        indent = indent * ' '
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])
    
# -------------------------------------- helper functions for attribute parsing
def parse_attribute(f):
    k, l = struct.unpack('>2sH', f.read(4))
    v = f.read(l)
    if len(v) != l:
        raise DecodeError("wsc attribute length error")
    return k, v

def parse_attributes(s):
    f = io.BytesIO(s)
    l = list()
    while f.tell() < len(s):
        k, v = parse_attribute(f)
        if k == VENDOR_EXT:
            k, v = v[:3], v[3:]
        if k == VENDOR_WFA:
            l.extend(parse_elements(v))
        else:
            l.append([k, v])
    return l

def parse_element(f):
    k, l = struct.unpack(">cB", f.read(2)); v = f.read(l)
    if len(v) != l:
        raise DecodeError("wfa subelement length error")
    return k, v

def parse_elements(s):
    f = io.BytesIO(s)
    l = list()
    while f.tell() < len(s):
        k, v = parse_element(f)
        l.append([k, v])
    return l

def write_attribute(f, k, v):
    f.write(struct.pack('>2sH', k, len(v)) + v)

def write_element(f, k, v):
    f.write(struct.pack('>cB', k, len(v)) + v)

def write_elements(kvl):
    f = io.BytesIO()
    for k, v in kvl:
        write_element(f, k, v)
    f.seek(0, 0)
    return f.read()

