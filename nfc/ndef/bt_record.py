# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
        return ':'.join(["{0:02X}".format(x) for x in self._bdaddr])

    @device_address.setter
    def device_address(self, value):
        self._bdaddr = bytearray.fromhex(value.replace(':', ''))
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
        if len(value) != 16:
            raise EncodeError("wrong length of simple pairing randomizer")
        self.eir[0x0F] = str(bytearray(value))

    @property
    def service_class_uuid_list(self):
        """List of Service Class UUIDs. Items may be 16-bit and 32-bit
        Bluetooth UUIDs or global 128-bit UUIDs. Received as EIR types
        0x02/0x03 (16-bit partial/complete UUIDs), 0x04/0x05 (32-bit
        partial/complete UUIDs), 0x06/0x07 (128-bit partial/complete
        UUIDs). Transmitted as complete UUID EIR types."""
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
        
