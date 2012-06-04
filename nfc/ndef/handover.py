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
# handover.py - Connection Handover Messages
#

import logging
log = logging.getLogger(__name__)

import io
import struct
from record import Record
from message import Message
from error import *
from bt_record import BluetoothConfigRecord

def parse_carrier_structure(ac_record, records):
    carrier_record = records.get(ac_record.carrier_data_reference)
    if carrier_record is None:
        s = "carrier data reference {0} linked to nowhere"
        log.warning(s.format(ac_record.carrier_data_reference))
        raise DecodeError("orphaned carrier data reference")
    if carrier_record.type == "urn:nfc:wkt:Hc":
        carrier_record = HandoverCarrierRecord(carrier_record)
    elif carrier_record.type == "application/vnd.bluetooth.ep.oob":
        carrier_record = BluetoothConfigRecord(carrier_record)
    carrier = Carrier(carrier_record, ac_record.carrier_power_state)
    for aux_data_ref in ac_record.auxiliary_data_reference_list:
        aux_data_record = records.get(aux_data_ref)
        if aux_data_record is None:
            s = "auxiliary data reference {0} linked to nowhere"
            log.warning(s.format(ac_record.carrier_data_reference))
            raise DecodeError("orphaned auxiliary data reference")
        carrier.axiliary_data_records.append(aux_data_record)
    return carrier

# ------------------------------------------------------ HandoverRequestMessage
class HandoverRequestMessage(object):
    def __init__(self, message=None, version=None):
        self.name = ''
        self.carriers = list()
        self.nonce = None
        if message is not None:
            hr_record = HandoverRequestRecord(message[0])
            self.name = hr_record.name
            self._version = hr_record.version
            self.nonce = hr_record.nonce
            records = dict([(record.name, record) for record in message[1:]])
            for ac_record in hr_record.carriers:
                carrier = parse_carrier_structure(ac_record, records)
                if carrier: self.carriers.append(carrier)
        elif version is not None:
            major, minor = [int(c) for c in version.split('.')]
            if major != 1 or minor not in range(16):
                raise ValueError("version not in range 1.0 to 1.15")
            self._version = Version(chr(major << 4 | minor))
        else:
            raise TypeError("either message or version arg must be given")

    def __str__(self):
        message = Message(HandoverRequestRecord())
        message[0].name = self.name
        message[0].version = self.version
        message[0].nonce = self.nonce
        for cref, carrier in enumerate(self.carriers):
            ac = AlternativeCarrier()
            ac.carrier_power_state = carrier.power_state
            ac.carrier_data_reference = str(cref)
            carrier.record.name = ac.carrier_data_reference
            message.append(carrier.record)
            for aref, aux in enumerate(carrier.auxiliary_data_records):
                aux.name = "aux"+str(aref)
                message.append(aux)
                ac.auxiliary_data_reference_list.append(aux.name)
            message[0].carriers.append(ac)
        return str(message)
        
    @property
    def type(self):
        return 'urn:nfc:wkt:Hr'
    
    @property
    def version(self):
        return self._version
    
    def add_carrier(self, carrier_record, power_state, aux_data_records=[]):
        """Add a new carrier to the handover request message."""
        carrier = Carrier(carrier_record, power_state)
        for aux in aux_data_records:
            carrier.auxiliary_data_records.append(aux)
        self.carriers.append(carrier)
    
# ------------------------------------------------------- HandoverRequestRecord
class HandoverRequestRecord(Record):
    def __init__(self, record=None):
        super(HandoverRequestRecord, self).__init__('urn:nfc:wkt:Hr')
        self.version = Version() #: Version of the handover request record.
        self.nonce = None        #: Random number for collision resolution.
        self.carriers = []       #: Alternative carrier information list.
        if record is not None:
            if not record.type == self.type:
                raise ValueError("record type mismatch")
            self.name = record.name
            self.data = record.data

    @property
    def data(self):
        msg = Message()
        if self.version >= Version('\x12'):
            if self.nonce is None:
                raise EncodeError("collision resolution required since V1.2")
            crn = struct.pack(">H", self.nonce)
            msg.append(Record("urn:nfc:wkt:cr", data=crn))
        for carrier in self.carriers:
            msg.append(Record('urn:nfc:wkt:ac', data=str(carrier)))
        return str(self.version) + str(msg)

    @data.setter
    def data(self, string):
        log.debug("parse '{0}' record".format(self.type))
        if len(string) > 0:
            f = io.BytesIO(string)
            self.version = Version(f.read(1))
            if self.version >= Version('\x12'):
                record = Record(data=f)
                if record.type == "urn:nfc:wkt:cr":
                    self.nonce = struct.unpack(">H", record.data)[0]
                else:
                    s = "cr record is required for version {0:s}"
                    raise FormatError(s.format(self.version))
            while f.tell() < len(string):
                record = Record(data=f)
                if record.type == 'urn:nfc:wkt:ac':
                    carrier = AlternativeCarrier(record.data)
                    self.carriers.append(carrier)
                else:
                    s = "skip unknown local record {0}"
                    log.debug(s.format(record.type))

# ------------------------------------------------------- HandoverSelectMessage
class HandoverSelectMessage(object):
    def __init__(self, message=None, version=None):
        self.name = ''
        self.carriers = list()
        self.error = HandoverError()
        if message is not None:
            hs_record = HandoverSelectRecord(message[0])
            self.name = hs_record.name
            self._version = hs_record.version
            self.error = hs_record.error
            records = dict([(record.name, record) for record in message[1:]])
            for ac_record in hs_record.carriers:
                carrier = parse_carrier_structure(ac_record, records)
                if carrier: self.carriers.append(carrier)
        elif version is not None:
            major, minor = [int(c) for c in version.split('.')]
            if major != 1 or minor not in range(16):
                raise ValueError("version not in range 1.0 to 1.15")
            self._version = Version(chr(major << 4 | minor))
        else:
            raise TypeError("either message or version arg must be given")

    def __str__(self):
        message = Message(HandoverSelectRecord())
        message[0].name = self.name
        message[0].version = self.version
        message[0].error = self.error
        for cref, carrier in enumerate(self.carriers):
            ac = AlternativeCarrier()
            ac.carrier_power_state = carrier.power_state
            ac.carrier_data_reference = str(cref)
            carrier.record.name = ac.carrier_data_reference
            message.append(carrier.record)
            for aref, aux in enumerate(carrier.auxiliary_data_records):
                aux.name = "aux"+str(aref)
                message.append(aux)
                ac.auxiliary_data_reference_list.append(aux.name)
            message[0].carriers.append(ac)
        return str(message)
        
    @property
    def type(self):
        return 'urn:nfc:wkt:Hs'
    
    @property
    def version(self):
        return self._version
    
    def add_carrier(self, carrier_record, power_state, aux_data_records=[]):
        """Add a new carrier to the handover select message."""
        carrier = Carrier(carrier_record, power_state)
        for aux in aux_data_records:
            carrier.auxiliary_data_records.append(aux)
        self.carriers.append(carrier)
    
# -------------------------------------------------------- HandoverSelectRecord
class HandoverSelectRecord(Record):
    def __init__(self, record=None):
        super(HandoverSelectRecord, self).__init__('urn:nfc:wkt:Hs')
        self.version = Version()     #: Version of the handover request record.
        self.carriers = []           #: Alternative carrier information list.
        self.error = HandoverError() #: Handover select error reason and data.
        if record is not None:
            if not record.type == self.type:
                raise ValueError("record type mismatch")
            self.name = record.name
            self.data = record.data

    @property
    def data(self):
        msg = Message()
        for carrier in self.carriers:
            msg.append(Record('urn:nfc:wkt:ac', data=str(carrier)))
        if self.error.reason is not None:
            msg.append(Record("urn:nfc:wkt:err", data=str(self.error)))
        return str(self.version) + str(msg)

    @data.setter
    def data(self, string):
        log.debug("parse '{0}' record".format(self.type))
        if len(string) > 0:
            f = io.BytesIO(string)
            self.version = Version(f.read(1))
            while f.tell() < len(string):
                record = Record(data=f)
                if record.type == 'urn:nfc:wkt:ac':
                    carrier = AlternativeCarrier(record.data)
                    self.carriers.append(carrier)
                elif record.type == 'urn:nfc:wkt:err':
                    self.error = HandoverError(record.data)
                else:
                    s = "skip unknown local record {0}"
                    log.debug(s.format(record.type))

# ------------------------------------------------------- HandoverCarrierRecord
class HandoverCarrierRecord(Record):
    def __init__(self, record=None):
        super(HandoverCarrierRecord, self).__init__('urn:nfc:wkt:Hc')
        self.carrier_type = ''
        self.carrier_data = ''
        if record is not None:
            if not record.type == self.type:
                raise ValueError("record type mismatch")
            self.name = record.name
            self.data = record.data

    @property
    def data(self):
        binary = str(Record(self.carrier_type))
        ctf = chr(ord(binary[0]) & 0x07)
        carrier_type = binary[3:]
        carrier_type_length = chr(len(carrier_type))
        return ctf + carrier_type_length + carrier_type + self.carrier_data

    @data.setter
    def data(self, string):
        log.debug("parse '{0}' record".format(self.type))
        if len(string) > 0:
            f = io.BytesIO(string)
            ctf = ord(f.read(1)) & 0x07
            ctn = bytearray(read_octet_sequence(f))
            rec = Record(data=bytearray([0x10|ctf, len(ctn), 0]) + ctn)
            self.carrier_type = rec.type
            self.carrier_data = f.read()

#----------------------------------------------------------- AlternativeCarrier
class AlternativeCarrier(object):
    def __init__(self, payload=None):
        self.carrier_power_state = 'unknown'
        self.carrier_data_reference = None
        self.auxiliary_data_reference_list = list()
        if payload is not None:
            self.decode(payload)

    def __str__(self):
        return self.encode()

    def decode(self, payload):
        f = io.BytesIO(payload)
        flags = ord(f.read(1))
        self.carrier_power_state = carrier_power_states[flags & 0x03]
        self.carrier_data_reference = read_octet_sequence(f)
        self.auxiliary_data_reference_list = ord(f.read(1)) * [None]
        for i in range(len(self.auxiliary_data_reference_list)):
            self.auxiliary_data_reference_list[i] = read_octet_sequence(f)
        if f.tell() < len(payload):
            log.debug("not all data consumed in ac record payload")
                
    def encode(self):
        f = io.BytesIO()
        f.write(chr(carrier_power_states.index(self.carrier_power_state)))
        f.write(chr(len(self.carrier_data_reference)))
        f.write(self.carrier_data_reference)
        f.write(chr(len(self.auxiliary_data_reference_list)))
        for auxiliary_data_reference in self.auxiliary_data_reference_list:
            f.write(chr(len(auxiliary_data_reference)))
            f.write(auxiliary_data_reference)
        f.seek(0, 0)
        return f.read()

carrier_power_states = ("inactive", "active", "activating", "unknown")

#---------------------------------------------------------------- HandoverError
class HandoverError(object):
    def __init__(self, payload=None):
        if payload is not None:
            self.decode(payload)
        else:
            self.reason = None
            self.data = None

    def __str__(self):
        return self.encode()
    
    def decode(self, payload):
        try:
            self.reason = ord(payload[0])
            if self.reason == 1:
                self.data = ord(payload[1])
            elif self.reason == 2:
                self.data = struct.unpack(">L", payload[1:])[0]
            elif self.reason == 3:
                self.data = ord(payload[1])
            else:
                log.warning("unknown error reason value {0}".format(reason))
        except (TypeError, struct.error):
            raise DecodeError("non matching error reason and data")
    
    def encode(self):
        try: payload = chr(self.reason)
        except ValueError: raise EncodeError("error reason out of limits")
        try:
            if self.reason == 1:
                payload += chr(self.data)
            elif self.reason == 2:
                payload += struct.pack(">L", self.data)
            elif self.reason == 3:
                payload += chr(self.data)
            else:
                raise EncodeError("reserved error reason %d" % self.reason)
        except (TypeError, struct.error):
            raise EncodeError("invalid data for error reason %d" % self.reason)
        return payload
    
# ---------------------------------------------------------------------- Version
class Version(object):
    def __init__(self, c='\x00'):
        self._major = ord(c) >> 4
        self._minor = ord(c) & 15

    @property
    def major(self):
        return self._major
    
    @property
    def minor(self):
        return self._minor
    
    def __cmp__(self, other):
        if self.major == other.major:
            return self.minor - other.minor
        else:
            return self.major - other.major
  
    def __str__(self):
        return chr((self.major << 4) | (self.minor & 0x0f))

# ---------------------------------------------------------------------- Carrier
class Carrier(object):
    def __init__(self, record=None, power_state=None):
        self.record = record
        self.power_state = power_state
        self.auxiliary_data_records = list()

# -----------------------------------------------------------------------------
def read_octet_sequence(f):
    length = ord(f.read(1))
    string = f.read(length)
    if len(string) < length:
        s = "expected octet sequence of length {0} but got just {1}"
        log.error(s.format(length, len(string)))
        raise FormatError("octet sequence length error")
    return string

