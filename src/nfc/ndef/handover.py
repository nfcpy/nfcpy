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
# handover.py - Connection Handover Messages
#

import logging
log = logging.getLogger(__name__)

import io
import struct
from record import Record, RecordList
from message import Message
from error import *
from bt_record import BluetoothConfigRecord
from wifi_record import WifiConfigRecord

def parse_carrier_structure(ac_record, records):
    carrier_record = records.get(ac_record.carrier_data_reference)
    if carrier_record is None:
        s = "carrier data reference {0} links to nowhere"
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
            s = "auxiliary data reference {0} links to nowhere"
            log.warning(s.format(ac_record.carrier_data_reference))
            raise DecodeError("orphaned auxiliary data reference")
        carrier.auxiliary_data_records.append(aux_data_record)
    return carrier

# ------------------------------------------------------ HandoverRequestMessage
class HandoverRequestMessage(object):
    """The handover request message is used in the the NFC Connection
    Handover protocol to send proposals for alternative carriers to a
    peer device.

    :param message: a parsed message with type 'urn:nfc:wkt:Hr'
    :param version: a '<major-number>.<minor-number>' version string
    :type message: :class:`nfc.ndef.Message`
    :type version: :class:`str`

    Either the `message` or `version` argument must be supplied. A
    :exc:`ValueError` is raised if both arguments are present or absent.

    The `message` argument must be a parsed NDEF message with,
    according to the Connection Handover Specification, at least two
    records. The first record, and thus the message, must match the
    NFC Forum Well-Known Type 'urn:nfc:wkt:Hr'.

    The version argument indicates the Connection Handover version
    that shall be used for encoding the handover request message NDEF
    data. It is currently limited to major-version '1' and
    minor-version '0' to '15' and for any other value a
    :exc:`ValueError` exception is raised.
    
    >>> nfc.ndef.HandoverRequestMessage(nfc.ndef.Message(ndef_message_data))
    >>> nfc.ndef.HandoverRequestMessage(version='1.2')
    """
    def __init__(self, message=None, version=None):
        if message is None and version is None:
            raise ValueError("a message or version argument is required")
        if message is not None and version is not None:
            raise ValueError("only one of message or version argument allowed")
        
        self._name = ''
        self._type = 'urn:nfc:wkt:Hr'
        self._carriers = list()
        self._nonce = None
        
        if message is not None:
            hr_record = HandoverRequestRecord(message[0])
            self._name = hr_record.name
            self._version = hr_record.version
            self._nonce = hr_record.nonce
            records = dict([(record.name, record) for record in message[1:]])
            for ac_record in hr_record.carriers:
                carrier = parse_carrier_structure(ac_record, records)
                if carrier: self.carriers.append(carrier)

        if version is not None:
            major, minor = [int(c) for c in version.split('.')]
            if major != 1 or minor not in range(16):
                raise ValueError("version not in range 1.0 to 1.15")
            self._version = Version(chr(major << 4 | minor))

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
        """The message type. This is a read-only attribute which
        returns the NFC Forum Well-Known Type 'urn:nfc:wkt:Hr'"""
        return self._type
    
    @property
    def name(self):
        """The message name (identifier). Corresponds to the name of the
        handover request record."""
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
    
    @property
    def version(self):
        """Connection Handover version number that the messsage
        complies to. A read-only :class:`~nfc.ndef.handover.Version`
        object that provides the major and minor version :class:`int`
        values."""        
        return self._version

    @property
    def nonce(self):
        """A nonce received or to be send as the random number for
        handover request collision resolution. This attribute is
        supported only since version 1.2."""
        return self._nonce
    
    @nonce.setter
    def nonce(self, value):
        self._nonce = value
    
    @property
    def carriers(self):
        """List of alternative carriers. Each entry is an
        :class:`~nfc.ndef.handover.Carrier` object that holds
        properties of the alternative carrier. Use :meth:`add_carrier`
        to expand this list."""
        return self._carriers
    
    def add_carrier(self, carrier_record, power_state, aux_data_records=None):
        """Add a new carrier to the handover request message.

        :param carrier_record: a record providing carrier information
        :param power_state: a string describing the carrier power state
        :param aux_data_records: list of auxiliary data records
        :type carrier_record: :class:`nfc.ndef.Record`
        :type power_state: :class:`str`
        :type aux_data_records: :class:`~nfc.ndef.record.RecordList`
        
        >>> hr = nfc.ndef.HandoverRequestMessage(version="1.2")
        >>> hr.add_carrier(some_carrier_record, "active")
        """
        carrier = Carrier(carrier_record, power_state)
        if aux_data_records is not None:
            for aux in RecordList(aux_data_records):
                carrier.auxiliary_data_records.append(aux)
        self.carriers.append(carrier)

    def pretty(self, indent=0):
        """Returns a string with a formatted representation that might
        be considered pretty-printable."""
        indent = indent * ' '
        lines = list()
        version_string = "{v.major}.{v.minor}".format(v=self.version)
        lines.append(("handover version", version_string))
        if self.nonce:
            lines.append(("collision nonce", str(self.nonce)))
        for index, carrier in enumerate(self.carriers):
            lines.append(("carrier {0}:".format(index+1),))
            lines.append((indent + "power state", carrier.power_state))
            if carrier.record.type == "urn:nfc:wkt:Hc":
                carrier_type = carrier.record.carrier_type
                carrier_data = carrier.record.carrier_data
                lines.append((indent + "carrier type", carrier_type))
                lines.append((indent + "carrier data", repr(carrier_data)))
            else:
                if carrier.type == "application/vnd.bluetooth.ep.oob":
                    carrier_record = BluetoothConfigRecord(carrier.record)
                elif carrier.type == "application/vnd.wfa.wsc":
                    carrier_record = WifiConfigRecord(carrier.record)
                else:
                    carrier_record = carrier.record
                lines.append((indent + "carrier type", carrier.type))
                pretty_lines = carrier_record.pretty(2).split('\n')
                lines.extend([tuple(l.split(' = ')) for l in pretty_lines
                              if not l.strip().startswith("identifier")])
            for record in carrier.auxiliary_data_records:
                lines.append((indent + "auxiliary data",))
                lines.append((2*indent + "record type", record.type))
                lines.append((2*indent + "record data", repr(record.data)))
        
        lwidth = max([len(line[0]) for line in lines])
        lines = [(line[0].ljust(lwidth),) + line[1:] for line in lines]
        lines = [" = ".join(line) for line in lines]
        return ("\n").join([indent + line for line in lines])
    
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
            if self.version.major != 1:
                raise DecodeError("unsupported major version")
            if self.version >= Version('\x12'):
                record = Record(data=f)
                if record.type == "urn:nfc:wkt:cr":
                    self.nonce = struct.unpack(">H", record.data)[0]
                else:
                    s = "cr record is required for version {v.major}.{v.minor}"
                    raise FormatError(s.format(v=self.version))
            while f.tell() < len(string):
                record = Record(data=f)
                if record.type == 'urn:nfc:wkt:ac':
                    carrier = AlternativeCarrier(record.data)
                    self.carriers.append(carrier)
                else:
                    s = "skip unknown local record {0}"
                    log.warning(s.format(record.type))

    def pretty(self, indent=0):
        indent = indent * ' '
        lines = list()
        version_string = "{v.major}.{v.minor}".format(v=self.version)
        lines.append(("handover version", version_string))
        if self.nonce:
            lines.append(("collision nonce", str(self.nonce)))
        for index, carrier in enumerate(self.carriers):
            lines.append(("carrier {0}:".format(index+1),))
            reference = carrier.carrier_data_reference
            lines.append((indent + "reference", repr(reference)))
            lines.append((indent + "power state", carrier.carrier_power_state))
            if len(carrier.auxiliary_data_reference_list) > 0:
                lines.append((indent + "auxiliary data",))
                for aux_data_ref in carrier.auxiliary_data_reference_list:
                    lines.append((2*indent + "reference", repr(aux_data_ref)))
        
        lwidth = max([len(line[0]) for line in lines])
        lines = [(line[0].ljust(lwidth),) + line[1:] for line in lines]
        lines = [" = ".join(line) for line in lines]
        return ("\n").join([indent + line for line in lines])
    
# ------------------------------------------------------- HandoverSelectMessage
class HandoverSelectMessage(object):
    """The handover select message is used in the the NFC Connection
    Handover protocol to send agreements for alternative carriers to a
    peer device as response to a handover request message.

    :param message: a parsed message with type 'urn:nfc:wkt:Hs'
    :param version: a '<major-number>.<minor-number>' version string
    :type message: :class:`nfc.ndef.Message`
    :type version: :class:`str`

    Either the `message` or `version` argument must be supplied. A
    :exc:`ValueError` is raised if both arguments are present or absent.

    The `message` argument must be a parsed NDEF message with,
    according to the Connection Handover Specification, at least one
    record. The first record, and thus the message, must match the
    NFC Forum Well-Known Type 'urn:nfc:wkt:Hs'.

    The version argument indicates the Connection Handover version
    that shall be used for encoding the handover select message NDEF
    data. It is currently limited to major-version '1' and
    minor-version '0' to '15' and for any other value a
    :exc:`ValueError` exception is raised.
    
    >>> nfc.ndef.HandoverSelectMessage(nfc.ndef.Message(ndef_message_data))
    >>> nfc.ndef.HandoverSelectMessage(version='1.2')
    """
    def __init__(self, message=None, version=None):
        if message is None and version is None:
            raise ValueError("a message or version argument is required")
        if message is not None and version is not None:
            raise ValueError("only one of message or version argument allowed")
        
        self._name = ''
        self._type = 'urn:nfc:wkt:Hs'
        self._carriers = list()
        self._error = HandoverError()
        if message is not None:
            hs_record = HandoverSelectRecord(message[0])
            self._name = hs_record.name
            self._version = hs_record.version
            self._error = hs_record.error
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
        """The message type. This is a read-only attribute which
        returns the NFC Forum Well-Known Type 'urn:nfc:wkt:Hs'"""
        return self._type
    
    @property
    def name(self):
        """The message name (identifier). Corresponds to the name of the
        handover select record."""
        return self._name

    @name.setter
    def name(self, value):
        self._name = value
    
    @property
    def version(self):
        """Connection Handover version number that the messsage
        complies to. A read-only :class:`~nfc.ndef.handover.Version`
        object that provides the major and minor version :class:`int`
        values."""        
        return self._version

    @property
    def error(self):
        """A :class:`~nfc.ndef.handover.HandoverError` structure that
        provides error reason and data received or to be send with the
        handover select message. An ``error.reason`` value of 0 means
        that no error was received or is to be send."""
        return self._error

    @property
    def carriers(self):
        """List of alternative carriers. Each entry is an
        :class:`~nfc.ndef.handover.Carrier` object that holds
        properties of the alternative carrier. Use :meth:`add_carrier`
        to expand this list."""
        return self._carriers
    
    def add_carrier(self, carrier_record, power_state, aux_data_records=[]):
        """Add a new carrier to the handover select message.

        :param carrier_record: a record providing carrier information
        :param power_state: a string describing the carrier power state
        :param aux_data_records: list of auxiliary data records
        :type carrier_record: :class:`nfc.ndef.Record`
        :type power_state: :class:`str`
        :type aux_data_records: :class:`~nfc.ndef.record.RecordList`
        
        >>> hs = nfc.ndef.HandoverSelectMessage(version="1.2")
        >>> hs.add_carrier(some_carrier_record, "active")
        """
        carrier = Carrier(carrier_record, power_state)
        for aux in aux_data_records:
            carrier.auxiliary_data_records.append(aux)
        self.carriers.append(carrier)
    
    def pretty(self, indent=0):
        """Returns a string with a formatted representation that might
        be considered pretty-printable."""
        indent = indent * ' '
        lines = list()
        version_string = "{v.major}.{v.minor}".format(v=self.version)
        lines.append(("handover version", version_string))
        if self.error.reason:
            lines.append(("error reason", self.error.reason))
            lines.append(("error value", self.error.value))
        for index, carrier in enumerate(self.carriers):
            lines.append(("carrier {0}:".format(index+1),))
            lines.append((indent + "power state", carrier.power_state))
            if carrier.record.type == "urn:nfc:wkt:Hc":
                carrier_type = carrier.record.carrier_type
                carrier_data = carrier.record.carrier_data
                lines.append((indent + "carrier type", carrier_type))
                lines.append((indent + "carrier data", repr(carrier_data)))
            else:
                if carrier.type == "application/vnd.bluetooth.ep.oob":
                    carrier_record = BluetoothConfigRecord(carrier.record)
                elif carrier.type == "application/vnd.wfa.wsc":
                    carrier_record = WifiConfigRecord(carrier.record)
                else:
                    carrier_record = carrier.record
                lines.append((indent + "carrier type", carrier.type))
                pretty_lines = carrier_record.pretty(2).split('\n')
                lines.extend([tuple(l.split(' = ')) for l in pretty_lines
                              if not l.strip().startswith("identifier")])
            for record in carrier.auxiliary_data_records:
                lines.append((indent + "auxiliary data",))
                lines.append((2*indent + "record type", record.type))
                lines.append((2*indent + "record data", repr(record.data)))

        lwidth = max([len(line[0]) for line in lines])
        lines = [(line[0].ljust(lwidth),) + line[1:] for line in lines]
        lines = [" = ".join(line) for line in lines]
        return ("\n").join([indent + line for line in lines])
    
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
            if self.version.major != 1:
                raise DecodeError("unsupported major version")
            while f.tell() < len(string):
                record = Record(data=f)
                if record.type == 'urn:nfc:wkt:ac':
                    carrier = AlternativeCarrier(record.data)
                    self.carriers.append(carrier)
                elif record.type == 'urn:nfc:wkt:err':
                    self.error = HandoverError(record.data)
                else:
                    s = "skip unknown local record {0}"
                    log.warning(s.format(record.type))

    def pretty(self, indent=0):
        indent = indent * ' '
        lines = list()
        version_string = "{v.major}.{v.minor}".format(v=self.version)
        lines.append(("handover version", version_string))
        if self.error.reason:
            lines.append(("error reason", self.error.reason))
            lines.append(("error value", self.error.value))
        for index, carrier in enumerate(self.carriers):
            lines.append(("carrier {0}:".format(index+1),))
            reference = carrier.carrier_data_reference
            lines.append((indent + "reference", repr(reference)))
            lines.append((indent + "power state", carrier.carrier_power_state))
            if len(carrier.auxiliary_data_reference_list) > 0:
                lines.append((indent + "auxiliary data",))
                for aux_data_ref in carrier.auxiliary_data_reference_list:
                    lines.append((2*indent + "reference", repr(aux_data_ref)))
        
        lwidth = max([len(line[0]) for line in lines])
        lines = [(line[0].ljust(lwidth),) + line[1:] for line in lines]
        lines = [" = ".join(line) for line in lines]
        return ("\n").join([indent + line for line in lines])
    
# ------------------------------------------------------- HandoverCarrierRecord
class HandoverCarrierRecord(Record):
    """The handover carrier record is used to identify an alternative
    carrier technology in a handover request message when no carrier
    configuration data shall be transmitted.
    
    :param carrier_type: identification of an alternative carrier
    :param carrier_data: additional alternative carrier information
    :type carrier_type: :class:`str`
    :type carrier_data: :class:`str`

    >>> nfc.ndef.HandoverCarrierRecord('application/vnd.bluetooth.ep.oob')
    """
    def __init__(self, carrier_type, carrier_data=None):
        super(HandoverCarrierRecord, self).__init__('urn:nfc:wkt:Hc')
        if isinstance(carrier_type, Record):
            record = carrier_type
            if record.type == self.type:
                self.name = record.name
                self.data = record.data
            else:
                raise ValueError("record type mismatch")
        else:
            self._carrier_type = carrier_type
            self._carrier_data = '' if carrier_data is None else carrier_data

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
            self._carrier_type = rec.type
            self._carrier_data = f.read()

    @property
    def carrier_type(self):
        """Identification of an alternative carrier. A string
        formatted as an NFC Forum Well-Known or External Type or
        Internet Media Type or absolute URI. This attribute is
        read-only."""
        return self._carrier_type

    @property
    def carrier_data(self):
        """An octet string that provides additional information about
        the alternative carrier."""
        return self._carrier_data
    
    @carrier_data.setter
    def carrier_data(self, value):
        self._carrier_data = value
    
    def pretty(self, indent=0):
        indent = indent * ' '
        lines = list()
        lines.append(("identifier", repr(self.name)))
        lines.append(("carrier type", self.carrier_type))
        lines.append(("carrier data", repr(self.carrier_data)))        
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])
    
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
            log.warning("not all data consumed in ac record payload")
                
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
        self._reason = None
        self._data = None
        if payload is not None:
            self.decode(payload)

    @property
    def reason(self):
        """The error reason. An 8-bit unsigned integer."""
        return self._reason

    @reason.setter
    def reason(self, value):
        self._reason = value
        
    @property
    def data(self):
        """The error data. An 8-bit unsigned integer if :attr:`reason`
        is 1 or 3, a 32-bit unsigned integer if :attr:`reason` is 2.
        """
        return self._data
    
    @data.setter
    def data(self, value):
        self._data = value
        
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
                log.warning("unknown error reason value {0}"
                            .format(self.reason))
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
    
#---------------------------------------------------------------------- Version
class Version(object):
    def __init__(self, c='\x00'):
        self._major = ord(c) >> 4
        self._minor = ord(c) & 15

    @property
    def major(self):
        """Major version number. A read-only attribute."""
        return self._major
    
    @property
    def minor(self):
        """Mainor version number. A read-only attribute."""
        return self._minor
    
    def __cmp__(self, other):
        if self.major == other.major:
            return self.minor - other.minor
        else:
            return self.major - other.major
  
    def __str__(self):
        return chr((self.major << 4) | (self.minor & 0x0f))

#---------------------------------------------------------------------- Carrier
class Carrier(object):
    def __init__(self, record=None, power_state=None):
        self._record = record
        self._power_state = power_state
        self._auxiliary_data_records = list()

    @property
    def type(self):
        """The alternative carrier type name, equivalent to
        :attr:`Carrier.record.type` or
        :attr:`Carrier.record.carrier_type` if the carrier is
        specified as a :class:`HandoverCarrierRecord`."""
        return self.record.type if self.record.type != "urn:nfc:wkt:Hc" \
            else self.record.carrier_type
        
    @property
    def record(self):
        """A carrier configuration record. Recognized and further
        interpreted records are: :class:`HandoverCarrierRecord`,
        :class:`BluetoothConfigRecord`, :class:`WifiConfigRecord`,
        :class:`WifiPasswordRecord`."""
        return self._record
        
    @property
    def power_state(self):
        """The carrier power state. This may be one of the following
        strings: "inactive", "active", "activating", or "unknown"."""
        return self._power_state
        
    @property
    def auxiliary_data_records(self):
        """A list of auxiliary data records providing additional
        carrier information."""
        return self._auxiliary_data_records

#------------------------------------------------------------------------------
def read_octet_sequence(f):
    length = ord(f.read(1))
    string = f.read(length)
    if len(string) < length:
        s = "expected octet sequence of length {0} but got just {1}"
        log.error(s.format(length, len(string)))
        raise FormatError("octet sequence length error")
    return string

