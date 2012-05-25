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
#
# record.py -- base class for NDEF records
#
# BUGS:
#   - does not handle chunked records
#   - does not control validity of parsed string

import logging
log = logging.getLogger(__name__)

import nfc.ndef
import struct
import io
import re

type_name_prefix = (
    '', 'urn:nfc:wkt:', '', '', 'urn:nfc:ext:', 'unknown', 'unchanged')
    
class Record(object):
    """Represents an NDEF (NFC Data Exchange Format) record."""
    
    def __init__(self, record_type=None, record_name=None, data=None):
        self._message_begin = self._message_end = False
        self._type = self._name = self._data = ''
        if not (record_type is None and record_name is None):
            self.type = record_type if record_type is not None else 'unknown'
            if record_name is not None:
                self.name = record_name
            if data is not None:
                self.data = data
        elif data is not None:
            if isinstance(data, (bytearray, str)):
                data = io.BytesIO(data)
            if isinstance(data, io.IOBase):
                self._read(data)
            else:
                raise TypeError("invalid data argument type")

    def _read(self, f):
        """Parse an NDEF record from a file-like object."""
        
        try:
            self.header = ord(f.read(1))
        except TypeError:
            log.error("buffer underflow at offset {0}".format(f.tell()))
            raise nfc.ndef.LengthError("insufficient data to parse")
        
        mbf = bool(self.header & 0x80)
        mef = bool(self.header & 0x40)
        cff = bool(self.header & 0x20)
        srf = bool(self.header & 0x10)
        ilf = bool(self.header & 0x08)
        tnf = self.header & 0x07

        try:
            type_length = ord(f.read(1))
            if srf: # short record
                data_length = ord(f.read(1))
            else: # 32-bit length
                struct.unpack('>L', f.read(4))[0]
            if ilf: # id length present
                name_length = ord(f.read(1))
            else:
                name_length = 0
        except (TypeError, struct.error):
            log.error("buffer underflow at offset {0}".format(f.tell()))
            raise nfc.ndef.LengthError("insufficient data to parse")

        try:
            record_type = f.read(type_length)
            assert len(record_type) == type_length
            record_name = f.read(name_length)
            assert len(record_name) == name_length
            record_data = f.read(data_length)
            assert len(record_data) == data_length
        except AssertionError:
            log.error("buffer underflow at offset {0}".format(f.tell()))
            raise nfc.ndef.LengthError("insufficient data to parse")

        self._message_begin, self._message_end = mbf, mef
        self._type = bytearray(type_name_prefix[tnf] + record_type)
        self._name = bytearray(record_name)
        self._data = bytearray(record_data)
        log.debug("parsed {0}".format(repr(self)))

    def _write(self, f):
        """Serialize an NDEF record to a file-like object."""
        log.debug("writing ndef record at offset {0}".format(f.tell()))

        record_type = self.type
        record_name = self.name
        record_data = self.data
        
        if record_type == '':
            header_flags = 0
        elif record_type.startswith("urn:nfc:wkt:"):
            header_flags = 1; record_type = record_type[12:]
        elif re.match(r'[a-zA-Z0-9-]+/[a-zA-Z0-9-+.]+', record_type):
            header_flags = 2; record_type = record_type
        elif re.match(r'[a-zA-Z][a-zA-Z0-9+-.]*://', record_type):
            header_flags = 3; record_type = record_type
        elif record_type.startswith("urn:nfc:ext:"):
            header_flags = 4; record_type = record_type[12:]
        elif record_type == 'unknown':
            header_flags = 5; record_type = ''
        elif record_type == 'unchanged':
            header_flags = 6; record_type = ''

        type_length = len(record_type)
        data_length = len(record_data)
        name_length = len(record_name)

        if self._message_begin:
            header_flags |= 0x80
        if self._message_end:
            header_flags |= 0x40
        if data_length < 256:
            header_flags |= 0x10
        if name_length > 0:
            header_flags |= 0x08

        if data_length < 256:
            f.write(struct.pack(">BBB", header_flags, type_length, data_length))
        else:
            f.write(struct.pack(">BBL", header_flags, type_length, data_length))
        if name_length > 0:
            f.write(struct.pack(">B", name_length))

        f.write(record_type)
        f.write(record_name)
        f.write(record_data)

    @property
    def type(self):
        """NDEF record type."""
        return str(self._type)

    @type.setter
    def type(self, value):
        value = str(value)
        if (value in ('', 'unknown', 'unchanged') or
            value.startswith("urn:nfc:wkt:") or
            value.startswith("urn:nfc:ext:") or
            re.match(r'[a-zA-Z0-9-]+/[a-zA-Z0-9-+.]+', value) or
            re.match(r'[a-zA-Z][a-zA-Z0-9+-.]*://', value)):
            self._type = bytearray(value)
        else:
            log.error("'{0}' is not an acceptable record type".format(value))
            raise ValueError("invalid record type")

    @property
    def name(self):
        """NDEF record identifier."""
        return str(self._name)

    @name.setter
    def name(self, value):
        self._name = bytearray(str(value))

    @property
    def data(self):
        """NDEF record payload."""
        return str(self._data)

    @data.setter
    def data(self, value):
        self._data = bytearray(str(value))

    def __iter__(self):
        from itertools import islice
        return islice(str(self), None)

    def __str__(self):
        stream = io.BytesIO()
        self._write(stream)
        stream.seek(0, 0)
        return stream.read()

    def __repr__(self):
        return "nfc.ndef.Record('{0}', '{1}', '{2}')".format(
            self.type.encode('string_escape'),
            self.name.encode('string_escape'),
            self.data.encode('string_escape'))

    # **************
    # * deprecated *
    # **************
    @staticmethod
    def fromstring(data):
        return Record(data=data)

    def tostring(self, message_begin=False, message_end=False):
        self._message_begin = message_begin
        self._message_end = message_end
        return str(self)

