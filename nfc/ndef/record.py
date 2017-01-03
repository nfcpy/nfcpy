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
# record.py -- base class for NDEF records
#
# BUGS:
#   - does not handle chunked records

import logging
log = logging.getLogger(__name__)

import struct
import io
import re

import nfc.ndef
from error import LengthError, FormatError

type_name_prefix = (
    '', 'urn:nfc:wkt:', '', '', 'urn:nfc:ext:', 'unknown', 'unchanged')
    
class Record(object):
    """Wraps an NDEF record and provides getting and setting of the
    record type name (:attr:`type`), record identifier (:attr:`name`)
    and record payload (:attr:`data`).
    
    :param record_type: NDEF record type name
    :param record_name: NDEF record identifier
    :param data: NDEF record payload or NDEF record data

    All arguments accept a :class:`str` or :class:`bytearray` object.
    
    Interpretation of the `data` argument depends on the presence of
    `record_type` and `record_name`. If any of the `record_type` or
    `record_name` argument is present, the `data` argument is
    interpreted as the record payload and copied to :attr:`data`. If
    none of the `record_type` or `record_name` argument are present,
    the `data` argument is interpreted as a NDEF record bytes (NDEF
    header and payload) and parsed.
    
    The `record_type` argument combines the NDEF TNF (Type Name
    Format) and NDEF TYPE information into a single string. The TNF
    values 0, 5 and 6 are expressed by the strings '', 'unknown' and
    'unchanged'. For TNF values 2 and 4 the `record_type` is the
    prefix 'urn:nfc:wkt:' and 'urn:nfc:ext:', respectively, followed
    by the NDEF TYPE string. TNF values 2 and 3 are not distinguished
    by regular expressions matching the either the media-type format
    'type-name/subtype-name' or absolute URI format 'scheme:hier-part'

    >>> nfc.ndef.Record('urn:nfc:wkt:T', 'id', b'\x02enHello World')
    >>> nfc.ndef.Record('urn:nfc:wkt:T', data=b'\x02enHello World')
    >>> nfc.ndef.Record(data=b'\xd1\x01\x0eT\x02enHello World')
    """
    
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
            log.debug("buffer underflow at offset {0}".format(f.tell()))
            raise LengthError("insufficient data to parse")
        
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
                data_length = struct.unpack('>L', f.read(4))[0]
            if ilf: # id length present
                name_length = ord(f.read(1))
            else:
                name_length = 0
        except (TypeError, struct.error):
            log.debug("buffer underflow at offset {0}".format(f.tell()))
            raise LengthError("insufficient data to parse")

        try:
            record_type = f.read(type_length)
            assert len(record_type) == type_length
            record_name = f.read(name_length)
            assert len(record_name) == name_length
            record_data = f.read(data_length)
            assert len(record_data) == data_length
        except AssertionError:
            log.debug("buffer underflow at offset {0}".format(f.tell()))
            raise LengthError("insufficient data to parse")

        if tnf in (0, 5, 6) and len(record_type) > 0:
            s = "ndef type name format {0} doesn't allow a type string"
            raise FormatError( s.format(tnf) )
        if tnf in (1, 2, 3, 4) and len(record_type) == 0:
            s = "ndef type name format {0} requires a type string"
            raise FormatError( s.format(tnf) )
        if tnf == 0 and len(record_data) > 0:
            s = "ndef type name format {0} doesn't allow a payload"
            raise FormatError( s.format(tnf) )
            
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
            header_flags = 0; record_name = ''; record_data = ''
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
        """The record type. A string that matches the empty string '',
        or the string 'unknown', or the string 'unchanged', or starts
        with 'urn:nfc:wkt:', or starts with 'urn:nfc:ext:', or matches
        the mime-type format, or matches the absolute-URI format."""
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
        """The record identifier as an octet string. Any type that can
        be coverted into a sequence of characters in range(0,256) can
        be assigned."""
        return str(self._name)

    @name.setter
    def name(self, value):
        self._name = bytearray(str(value))

    @property
    def data(self):
        """The record payload as an octet string. Any type that can be
        coverted into a sequence of characters in range(0,256) can be
        assigned."""
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

    def pretty(self, indent=0):
        """Returns a string with a formatted representation that might
        be considered pretty-printable. The optional argument *indent*
        specifies the amount of indentation added for each level of
        output."""
        indent = indent * ' '
        lines = list()
        lines.append((indent + "type", repr(self.type)))
        lines.append((indent + "name", repr(self.name)))
        lines.append((indent + "data", repr(self.data)))
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])
        
class RecordList(list):
    """A specialized list type that only accepts :class:`Record` objects."""

    def __init__(self, iterable=tuple()):
        super(RecordList, self).__init__()
        for item in iterable:
            self.append(item)
        
    def __setitem__(self, key, value):
        if not isinstance(value, Record):
            raise TypeError("RecordList only accepts Record objects")
        super(RecordList, self).__setitem__(key, value)

    def append(self, value):
        if not isinstance(value, Record):
            raise TypeError("RecordList only accepts Record objects")
        super(RecordList, self).append(value)

    def extend(self, iterable):
        for item in iterable:
            self.append(item)

