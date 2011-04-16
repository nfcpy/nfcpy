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
# record.py -- contains the base class for NDEF records
#
# BUGS:
#   - does not handle chunked records
#   - does not control validity of parsed string
import logging
log = logging.getLogger(__name__)

from struct import pack, unpack
import re

type_prefix = ('', 'urn:nfc:wkt:', '', '', 'urn:nfc:ext:',
               'application/octet-stream', '', '')

class Record(object):
    def __init__(self, initializer=None):
        if initializer is None:
            initializer = ('', '', '')
        if isinstance(initializer, Record):
            self.type = initializer.type
            self.name = initializer.name
            self.data = initializer.data
        else:
            self.type, self.name, self.data = initializer

    @staticmethod
    def fromstring(string):
        header_flags = ord(string[0])
        mbf = bool(header_flags & 0x80)
        mef = bool(header_flags & 0x40)
        cff = bool(header_flags & 0x20)
        srf = bool(header_flags & 0x10)
        ilf = bool(header_flags & 0x08)
        tnf  = header_flags & 0x07

        type_length = ord(string[1])
        data_length = ord(string[2]) if srf else unpack('>L', string[2:6])[0]
        name_length = ord(string[3 if srf else 6]) if ilf else 0
        offset = (3 if srf else 6) + int(ilf)

        if offset + type_length + name_length + data_length > len(string):
            log.error("insufficient data for ndef record extraction")
        
        record_type = string[offset:offset+type_length]; offset += type_length
        record_name = string[offset:offset+name_length]; offset += name_length
        record_data = string[offset:offset+data_length]; offset += data_length
        
        record_type = type_prefix[tnf] + record_type

        record = Record()
        record._type = record_type
        record._name = record_name
        record._data = record_data

        return record, string[offset:]

    def tostring(self, message_begin=False, message_end=False):
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
        elif record_type.startswith("application/octet-stream"):
            header_flags = 5; record_type = record_type[24:]

        type_length = len(record_type)
        data_length = len(record_data)
        name_length = len(record_name)

        if message_begin:
            header_flags |= 0x80
        if message_end:
            header_flags |= 0x40
        if data_length < 256:
            header_flags |= 0x10
        if name_length > 0:
            header_flags |= 0x08

        string  = chr(header_flags)
        string += chr(type_length)
        if data_length < 256: string += chr(data_length)
        else: string += pack('>L', data_length)
        string += chr(name_length) if name_length > 0 else ''

        return string + record_type + record_name + record_data

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    def __str__(self):
        return "%s,%s,%s" % (self.type, self.name, self.data.encode('hex'))


