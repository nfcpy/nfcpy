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
#

from struct import pack, unpack
import re

from nfc.ndef.Record import Record

class Message(list):
    def __init__(self, initializer):
        list.__init__(self)
        if type(initializer) == type(str()):
            self.tail = self._fromstring(initializer)
        elif isinstance(initializer, Record):
            self.append(initializer)
        elif type(initializer) == type(list()):
            if sum([not isinstance(elem, Record) for elem in initializer]):
                raise ValueError("list elements must be class Record type")
            self = initializer

    def tostring(self):
        if len(self) == 0:
            return ''

        if len(self) == 1:
            return self[0].tostring(message_begin=True, message_end=True)

        string = self[0].tostring(message_begin=True)

        for i in range(1,len(self)-1):
            string += self[i].tostring()

        return string + self[-1].tostring(message_end=True)

    def _fromstring(self, string):
        while len(string):
            message_end = bool(ord(string[0]) & 0x40)
            record, string = Record.fromstring(string)
            self.append(record)
            if message_end:
                break
        return string

    @staticmethod
    def fromstring(string):
        message = Message(string)
        return message, message.tail

    @property
    def type(self):
        return self[0].type

