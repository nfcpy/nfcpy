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
# message.py -- NDEF message handling
#
import logging
log = logging.getLogger(__name__)

import io
import copy
import nfc.ndef

class Message(object):
    def __init__(self, *args):
        self._records = list()
        if len(args) == 1:
            if isinstance(args[0], io.BytesIO):
                self._read(args[0])
            elif isinstance(args[0], (str, bytearray)):
                self._read(io.BytesIO(args[0]))
            elif isinstance(args[0], nfc.ndef.Record):
                self.append(args[0])
            elif isinstance(args[0], (list, tuple)):
                self.extend(args[0])
            else: raise TypeError("invalid argument type")
        elif len(args) > 1:
            self.extend(args)
        
    def _read(self, f):
        log.debug("parse ndef message at offset {0}".format(f.tell()))
        record = nfc.ndef.Record(data=f)
        if record._message_begin == False:
            log.error("message begin flag not set at begin of ndef")
            raise nfc.ndef.FormatError("message begin flag not set")
        self._records.append(record)
        while self._records[-1]._message_end == False:
            self._records.append(nfc.ndef.Record(data=f))
        log.debug("done ndef message at offset {0}".format(f.tell()))

    def _write(self, f):
        if len(self._records) > 0:
            for record in self._records:
                record._message_begin = record._message_end = False
            self._records[0]._message_begin = True
            self._records[-1]._message_end = True
            for record in self._records:
                record._write(f)

    def __repr__(self):
        return 'nfc.ndef.Message(' + repr(self._records) + ')'
    
    def __str__(self):
        stream = io.BytesIO()
        self._write(stream)
        stream.seek(0, 0)
        return stream.read()
    
    def __len__(self):
        return len(self._records)

    def __getitem__(self, key):
        return self._records[key]

    def __setitem__(self, key, value):
        if not (isinstance(value, nfc.ndef.Record) or
                all([isinstance(elem, nfc.ndef.Record) for elem in value])):
            raise TypeError("only nfc.ndef.Record objects are accepted")
        self._records[key] = value

    def __delitem__(self, key):
        del self._records[key]

    def append(self, record):
        """Add an NDEF Record to the end of the message; equivalent to
        message[len(message):] = [record]."""
        
        if not isinstance(record, nfc.ndef.Record):
            raise TypeError("an nfc.ndef.Record object is required")
        self._records.append(copy.copy(record))

    def extend(self, records):
        """Extend the message by appending all the records in the
        given list; equivalent to message[len(message):] = [r1,r2]."""

        for record in records:
            if not isinstance(record, nfc.ndef.Record):
                raise TypeError("only nfc.ndef.Record objects are accepted")
            self._records.append(copy.copy(record))
        
    def insert(self, i, record):
        """Insert an NDEF Record at the given position. The first
        argument is the index of the record before which to insert, so
        message.insert(0, record) inserts at the front of the message,
        and message.insert(len(message), record) is equivalent to
        message.append(record)."""
        
        if not isinstance(record, nfc.ndef.Record):
            raise TypeError("an nfc.ndef.Record object is required")
        self._records.append(copy.copy(record))

    def pop(self, i=-1):
        """Remove the record at the given position in the message, and
        return it. If no index is specified, message.pop() removes and
        returns the last item."""

        return self._records.pop(i)

    @property
    def type(self):
        "The type of the first record or :const:`None` if len is zero."
        return self._records[0].type if len(self._records) else None

    @property
    def name(self):
        "The name of the first record or :const:`None` if len is zero."
        return self._records[0].name if len(self._records) else None

    # **************
    # * deprecated *
    # **************
    @staticmethod
    def fromstring(data):
        return Message(data)

    def tostring(self):
        return str(self)

