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
    """Wraps a sequence of NDEF records and provides methods for
    appending, inserting and indexing. Instantiation accepts a
    variable number of positional arguments. A call without argument
    produces a Message object with no records. A single str or
    bytearray argument is parsed as NDEF message bytes. A single list
    or tuple of :class:`nfc.ndef.Record` objects produces a Message
    with those records in order. One or more :class:`nfc.ndef.Record`
    arguments produce a Message with those records in order.

    >>> nfc.ndef.Message(b'\\x10\\x00\\x00')     # NDEF data bytes
    >>> nfc.ndef.Message(bytearray([16,0,0])) # NDEF data bytes
    >>> nfc.ndef.Message([record1, record2])  # list of records
    >>> nfc.ndef.Message(record1, record2)    # two record args
    """
    
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
        log.debug("ndef message complete at offset {0}".format(f.tell()))

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

    def __eq__(self, other):
        return str(self) == str(other)
    
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
        """Add a record to the end of the message. The *record*
        argument must be an instance of :class:`nfc.ndef.Record`."""
        
        if not isinstance(record, nfc.ndef.Record):
            raise TypeError("an nfc.ndef.Record object is required")
        self._records.append(copy.copy(record))

    def extend(self, records):
        """Extend the message by appending all the records in the
        given list. The *records* argument must be a sequence of
        :class:`nfc.ndef.Record` elements."""

        for record in records:
            if not isinstance(record, nfc.ndef.Record):
                raise TypeError("only nfc.ndef.Record objects are accepted")
            self._records.append(copy.copy(record))
        
    def insert(self, i, record):
        """Insert a record at the given position. The first argument
        *i* is the index of the record before which to insert, so
        message.insert(0, record) inserts at the front of the message,
        and message.insert(len(message), record) is equivalent to
        message.append(record). The second argument *record* must be
        an instance of :class:`nfc.ndef.Record`."""
        
        if not isinstance(record, nfc.ndef.Record):
            raise TypeError("an nfc.ndef.Record object is required")
        self._records.append(copy.copy(record))

    def pop(self, i=-1):
        """Remove the record at the given position *i* in the message,
        and return it. If no position is specified, message.pop()
        removes and returns the last item."""

        return self._records.pop(i)

    @property
    def type(self):
        """The message type. Corresponds to the record type of the
        first record in the message. None if the message has no
        records. This attribute is read-only."""
        return self._records[0].type if len(self._records) else None

    @property
    def name(self):
        """The message name. Corresponds to the record name of the
        first record in the message. None if the message has no
        records. This attribute is read-only."""
        return self._records[0].name if len(self._records) else None

    def pretty(self):
        """Returns a message representation that might be considered
        pretty-printable."""
        lines = list()
        for index, record in enumerate(self._records):
            lines.append(("record {0}".format(index+1),))
            lines.append(("  type", repr(record.type)))
            lines.append(("  name", repr(record.name)))
            lines.append(("  data", repr(record.data)))
        lwidth = max([len(line[0]) for line in lines])
        lines = [(line[0].ljust(lwidth),) + line[1:] for line in lines]
        lines = [" = ".join(line) for line in lines]
        return ("\n").join([line for line in lines])
        
