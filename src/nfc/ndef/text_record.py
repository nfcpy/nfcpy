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
# text_record.py -- NDEF text record
#
import logging
log = logging.getLogger(__name__)

from record import Record

class TextRecord(Record):
    """Wraps an NDEF Text record and provides access to the
    :attr:`encoding`, :attr:`language` and actual :attr:`text`
    content.

    :param text: Text string or :class:`nfc.ndef.Record` object
    :param language: ISO/IANA language code string
    :param encoding: Text encoding in binary NDEF

    The `text` argument may alternatively supply an instance of class
    :class:`nfc.ndef.Record`. Initialization is then done by parsing
    the record payload. If the record type does not match
    'urn:nfc:wkt:T' a :exc:`ValueError` exception is raised.

    >>> nfc.ndef.TextRecord(nfc.ndef.Record())
    >>> nfc.ndef.TextRecord("English UTF-8 encoded")
    >>> nfc.ndef.TextRecord("Deutsch UTF-8", language="de")
    >>> nfc.ndef.TextRecord("English UTF-16", encoding="UTF-16")
    """
    
    def __init__(self, text=None, language='en', encoding='UTF-8'):
        super(TextRecord, self).__init__('urn:nfc:wkt:T')
        if isinstance(text, Record):
            record = text
            if record.type == self.type:
                self.name = record.name
                self.data = record.data
            else:
                raise ValueError("record type mismatch")
        else:
            self.text = text if text else ''
            self.language = language
            self.encoding = encoding
        
    def __repr__(self):
        s = "nfc.ndef.TextRecord(text='{0}', language='{1}', encoding='{2}')"
        return s.format(self.text, self.language, self.encoding)
        
    @property
    def data(self):
        sb = chr(len(self.language) | ((self.encoding == "UTF-16") << 7))
        return sb + self.language + self._text.encode(self.encoding)

    @data.setter
    def data(self, string):
        log.debug("decode text record " + repr(string))
        if len(string) > 0:
            status_byte = ord(string[0])
            if status_byte & 0x40:
                log.warning("bit 6 of status byte is not zero")
            if status_byte & 0x3F == 0:
                log.warning("language code length is zero")
            if status_byte & 0x3F >= len(string):
                log.error("language code length exceeds payload")
            self._utfx = "UTF-16" if status_byte >> 7 else "UTF-8"
            self._lang = string[1:1+(status_byte & 0x3F)]
            self._text = string[1+len(self._lang):].decode(self._utfx)
        else: log.error("nothing to parse")

    @property
    def text(self):
        """The text content. A unicode string that specifies the TEXT
        record text field. Coerced into unicode when set."""
        return self._text

    @text.setter
    def text(self, value):
        self._text = unicode(value)

    @property
    def language(self):
        """The text language. A string that specifies the ISO/IANA
        language code coded into the TEXT record. The value is not
        verified except that a :exc:`ValueError` exception is raised
        if the assigned value string exceeds 64 characters."""
        return self._lang

    @language.setter
    def language(self, value):
        if not isinstance(value, str):
            raise TypeError("language must be specified as string")
        if len(value) > 64:
            raise ValueError('maximum string length is 64')
        self._lang = value.encode('ascii')

    @property
    def encoding(self):
        """The text encoding, given as a string. May be 'UTF-8' or
        'UTF-16'. A :exc:`ValueError` exception is raised for
        anythinge else."""
        return self._utfx

    @encoding.setter
    def encoding(self, value):
        if not value in ("UTF-8", "UTF-16"):
            raise ValueError('value not in ("UTF-8", "UTF-16")')
        self._utfx = value

    def pretty(self, indent=0):
        lines = list()
        if self.name:
            lines.append(("identifier", repr(self.name)))
        lines.append(("text", self.text))
        lines.append(("language", self.language))
        lines.append(("encoding", self.encoding))
        
        indent = indent * ' '
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])
