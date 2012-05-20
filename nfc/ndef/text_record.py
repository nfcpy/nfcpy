# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2011 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
# text_record.py -- NDEF text record
#
import logging
log = logging.getLogger(__name__)

import record

class TextRecord(record.Record):
    """NDEF Text Record representation class.

    nfc.ndef.TextRecord(nfc.ndef.Record())    
    nfc.ndef.TextRecord(text="", language="en", encoding="utf8")
    """
        
    def __init__(self, *args, **kwargs):
        """
        
        nfc.ndef.TextRecord(nfc.ndef.Record())
        nfc.ndef.TextRecord(text="", language="en", encoding="UTF16")
        """
        super(TextRecord, self).__init__('urn:nfc:wkt:T')
        if args and isinstance(args[0], record.Record):
            if not args[0].type == 'urn:nfc:wkt:T':
                raise ValueError("record type mismatch")
            self.name = args[0].name
            self.data = args[0].data
        else:
            self.text = unicode(kwargs.get('text', ''))
            self.language = kwargs.get('language', 'en')
            self.encoding = kwargs.get('encoding', 'UTF-8')

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
        else:
            log.error("no payload to parse text record")

    @property
    def text(self):
        """Text content."""
        return self._text

    @text.setter
    def text(self, value):
        self._text = unicode(value)

    @property
    def language(self):
        """ISO/IANA language code."""
        return self._lang

    @language.setter
    def language(self, value):
        assert len(value) <= 64
        self._lang = value.encode('ascii')

    @property
    def encoding(self):
        """Text encoding 'UTF-8' or 'UTF-16'."""
        return self._utfx

    @encoding.setter
    def encoding(self, value):
        assert value in ("UTF-8", "UTF-16")
        self._utfx = value

