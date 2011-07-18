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

from nfc.ndef import Record

class TextRecord(Record):
    def __init__(self, initializer=("en", "")):
        if isinstance(initializer, Record):
            Record.__init__(self, initializer)
        else:
            Record.__init__(self)
            self.language, self.text = initializer

    @property
    def data(self):
        text_utf8 = self._text.encode("utf8")
        text_utf16 = self._text.encode("utf16")
        encoding = "utf8" if len(text_utf8) <= len(text_utf16) else "utf16"
        string = chr(len(self._lang) | (int(encoding == "utf16") << 7))
        return string + self._lang + self._text.encode(encoding)

    @data.setter
    def data(self, string):
        if not string: return
        status_byte = ord(string[0])
        encoding = "utf16" if status_byte >> 7 else "utf8"
        self._lang = string[1:1+status_byte & 0x3F]
        self._text = string[1+len(self._lang):].decode(encoding)

    @property
    def type(self):
        return "urn:nfc:wkt:T"

    @type.setter
    def type(self, value):
        pass

    @property
    def language(self):
        return self._lang

    @language.setter
    def language(self, value):
        self._lang = value.encode('ascii')

    @property
    def text(self):
        return self._text

    @text.setter
    def text(self, value):
        self._text = value


