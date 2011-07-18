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

import struct
from nfc.ndef import Message, Record
from nfc.ndef.Uri import UriRecord
from nfc.ndef.Text import TextRecord

action_values = ("exec", "save", "open", "rfu")

class SmartPosterRecord(Record):
    def __init__(self, record=None):
        self._uri = ""
        self._title = dict()
        self._image = dict()
        self._action = None
        self._res_size = None
        self._res_type = None
        Record.__init__(self, record)

    @property
    def data(self):
        # smart poster payload is an ndef message
        message = Message(UriRecord(self._uri))
        for title_lang, title_text in self.title.iteritems():
            message.append(TextRecord((title_lang, title_text)))
        for image_type, image_data in self.image.iteritems():
            message.append(Record(("image/"+image_type, "", image_data)))
        if self._action:
            action_record = Record(("urn:nfc:wkt:act", "", chr(self._action)))
            message.append(action_record)
        if self._res_size:
            size = struct.pack('>L', self._res_size)
            message.append(Record(("urn:nfc:wkt:s", "", size)))
        return message.tostring()

    @data.setter
    def data(self, string):
        if not string: return
        for record in Message(string):
            if record.type == "urn:nfc:wkt:U":
                self._uri = UriRecord(record).uri
            elif record.type == "urn:nfc:wkt:T":
                record = TextRecord(record)
                self._title[record.language] = record.text
            elif record.type == "urn:nfc:wkt:act":
                self._action = ord(record.data)
            elif record.type == "urn:nfc:wkt:s":
                self._res_size = struct.unpack('>L', record.data)
            elif record.type == "urn:nfc:wkt:t":
                self._res_type = record.data
            elif record.type.startswith("image/"):
                image_type = record.type.replace("image/", "", 1)
                self._image[image_type] = record.data

    @property
    def type(self):
        return "urn:nfc:wkt:Sp"

    @type.setter
    def type(self, value):
        pass

    @property
    def uri(self):
        return self._uri

    @uri.setter
    def uri(self, value):
        self._uri = value

    @property
    def title(self):
        return self._title

    @title.setter
    def title(self, value):
        self._title["en"] = value

    @property
    def image(self):
        return self._image

    @image.setter
    def image(self, value):
        pass

    @property
    def action(self):
        if self._action is None: return "unspecified"
        else: return action_values[min(self._action, len(action_values))]

    @action.setter
    def action(self, value):
        if value in action_values:
            self._action = action_values.index(value)

    @property
    def resource_size(self):
        return self._res_size

    @resource_size.setter
    def resource_size(self, value):
        self._res_size = int(value)

    @property
    def resource_type(self):
        return self._res_type

    @resource_type.setter
    def resource_type(self, value):
        self._res_type = str(value)


