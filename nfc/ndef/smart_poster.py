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

import io
import struct
from record import Record
from message import Message
from uri_record import UriRecord
from text_record import TextRecord

actions = ("exec", "save", "open")

class SmartPosterRecord(Record):
    def __init__(self, *args, **kwargs):
        super(SmartPosterRecord, self).__init__('urn:nfc:wkt:Sp')
        self._uri = ''
        self._title = dict()
        self._image = dict()
        self._action = ''
        self._res_size = 0
        self._res_type = ''
        
        if len(args) > 0:
            if isinstance(args[0], Record):
                if not args[0].type == self.type:
                    raise ValueError("record type mismatch")
                self.name = args[0].name
                self.data = args[0].data
            else:
                self.uri = args[0]

        if 'title' in kwargs:
            self.title['en'] = unicode(kwargs['title'])

    @property
    def data(self):
        # encode smart poster payload as ndef message
        message = Message(UriRecord(self._uri))
        for lang, text in self.title.iteritems():
            message.append(TextRecord(text=text, language=lang))
        for image_type, image_data in self.image.iteritems():
            message.append(Record("image/"+image_type, data=image_data))
        if self.action:
            try: action = actions.index(self.action)
            except ValueError: action = int(self.action)
            message.append(Record("urn:nfc:wkt:act", data=chr(action)))
        if self._res_size:
            size = struct.pack('>L', self._res_size)
            message.append(Record("urn:nfc:wkt:s", data=size))
        return str(message)

    @data.setter
    def data(self, string):
        log.debug("decode smart poster record " + repr(string))
        if len(string) > 0:
            f = io.BytesIO(string)
            while f.tell() < len(string):
                record = Record(data=f)
                if record.type == "urn:nfc:wkt:U":
                    self.uri = UriRecord(record).uri
                elif record.type == "urn:nfc:wkt:T":
                    record = TextRecord(record)
                    self.title[record.language] = record.text
                elif record.type == "urn:nfc:wkt:act":
                    self.action = ord(record.data)
                elif record.type == "urn:nfc:wkt:s":
                    self._res_size = struct.unpack('>L', record.data)
                elif record.type == "urn:nfc:wkt:t":
                    self._res_type = record.data
                elif record.type.startswith("image/"):
                    image_type = record.type.replace("image/", "", 1)
                    self._image[image_type] = record.data
        else:
            log.error("nothing to parse")

    @property
    def uri(self):
        """The smart poster URI, a string of ascii characters. A
        :exc:`ValueError` exception is raised if non ascii characters
        are contained."""
        return self._uri

    @uri.setter
    def uri(self, value):
        try:
            self._uri = value.encode("ascii")
        except UnicodeDecodeError:
            raise ValueError("uri value must be an ascii string")
        except AttributeError:
            raise TypeError("uri value must be a str type")

    @property
    def title(self):
        """A dictionary of smart poster titles with ISO/IANA language
        codes as keys and title strings as values. Set specific title
        strings with ``obj.title['en']=title``. Assigning a string
        value is equivalent to setting the title for language code
        'en'."""
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
        return self._action

    @action.setter
    def action(self, value):
        if value in actions:
            self._action = value
        else:
            value = int(value)
            if value in range(len(actions)):
                self._action = actions[value]
            else:
                self._action = str(min(abs(value), 255))

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


