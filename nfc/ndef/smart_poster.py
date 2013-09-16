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

import logging
log = logging.getLogger(__name__)

import io
import struct
from record import Record
from message import Message
from uri_record import UriRecord
from text_record import TextRecord

actions = ('default', "exec", "save", "edit")

class SmartPosterRecord(Record):
    """Wraps an NDEF SmartPoster record and provides access to the
    :attr:`encoding`, :attr:`language` and actual :attr:`text`
    content.

    :param uri: URI string or :class:`nfc.ndef.Record` object
    :param title: Smart poster title(s), assigned to :attr:`title`
    :param icons: Smart poster icons, assigned to :attr:`icons`
    :param action: Recommended action, assigned to :attr:`action`
    :param resource_size: Size of the referenced resource
    :param resource_type: Type of the referenced resource

    The `uri` argument may alternatively supply an instance of class
    :class:`nfc.ndef.Record`. Initialization is then done by parsing
    the record payload. If the record type does not match
    'urn:nfc:wkt:Sp' a :exc:`ValueError` exception is raised.

    >>> nfc.ndef.SmartPosterRecord(nfc.ndef.Record())
    >>> nfc.ndef.SmartPosterRecord("http://nfcpy.org", "nfcpy")
    >>> nfc.ndef.SmartPosterRecord("http://nfcpy.org", "nfcpy", action="save")
    """
    def __init__(self, uri, title={}, icons={}, action='default',
                 resource_size=None, resource_type=None):
        super(SmartPosterRecord, self).__init__('urn:nfc:wkt:Sp')
        self._title = dict()
        self.title = title
        self.icons = icons
        self.action = action
        self.resource_size = resource_size
        self.resource_type = resource_type
        if isinstance(uri, Record):
            record = uri
            if record.type == self.type:
                self.name = record.name
                self.data = record.data
            else:
                raise ValueError("record type mismatch")
        else:
            self.uri = uri

    @property
    def data(self):
        # encode smart poster payload as ndef message
        message = Message(UriRecord(self._uri))
        for lang, text in self.title.iteritems():
            message.append(TextRecord(text=text, language=lang))
        for image_type, image_data in self.icons.iteritems():
            message.append(Record("image/"+image_type, data=image_data))
        if self._action >= 0:
            message.append(Record("urn:nfc:wkt:act", data=chr(self._action)))
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
                    self._action = ord(record.data)
                elif record.type == "urn:nfc:wkt:s":
                    self._res_size = struct.unpack('>L', record.data)
                elif record.type == "urn:nfc:wkt:t":
                    self._res_type = record.data
                elif record.type.startswith("image/"):
                    image_type = record.type.replace("image/", "", 1)
                    self.icons[image_type] = record.data
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
        'en'. Titles are optional for a smart poster record"""
        return self._title

    @title.setter
    def title(self, value):
        if isinstance(value, dict):
            self._title = value
        else:
            self._title["en"] = value

    @property
    def icons(self):
        """A dictionary of smart poster icon images. The keys specify
        the image mime sub-type and the values are strings of image
        data. Icons are optional for a smart poster record."""
        return self._icons

    @icons.setter
    def icons(self, value):
        if not isinstance(value, dict):
            raise TypeError("icons must be assigned a dict of images")
        self._icons = value

    @property
    def action(self):
        """The recommended action for the receiver of the smart
        poster. Reads as 'default', 'exec', 'save', 'edit' or a number
        string if RFU values were decoded. Can be set to 'exec',
        'save', 'edit' or :const:`None`. The action is optional in a
        smart poster record."""
        try:
            return actions[self._action + 1]
        except IndexError:
            return str(self._action)

    @action.setter
    def action(self, value):
        try:
            self._action = actions.index(value) - 1
        except ValueError:
            raise ValueError("action value not in " + repr(actions))

    @property
    def resource_size(self):
        """The size of the resource referred by the URI. A 32 bit
        unsigned integer value or :const:`None`. The resource size is
        optional in a smart poster record."""
        return self._res_size

    @resource_size.setter
    def resource_size(self, value):
        if value is not None:
            value = int(value)
            if value < 0 or value > 0xffffffff:
                raise ValueError("expected a 32-bit unsigned integer")
        self._res_size = value

    @property
    def resource_type(self):
        """The type of the resource referred by the URI. A UTF-8
        formatted string that describes an Internet media type (MIME
        type) or :const:`None`. The resource type is optional in a
        smart poster record."""
        return self._res_type

    @resource_type.setter
    def resource_type(self, value):
        self._res_type = value

    def pretty(self, indent=0):
        lines = list()
        lines.append(("resource", self.uri))
        if self.name:
            lines.append(("identifier", repr(self.name)))
        if self.resource_type:
            lines.append(("resource type", self.resource_type))
        if self.resource_size:
            lines.append(("resource size", str(self.resource_size)))
        for lang in sorted(self.title):
            lines.append(("title[%s]" % lang, self.title[lang]))
        for icon in sorted(self.icons):
            info = "{0} ... ({1} bytes)".format(
                repr(self.icons[icon][:10]).strip("'"),
                len(self.icons[icon]))
            lines.append(("icon[%s]"%icon, info))
        lines.append(("action", self.action))
        
        indent = indent * ' '
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])
