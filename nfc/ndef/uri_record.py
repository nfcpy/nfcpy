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
# uri_record.py -- NDEF URI Record
#
import logging
log = logging.getLogger(__name__)

from record import Record

class UriRecord(Record):
    """Wraps an NDEF URI record and provides access to the :attr:`uri`
    content. The URI RTD specification defines the payload of the URI
    record as a URI identifier code byte followed by a URI string. The
    URI identifier code provides one byte code points for
    abbreviations of commonly used URI protocol names. The
    :class:`UriRecord` class handles abbreviations transparently by
    expanding and compressing when decoding and encoding.

    :param uri: URI string or :class:`nfc.ndef.Record` object

    The `uri` argument may alternatively supply an instance of class
    :class:`nfc.ndef.Record`. Initialization is then done by parsing
    the record payload. If the record type does not match
    'urn:nfc:wkt:U' a :exc:`ValueError` exception is raised.

    >>> nfc.ndef.UriRecord(nfc.ndef.Record())
    >>> nfc.ndef.UriRecord("http://nfcpy.org")
    """
    
    def __init__(self, uri=None):
        super(UriRecord, self).__init__('urn:nfc:wkt:U')
        if isinstance(uri, Record):
            record = uri
            if record.type == self.type:
                self.name = record.name
                self.data = record.data
            else:
                raise ValueError("record type mismatch")
        else:
            self.uri = uri if uri else ''

    def __repr__(self):
        s = "nfc.ndef.UriRecord(uri='{0}')"
        return s.format(self.uri)
        
    @property
    def data(self):
        for i, p in enumerate(protocol_strings):
            if i > 0 and self.uri.startswith(p):
                return chr(i) + self.uri[len(p):]
        else:
            return "\x00" + self.uri

    @data.setter
    def data(self, string):
        log.debug("decode uri record " + repr(string))
        if len(string) > 0:
            p = min(ord(string[0]), len(protocol_strings)-1)
            self.uri = protocol_strings[p] + string[1:]
        else: log.error("nothing to parse")

    @property
    def uri(self):
        """The URI string, including any abbreviation that is possibly
        available. A :exc:`ValueError` exception is raised if the
        string contains non ascii characters."""
        return self._uri

    @uri.setter
    def uri(self, value):
        try:
            self._uri = value.encode("ascii")
        except UnicodeDecodeError:
            raise ValueError("uri value must be an ascii string")
        except AttributeError:
            raise TypeError("uri value must be a str type")

    def pretty(self, indent=0):
        lines = list()
        if self.name:
            lines.append(("identifier", repr(self.name)))
        lines.append(("resource", self.uri))
        
        indent = indent * ' '
        lwidth = max([len(line[0]) for line in lines])
        lines = [line[0].ljust(lwidth) + " = " + line[1] for line in lines]
        return ("\n").join([indent + line for line in lines])

protocol_strings = (
    "",
    "http://www.",
    "https://www.",
    "http://",
    "https://",
    "tel:",
    "mailto:",
    "ftp://anonymous:anonymous@",
    "ftp://ftp.",
    "ftps://",
    "sftp://",
    "smb://",
    "nfs://",
    "ftp://",
    "dav://",
    "news:",
    "telnet://",
    "imap:",
    "rtsp://",
    "urn:",
    "pop:",
    "sip:",
    "sips:",
    "tftp:",
    "btspp://",
    "btl2cap://",
    "btgoep://",
    "tcpobex://",
    "irdaobex://",
    "file://",
    "urn:epc:id:",
    "urn:epc:tag:",
    "urn:epc:pat:",
    "urn:epc:raw:",
    "urn:epc:",
    "urn:nfc:",
    "RFU:"
)

