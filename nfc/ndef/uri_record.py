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

import record

class UriRecord(record.Record):
    """NDEF URI Record representation."""
    
    def __init__(self, *args, **kwargs):
        super(UriRecord, self).__init__('urn:nfc:wkt:U')
        self._uri = ''
        if len(args) > 0:
            if isinstance(args[0], record.Record):
                if not args[0].type == self.type:
                    raise ValueError("record type mismatch")
                self.name = args[0].name
                self.data = args[0].data
            else:
                self.uri = args[0]
        if 'uri' in kwargs:
            self.uri = kwargs['uri']

    def __repr__(self):
        s = "nfc.ndef.UriRecord(uri='{0}')"
        return s.format(self.uri)
        
    @property
    def data(self):
        for i, p in enumerate(protocol_strings):
            if i > 0 and self.uri.startswith(p):
                return chr(i) + self.uri[len(p):]
        else:
            return "\x00"

    @data.setter
    def data(self, string):
        log.debug("decode uri record " + repr(string))
        if len(string) > 0:
            p = min(ord(string[0]), len(protocol_strings)-1)
            self.uri = protocol_strings[p] + string[1:]
        else: log.error("nothing to parse")

    @property
    def uri(self):
        return self._uri

    @uri.setter
    def uri(self, value):
        self._uri = value.encode("ascii")

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

