# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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

class UriRecord(Record):
    def __init__(self, initializer=None):
        if isinstance(initializer, Record):
            Record.__init__(self, initializer)
        else:
            Record.__init__(self)
            self._uri = initializer.encode("ascii")

    @property
    def data(self):
        for i in range(1, len(protocol_strings)):
            if self._uri.startswith(protocol_strings[i]):
                return chr(i) + self._uri[len(protocol_strings[i]):]
        return "\x00"

    @data.setter
    def data(self, string):
        if not string: return
        protocol = min(ord(string[0]), len(protocol_strings)-1)
        self._uri = protocol_strings[protocol] + string[1:]

    @property
    def type(self):
        return "urn:nfc:wkt:U"

    @type.setter
    def type(self, value):
        pass

    @property
    def uri(self):
        return self._uri

    @uri.setter
    def uri(self, value):
        self._uri = value

protocol_strings = ("",
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

