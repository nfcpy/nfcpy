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

import logging
log = logging.getLogger(__name__)

class NDEF(object):
    def __init__(self, tag):
        self._tag = tag
        self._msg = None
        self._cc = tag[12:16]
        if not self._cc[0] == 0xE1:
            raise ValueError("wrong ndef magic number")
        if not self._cc[3] & 0xF0 == 0:
            raise ValueError("no read permissions for ndef container")
        i = 16
        while True:
            if tag[i] == 0x03:
                ndef_size = tag[i+1]
                if ndef_size == 255:
                    ndef_size = tag[i+2] * 256 + tag[i+3];
                    if ndef_size < 256:
                        raise ValueError("invalid ndef tlv lenght value")
                    self._msg = tag[i+4:i+4+ndef_size]
                else:
                    self._msg = tag[i+2:i+2+ndef_size]
                break
            elif tag[i] == 0x00 or tag[i] == 0xFE: i += 1
            elif tag[i] == 0x01 or tag[i] == 0x02: i += 5
            elif tag[i] == 0xFD: i += 2 + tag[i+1]
            else: raise ValueError("invalid tlv tag value detected")
            
    @property
    def version(self):
        """The version of the NDEF mapping."""
        return "%d.%d" % (self._cc[1]>>4, self._cc[1]&0x0F)

    @property
    def capacity(self):
        """The maximum number of user bytes on the NDEF tag."""
        return self._cc[2] * 8

    @property
    def writeable(self):
        """Is True if new data can be written to the NDEF tag."""
        return self._cc[3] == 0x00

    @property
    def message(self):
        """A character string containing the NDEF message data."""
        return str(self._msg)

    @message.setter
    def message(self, data):
        raise NotImplemented("type 4 tag writing is not yet implemented")

class Type2Tag(object):
    def __init__(self, dev, data):
        self.dev = dev
        self.atq = data["ATQ"]
        self.sak = data["SAK"]
        self.uid = data["UID"]
        self._mmap = dict()
        #self._ndef = None
        try: self._ndef = NDEF(self)
        except Exception as e:
            log.error("while reading ndef: " + str(e))

    def __str__(self):
        s = "Type2Tag ATQ={atq:04x} SAK={sak:02x} UID={uid}"
        uid = self.uid.tostring().encode("hex")
        return s.format(atq=self.atq, sak=self.sak, uid=uid)

    def __getitem__(self, key):
        if type(key) is type(int()):
            key = slice(key, key+1)
        bytes = bytearray(key.stop - key.start)
        for i in xrange(key.start, key.stop):
            data = self._mmap.get(i/16, None)
            if data is None:
                data = self.read((i/16)*4)
                self._mmap[i/16] = data
            bytes[i-key.start] = data[i%16]
        return bytes if len(bytes) > 1 else bytes[0]
        
    @property
    def ndef(self):
        """For an NDEF tag this attribute holds an :class:`nfc.tt2.NDEF`
        object."""
        return self._ndef if hasattr(self, "_ndef") else None

    @property
    def is_present(self):
        """Returns True if the tag is still within communication range."""
        try: return bool(self.read(0))
        except IOError: return False

    def read(self, block):
        """Read a 16-byte data block from the tag. The *block*
        argument specifies the offset in multiples of 4 bytes
        (i.e. block number 1 will return bytes 4 to 19). The data is
        returned as a byte string.
        """
        log.debug("read block #{0}".format(block))
        cmd = "\x30" + chr(block)
        return self.dev.tt2_exchange(cmd)

    def write(self, data, block):
        """Write a 16-byte data block to the tag.
        """
        log.debug("write block #{0}".format(block))
        raise NotImplemented

