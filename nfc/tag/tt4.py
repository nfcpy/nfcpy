# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

import sys, time
from binascii import hexlify
if sys.hexversion >= 0x020704F0:
    from struct import pack, unpack
else: # for Debian Wheezy (and thus Raspbian)
    from struct import pack, unpack as _unpack
    unpack = lambda fmt, string: _unpack(fmt, buffer(string))

import nfc.tag
import nfc.clf

ndef_aid_v1 = bytearray.fromhex("D2760000850100")
ndef_aid_v2 = bytearray.fromhex("D2760000850101")

class Type4TagCommandError(nfc.tag.TagCommandError):
    """Type 4 Tag exception class. Beyond the generic error values from
    :attr:`~nfc.tag.TagCommandError` this class covers ISO 7816-4
    response APDU error codes.
    
    """
    errno_str = {
        # ISO/IEC 7816-4 (2005) APDU errors (SW1/SW2)
        0x6700: "wrong lenght (general error)",
        0x6900: "command not allowed (general error)",
        0x6981: "command incompatible with file structure",
        0x6982: "security status not satisfied",
        0x6A00: "wrong parameters p1/p2 (general error)",
        0x6A80: "incorrect parameters in command data field",
        0x6A81: "function not supported",
        0x6A82: "file or application not found",
        0x6A83: "record not found",
        0x6A84: "not enough memory space in the file",
        0x6A85: "command length inconsistent with TLV structure",
        0x6A86: "incorrect parameters p1/p2",
        0x6A87: "command length inconsistent with p1/p2",
        0x6A88: "referenced data or reference data not found",
        0x6A89: "file already exists",
        0x6A8A: "file name already exists",
        }

    @staticmethod
    def from_status(status):
        return Type4TagCommandError(unpack(">H", status)[0])

class IsoDepInitiator(object):
    def __init__(self, clf, miu, fwt):
        self.clf = clf # contactless frontend instance
        self.miu = miu # maximum information unit in octets
        self.fwt = fwt # frame waiting time in seconds
        self.pni = 0

    def exchange(self, command, timeout=None):
        if timeout is None:
            timeout = self.fwt + 0.01

        if command is None:
            # presence check with R(NAK)
            data = bytearray([0xB2|self.pni])
            self.clf.exchange(data, timeout)
            return

        for offset in range(0, len(command), self.miu):
            more = len(command) - offset > self.miu
            pfb = (0x02 if not more else 0x12) | self.pni
            data = chr(pfb) + command[offset:offset+self.miu]
            data = self.clf.exchange(data, timeout)
            while data[0] & 0b11111110 == 0b11110010: # WTX
                log.debug("ISO-DEP waiting time extension")
                data = self.clf.exchange(data, timeout)
            if data[0] & 0x01 != self.pni:
                log.error("ISO-DEP protocol error: block number")
                raise IOError("ISO-DEP protocol error: block number")
            if more:
                if data[0] & 0b11111110 == 0b10100010: # ACK
                    self.pni = (self.pni + 1) % 2
                else:
                    log.error("ISO-DEP protocol error: expected ack")
                    raise IOError("ISO-DEP protocol error: expected ack")
            else:
                if data[0] & 0b11101110 == 0b00000010: # INF
                    self.pni = (self.pni + 1) % 2
                    response = data[1:]
                else:
                    log.error("ISO-DEP protocol error: expected inf")
                    raise IOError("ISO-DEP protocol error: expected inf")

        while bool(data[0] & 0b00010000):
            data = chr(0b10100010 | self.pni) # ack
            data = self.clf.exchange(data, timeout)
            if data[0] & 0x01 != self.pni:
                log.error("ISO-DEP protocol error: block number")
                raise IOError("ISO-DEP protocol error: block number")
            response = response + data[1:]
            self.pni = (self.pni + 1) % 2
            
        return response

class Type4Tag(nfc.tag.Tag):
    """Implementation of the NFC Forum Type 4 Tag operation specification.

    The NFC Forum Type 4 Tag is based on ISO/IEC 14443 DEP protocol
    for Type A and B modulation and uses ISO/IEC 7816-4 command and
    response APDUs.

    """
    TYPE = "Type4Tag"

    class NDEF(nfc.tag.Tag.NDEF):
        # Type 4 Tag specific implementation of the NDEF access type
        # class that is returned by the Tag.ndef attribute.

        def _select_aid(self, aid):
            try:
                self.tag.send_apdu(0, 0xA4, 0x04, 0x00, aid)
                return True
            except Type4TagCommandError:
                return False
                
        def _select_fid(self, fid):
            for p2 in (0x0C, 0x00):
                try:
                    self.tag.send_apdu(0, 0xA4, 0x00, p2, fid)
                    return True
                except Type4TagCommandError:
                    pass
            return False

        def _read_binary(self, offset, max_data):
            p1, p2 = pack(">H", offset)
            max_data = min(max_data, self._max_le)
            try:
                return self.tag.send_apdu(0, 0xB0, p1, p2, mrl=max_data)
            except Type4TagCommandError:
                log.debug("read_binary command error")

        def _update_binary(self, offset, data):
            p1, p2 = pack(">H", offset)
            max_data = min(len(data), self._max_lc)
            try:
                self.tag.send_apdu(0, 0xD6, p1, p2, data[0:max_data])
                return max_data
            except Type4TagCommandError:
                log.debug("update_binary command error")

        def _discover_ndef(self):
            self._max_lc = 1
            self._max_le = 15
            
            log.debug("select ndef application")
            if not (self._select_aid(ndef_aid_v2) or
                    self._select_aid(ndef_aid_v1)):
                log.debug("no ndef application file")
                return False

            log.debug("select ndef capability file")
            if not self._select_fid("\xE1\x03"):
                log.warning("no ndef capability file")
                return False

            log.debug("read ndef capability file")
            cclen = self._read_binary(0, 2)
            if not (cclen and len(cclen) == 2):
                log.debug("error reading capability length")
                return False

            cclen = unpack(">H", cclen)[0]
            capabilities = self._read_binary(2, min(cclen-2, 15))
            
            if capabilities is None or len(capabilities) < 13:
                log.warning("insufficient capability data")
                return False

            capabilities += (15-len(capabilities)) * "\0" # for unpack
            ver, mle, mlc, tag, val = unpack(">BHHB9p", capabilities)
            
            if ver >> 4 not in (1, 2, 3):
                log.debug("unsupported major ndef version")
                return False

            if not (tag, len(val)) in ((4, 6), (6, 8)):
                log.error("invalid ndef control tlv")
                return False

            ndef_control_tlv_format = ">2sHBB" if tag == 4 else ">2sIBB"
            ndef_file, mfs, rf, wf = unpack(ndef_control_tlv_format, val)

            self._max_le = mle
            self._max_lc = mlc
            self._capacity = mfs - tag + 2
            self._readable = bool(rf == 0)
            self._writeable = bool(wf == 0)
            self._nlen_size = tag - 2
            self._ndef_file = ndef_file
            
            return True
            
        def _read_ndef_data(self):
            log.debug("read ndef data")
            
            if not hasattr(self, "_ndef_file") and not self._discover_ndef():
                log.debug("no ndef application")
                return None

            log.debug("select ndef data file")
            if not self._select_fid(self._ndef_file):
                log.warning("ndef file select error")
                return None

            log.debug("read ndef data file")
            lfmt = ">I" if self._nlen_size == 4 else ">H"
            nlen = self._read_binary(0, self._nlen_size)
            nlen = unpack(lfmt, nlen)[0]

            data = bytearray()
            while len(data) < nlen:
                offset = self._nlen_size + len(data)
                data += self._read_binary(offset, nlen-len(data))
                if not self._nlen_size + len(data) > offset: break
            else:
                return data

        def _write_ndef_data(self, data):
            log.debug("write ndef data")

            lfmt = ">I" if self._nlen_size == 4 else ">H"
            nlen = bytearray(pack(lfmt, len(data)))
            if len(nlen) + len(data) <= self._max_lc:
                data = bytearray(nlen) + data
                nlen = None
            else:
                data = bytearray(len(nlen)) + data

            offset = 0
            while offset < len(data):
                sent = self._update_binary(offset, buffer(data, offset))
                if sent is None: return False
                offset += sent
            else:
                if nlen: self._update_binary(0, nlen)
                return True
            
    def __init__(self, clf, target):
        super(Type4Tag, self).__init__(clf)
        self.atq = target.cfg[0] << 8 | target.cfg[1]
        self.sak = target.cfg[2]
        self.uid = target.uid
        self.ats = target.ats
        if self.ats is None:
            self.ats = self.clf.exchange('\xE0\x80', timeout=0.03)
        try:
            miu = (16,24,32,40,48,64,86,128,256)[self.ats[1] & 0x0F]
        except IndexError:
            log.warning("FSCI with RFU value in Type 4A Answer To Select")
            miu = 32
        fwi = (self.ats[3] >> 4) if (self.ats[3] >> 4 != 15) else 4
        fwt = 4096 / 13.56E6 * pow(2, fwi)
        self.dep = IsoDepInitiator(clf, miu, fwt)
        self._extended_length_support = False

    def __str__(self):
        hx = lambda x: str(x) if x is None else hexlify(x).upper()
        s = " ATQ={tag.atq:04x} SAK={tag.sak:02x} ATS={ats}"
        return nfc.tag.Tag.__str__(self) \
            + s.format(tag=self, ats=hx(self.ats))

    def _is_present(self):
        try:
            self.dep.exchange(None)
            return True
        except nfc.clf.DigitalProtocolError:
            return False

    def dump(self):
        return []

    def transceive(self, data, timeout=None):
        """Transmit arbitrary data and receive the response.

        This is a low level method to send arbitrary data to the
        tag. While it should almost always be better to use
        :meth:`send_apdu` this is the only way to force a specific
        timeout value (which is otherwise derived from the Tag's
        answer to select). The *timeout* value is expected as a float
        specifying the seconds to wait.

        """
        log.debug(">> {0}".format(hexlify(data)))
        
        try:
            data = self.dep.exchange(data, timeout)
        except nfc.clf.TimeoutError:
            raise Type4TagCommandError(nfc.tag.TIMEOUT_ERROR)
        except nfc.clf.ProtocolError:
            raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)
        except nfc.clf.TransmissionError:
            raise Type4TagCommandError(nfc.tag.RECEIVE_ERROR)

        log.debug("<< {0}".format(hexlify(data) if data else "None"))
        return data

    def send_apdu(self, cla, ins, p1, p2, data=None, mrl=0, check_status=True):
        """Send an ISO/IEC 7816-4 APDU to the Type 4 Tag.

        The 4 byte APDU header (class, instruction, parameter 1 and 2)
        is constructed from the first four parameters (cla, ins, p1,
        p2) without interpretation. The byte string *data* argument
        represents the APDU command data field. It is encoded as a
        short or extended length field followed by the *data*
        bytes. The length field is not transmitted if *data* is None
        or an empty string. The maximum acceptable number of response
        data bytes is given with the max-response-length *mrl*
        argument. The value of *mrl* is transmitted as the 7816-4 APDU
        Le field after appropriate conversion.
        
        By default, the response is returned as a byte array not
        including the status word, a :exc:`Type4TagCommandError`
        exception is raised for any status word other than
        9000h. Response status verification can be disabled with
        *check_status* set to False, the byte array will then include
        the response status word at the last two positions.
        
        Transmission errors always raise a :exc:`Type4TagCommandError`
        exception.

        """
        apdu = bytearray([cla, ins, p1, p2])
        
        if not self._extended_length_support:
            if data and len(data) > 255:
                raise ValueError("unsupported command data length")
            if mrl and mrl > 256:
                raise ValueError("unsupported max response length")
            if data:
                apdu += chr(len(data)) + data
            if mrl > 0:
                apdu += chr(0) if mrl == 256 else chr(mrl)
        else:
            if data and len(data) > 65535:
                raise ValueError("invalid command data length")
            if le and le > 65536:
                raise ValueError("invalid max response length")
            if data:
                apdu += pack(">xH", len(data)) + data
            if mrl > 0:
                le = 0 if mrl == 65536 else mrl
                apdu += pack(">H", le) if data else pack(">xH", le)

        apdu = self.transceive(apdu)
            
        if not apdu or len(apdu) < 2:
            raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)

        if check_status and apdu[-2:] != "\x90\x00":
            raise Type4TagCommandError.from_status(apdu[-2:])

        return apdu[:-2] if check_status else apdu

def activate(clf, target):
    return Type4Tag(clf, target)
