# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import itertools
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
    def __init__(self, clf, fsc, fwt):
        self.clf = clf # contactless frontend instance
        self.pni = 0
        self.miu = fsc-1
        self.fwt = fwt
        self.delta_fwt = 49152 / 13.56E6
        self.n_retry_ack = min(int(1/self.fwt), 5)
        self.n_retry_nak = self.n_retry_ack

    def exchange(self, command, timeout=None):
        if timeout is None:
            timeout = self.fwt + self.delta_fwt

        if command is None:
            # presence check with R(NAK)
            data = bytearray([0xB2|self.pni])
            self.clf.exchange(data, timeout)
            return

        for offset in range(0, len(command), self.miu):
            more = len(command) - offset > self.miu
            pfb = chr((0x02, 0x12)[more] | self.pni)
            data = pfb + command[offset:offset+self.miu]
            
            for i in itertools.count(start=1):
                try:
                    data = self.clf.exchange(data, timeout)
                    if data is not None and len(data) == 0:
                        raise nfc.clf.TransmissionError
                    if data[0] == 0xA2 | (~self.pni & 1):
                        log.debug("ISO-DEP retransmit after ack")
                        data = pfb + command[offset:offset+self.miu]
                        continue
                    break
                except nfc.clf.TransmissionError:
                    if i <= self.n_retry_nak:
                        log.warning("ISO-DEP transmission error, retry #%d"%i)
                        data = bytearray([0xB2|self.pni])
                    else:
                        log.error("ISO-DEP unrecoverable transmission error")
                        raise Type4TagCommandError(nfc.tag.RECEIVE_ERROR)
                except nfc.clf.TimeoutError:
                    if i <= self.n_retry_nak:
                        log.warning("ISO-DEP timeout error, retry #%d" % i)
                        data = bytearray([0xB2|self.pni])
                    else:
                        log.error("ISO-DEP unrecoverable timeout error")
                        raise Type4TagCommandError(nfc.tag.TIMEOUT_ERROR)
                except nfc.clf.ProtocolError:
                    log.error("ISO-DEP unrecoverable protocol error")
                    raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)

            if not data:
                log.error("ISO-DEP unrecoverable protocol error")
                raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)
                
            while data[0] & 0b11111110 == 0b11110010: # WTX
                log.debug("ISO-DEP waiting time extension")
                data = self.clf.exchange(data, (data[1]&0x3F) * self.fwt)
            if data[0] & 0x01 != self.pni:
                log.warning("ISO-DEP protocol error: block number")
                raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)
            if more:
                if data[0] & 0b11111110 == 0b10100010: # ACK
                    self.pni = (self.pni + 1) % 2
                else:
                    log.error("ISO-DEP protocol error: expected ack")
                    raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)
            else:
                if data[0] & 0b11101110 == 0x02: # INF
                    self.pni = (self.pni + 1) % 2
                    response = data[1:]
                else:
                    log.error("ISO-DEP protocol error: expected inf")
                    raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)

        while bool(data[0] & 0b00010000):
            data = chr(0xA2|self.pni) # ack
            
            for i in itertools.count(start=1):
                try:
                    data = self.clf.exchange(data, timeout)
                    if data is not None and len(data) == 0:
                        raise nfc.clf.TransmissionError
                    break
                except nfc.clf.TransmissionError:
                    if i <= self.n_retry_ack:
                        log.warning("ISO-DEP transmission error, retry #%d"%i)
                        data = bytearray([0xA2|self.pni])
                    else:
                        log.error("ISO-DEP unrecoverable transmission error")
                        raise Type4TagCommandError(nfc.tag.RECEIVE_ERROR)
                except nfc.clf.TimeoutError:
                    if i <= self.n_retry_ack:
                        log.warning("ISO-DEP timeout error, retry #%d" % i)
                        data = bytearray([0xA2|self.pni])
                    else:
                        log.error("ISO-DEP unrecoverable timeout error")
                        raise Type4TagCommandError(nfc.tag.TIMEOUT_ERROR)
                except nfc.clf.ProtocolError:
                    log.error("ISO-DEP unrecoverable protocol error")
                    raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)
                
            if data[0] & 0x01 != self.pni:
                log.error("ISO-DEP protocol error: block number")
                raise Type4TagCommandError(nfc.tag.PROTOCOL_ERROR)

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

        def _select_ndef_application(self):
            for self._aid in (ndef_aid_v2, ndef_aid_v1):
                try:
                    self.tag.send_apdu(0, 0xA4, 0x04, 0x00, self._aid)
                    log.debug("selected " + hexlify(self._aid))
                    return True
                except Type4TagCommandError as error:
                    if error.errno <= 0: break

        def _select_fid(self, fid):
            p2 = 0x00 if self._aid == ndef_aid_v1 else 0x0C
            try:
                self.tag.send_apdu(0, 0xA4, 0x00, p2, fid)
                log.debug("selected " + hexlify(fid))
                return True
            except Type4TagCommandError:
                log.debug("failed to select " + hexlify(fid))

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
            if not self._select_ndef_application():
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
            log.debug("ndef mapping version {0}.{1}".format(ver>>4, ver&15))
            log.debug("max apdu response length {0}".format(mle))
            log.debug("max apdu command length {0}".format(mlc))
            log.debug("ndef file control tlv tag {0}".format(tag))
            
            if ver >> 4 not in (1, 2, 3):
                log.debug("unsupported major ndef version")
                return False

            if not (tag, len(val)) in ((4, 6), (6, 8)):
                log.error("invalid ndef control tlv")
                return False

            ndef_control_tlv_format = ">2sHBB" if tag == 4 else ">2sIBB"
            ndef_file, mfs, rf, wf = unpack(ndef_control_tlv_format, val)
            log.debug("ndef file identifier {0}".format(hexlify(ndef_file)))
            log.debug("ndef file size limit {0}".format(mfs))
            log.debug("ndef file read flag is {0}".format(rf))
            log.debug("ndef file write flag is {0}".format(wf))

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
            if nlen is not None and len(nlen) == self._nlen_size:
                nlen = unpack(lfmt, nlen)[0]
            else: return None
            log.debug("ndef data length is {0}".format(nlen))

            data = bytearray()
            while len(data) < nlen:
                offset = self._nlen_size + len(data)
                part = self._read_binary(offset, nlen-len(data))
                if not part: return None
                data += part
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

        def _wipe_ndef_data(self, wipe=None):
            lfmt = ">I" if self._nlen_size == 4 else ">H"
            nlen = bytearray(pack(lfmt, 0))
            self._update_binary(0, nlen)
            if wipe is not None:
                offset = self._nlen_size
                data = self._capacity * chr(wipe % 256)
                while offset < len(data):
                    sent = self._update_binary(offset, buffer(data, offset))
                    if sent: offset += sent
                    else: return False
            return True
            
        def _dump_ndef_data(self):
            lines = []
            for offset in itertools.count(0, 16):
                line = self._read_binary(offset, 16)
                if line: lines.append(line)
                if line is None or len(line) < 16: break
            return lines
            
    def _is_present(self):
        try:
            self._dep.exchange(None)
            return True
        except nfc.clf.CommunicationError:
            return False

    def dump(self):
        """Returns tag data as a list of formatted strings.

        The :meth:`dump` method provides useful output only for NDEF
        formatted Type 4 Tags. Each line that is returned contains a
        hexdump of 16 octets from the NDEF data file.

        """
        return self._dump()

    def _dump(self):
        ispchr = lambda x: x >= 32 and x <= 126
        oprint = lambda o: ' '.join(['%02x' % x for x in o])
        cprint = lambda o: ''.join([chr(x) if ispchr(x) else '.' for x in o])
        lprint = lambda fmt, d, i: fmt.format(i, oprint(d), cprint(d))
        lfmt = "0x{0:04x}: {1} |{2}|"

        if self.ndef and self.ndef.is_readable:
            lines = self.ndef._dump_ndef_data()
            return [lprint(lfmt, d, i<<4) for i,d in enumerate(lines)]

        return []

    def format(self, version=None, wipe=None):
        """Erase the NDEF message on a Type 4 Tag.

        The :meth:`format` method writes the length of the NDEF
        message on a Type 4 Tag to zero, thus the tag will appear to
        be empty. If the *wipe* argument is set to some integer then
        :meth:`format` will also overwrite all user data with that
        integer (mod 256).

        Despite it's name, the :meth:`format` method can not format a
        blank tag to make it NDEF compatible; this requires
        proprietary information from the manufacturer.

        """
        return super(Type4Tag, self).format(version, wipe)

    def _format(self, version, wipe):
        if self.ndef and self.ndef.is_writeable:
            return self.ndef._wipe_ndef_data(wipe)
        return False

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
        data = self._dep.exchange(data, timeout)
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

    def __str__(self):
        hx = lambda x: str(x) if x is None else hexlify(x).upper()
        s = "{tag.__class__.__name__} MIU={tag._dep.miu} FWT={tag._dep.fwt:f}"
        return s.format(tag=self)
    
class Type4ATag(Type4Tag):
    def __init__(self, clf, target):
        super(Type4ATag, self).__init__(clf, target)
        self._nfcid = bytearray(target.sdd_res)

        log.debug("send RATS command to activate the Type 4A Tag")
        if self.clf.max_recv_data_size < 256:
            log.warning("{0} does not support fsd 256".format(self.clf))
            rats_cmd = bytearray.fromhex("E0 70")
        else:
            rats_cmd = bytearray.fromhex("E0 80")
        rats_res = self.clf.exchange(rats_cmd, timeout=0.03)
        log.debug("rcvd RATS response: {0}".format(hexlify(rats_res)))
        
        fsci, fwti = rats_res[1] & 0x0F, rats_res[3] >> 4
        if fsci > 8:
            log.warning("FSCI with RFU value in RATS_RES"); fsci = 8
        if fwti > 14:
            log.warning("FWI with RFU value in RATS_RES"); fwti = 4
        
        fsc = (16, 24, 32, 40, 48, 64, 96, 128, 256)[fsci]
        fwt = 4096 / 13.56E6 * (2**fwti)

        if fsc > self.clf.max_send_data_size:
            log.warning("{0} does not support fsc {1}".format(self.clf, fsc))
            fsc = self.clf.max_send_data_size

        log.debug("max command frame size is {0:d} byte".format(fsc))
        log.debug("max frame waiting time is {0:f}".format(fwt))

        self._dep = IsoDepInitiator(clf, fsc, fwt)
        self._extended_length_support = False

class Type4BTag(Type4Tag):
    def __init__(self, clf, target):
        super(Type4BTag, self).__init__(clf, target)
        self._nfcid = bytearray(target.sensb_res[1:5])

        log.debug("send ATTRIB command to activate the Type 4B Tag")
        if self.clf.max_recv_data_size < 256:
            log.warning("{0} does not support fsd 256".format(self.clf))
            attrib_cmd = '\x1D' + self._nfcid + '\x00\x07\x01\x00'
        else:
            attrib_cmd = '\x1D' + self._nfcid + '\x00\x08\x01\x00'
        attrib_res = self.clf.exchange(attrib_cmd, timeout=0.03)
        log.debug("rcvd ATTRIB response {0}".format(hexlify(attrib_res)))

        fsci, fwti = target.sensb_res[10] >> 4, target.sensb_res[11] >> 4
        if fsci > 8:
            log.warning("FSCI with RFU value in SENSB_RES"); fsci = 8
        if fwti > 14:
            log.warning("FWI with RFU value in SENSB_RES"); fwti = 4

        fsc = (16, 24, 32, 40, 48, 64, 96, 128, 256)[fsci]
        fwt = 4096 / 13.56E6 * (2**fwti)
        
        if fsc > self.clf.max_send_data_size:
            log.warning("{0} does not support fsc {1}".format(self.clf, fsc))
            fsc = self.clf.max_send_data_size

        log.debug("max command frame size is {0:d} byte".format(fsc))
        log.debug("max frame waiting time is {0:f}".format(fwt))

        self._dep = IsoDepInitiator(clf, fsc, fwt)
        self._extended_length_support = False

def activate(clf, target):
    if target.brty.endswith('A'):
        return Type4ATag(clf, target)
    if target.brty.endswith('B'):
        return Type4BTag(clf, target)
