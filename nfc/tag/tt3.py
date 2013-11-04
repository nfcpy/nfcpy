# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

import nfc.tag
import nfc.clf
import nfc.ndef

ndef_read_service = 11 # service code for NDEF reading
ndef_write_service = 9 # service code for NDEF writing

def trace(func):
    def traced_func(*args, **kwargs):
        _args = "{0}".format(args[1:]).strip("(),")
        if kwargs:
            _args = ', '.join([_args, "{0}".format(kwargs).strip("{}")])
        log.debug("{func}({args})".format(func=func.__name__, args=_args))
        return func(*args, **kwargs)
    return traced_func

class NdefAttributeData:
    def __init__(self, init=16):
        attr = bytearray(init)
        self.version = "{0}.{1}".format(attr[0] >> 4, attr[0] & 15)
        self.nbr = attr[1]
        self.nbw = attr[2]
        self.capacity = (attr[3] * 256 + attr[4]) * 16
        self.rfu = attr[5:9]
        self.writing = bool(attr[9])
        self.writeable = bool(attr[10])
        self.length = attr[11]<<16 | attr[12]<<8 | attr[13]
        self.checksum = attr[14:16]
        self.valid = sum(attr[0:14]) == attr[14] << 8 | attr[15]
        self.wf = 0x0F
        self.rw = 0x01

    def __str__(self):
        attr = bytearray(16)
        vers = map(lambda x: int(x) & 15, self.version.split('.'))
        maxb = ((self.capacity + 15) // 16) & 0xffff
        attr[0] = vers[0] << 4 | vers[1]
        attr[1] = self.nbr
        attr[2] = self.nbw
        attr[3] = maxb >> 8
        attr[4] = maxb & 0xff
        attr[5:9] = self.rfu
        attr[9] = self.wf if self.writing else 0
        attr[10] = self.rw if self.writeable else 0
        attr[11] = self.length >> 16 & 0xff
        attr[12] = self.length >> 8 & 0xff
        attr[13] = self.length & 0xff
        checksum = sum(attr[0:14])
        attr[14] = checksum >> 8
        attr[15] = checksum & 0xff
        return str(attr)

    def pretty(self):
        return ("Ver={a.version!r} Nbr={a.nbr} Nbw={a.nbw} Nmaxb={nmaxb} "
                "WF={a.wf:02X}h RW={a.rw:02X}h Ln={a.length} Checksum={cs}h"
                .format(a=self, nmaxb=self.capacity/16,
                        cs=str(self.checksum).encode("hex").upper()))
    
class NDEF(object):
    def __init__(self, tag):
        self.tag = tag
        self._attr = None
        self._data = ''
        if not self.attr.valid:
            raise ValueError("invalid ndef attribute block")
        self.changed # force initial read
            
    @property
    def version(self):
        """The version of the NDEF mapping."""
        return self.attr.version

    @property
    def capacity(self):
        """The maximum number of user bytes on the NDEF tag."""
        return self.attr.capacity

    @property
    def readable(self):
        """Is True if data can be read from the NDEF tag."""
        return self.attr.nbr > 0

    @property
    def writeable(self):
        """Is True if data can be written to the NDEF tag."""
        return self.attr.writeable and self.attr.nbw > 0

    @property
    def length(self):
        """NDEF message data length."""
        return len(self._data)
        
    @property
    def attr(self):
        if self._attr is None:
            self._attr = NdefAttributeData(self.tag.read(blocks=[0]))
            if not self._attr.valid:
                log.error("checksum error in ndef attribute block")
        return self._attr

    @property
    def changed(self):
        """True if the message has changed since last read."""
        self._attr = None
        blocks = range(1, (self.attr.length + 15) / 16 + 1)
        data = ""
        while len(blocks) > self.attr.nbr:
            block_list = blocks[0:self.attr.nbr]
            data += self.tag.read(blocks[0:self.attr.nbr])
            del blocks[0:self.attr.nbr]
        if len(blocks) > 0:
            data += self.tag.read(blocks)
        old_data, self._data = self._data, data[0:self.attr.length]
        return self._data != old_data

    @property
    def message(self):
        """An NDEF message object (an empty record message if tag is empty)."""
        try: return nfc.ndef.Message(str(self._data))
        except nfc.ndef.parser_error: pass
        return nfc.ndef.Message(nfc.ndef.Record())

    @message.setter
    def message(self, msg):
        if not self.writeable:
            raise nfc.tag.AccessError
        
        data = str(msg)
        if len(data) > self.capacity:
            raise nfc.tag.CapacityError

        self.attr.writing = True
        self.attr.length = len(data)
        self.tag.write(str(self.attr), [0])

        blocks = range(1, (len(data)+15)/16 + 1)
        nb_max = self.attr.nbw # blocks to write at once
        length = nb_max * 16  # bytes to write at once
        offset = 0
        while len(blocks) > nb_max:
            self.tag.write(data[offset:offset+length], blocks[0:nb_max])
            del blocks[0:nb_max]
            offset += length
        if len(blocks) > 0:
            data += (-len(data) % 16) * '\x00'
            self.tag.write(data[offset:], blocks)

        self.attr.writing = False # writing finished
        self.tag.write(str(self.attr), [0])

class Type3Tag(object):
    type = "Type3Tag"
    
    def __init__(self, clf, target):
        self.clf = clf
        self.idm = target.idm
        self.pmm = target.pmm
        self.sys = target.sys

        if self.sys != "\x12\xFC" and self.pmm[0:2] != "\x01\xE0":
            idm, pmm = self.poll(0x12FC)
            if idm is not None and pmm is not None:
                self.sys = bytearray([0x12, 0xFC])
                self.idm, self.pmm = idm, pmm

        rto, wto = self.pmm[5], self.pmm[6]
        self.rto = ((rto&0x07)+1, (rto>>3&0x07)+1, 302E-6 * 4**(rto >> 6))
        self.wto = ((wto&0x07)+1, (wto>>3&0x07)+1, 302E-6 * 4**(wto >> 6))

        try:
            self.ndef = NDEF(self) if self.sys == "\x12\xFC" else None
        except Exception as error:
            log.error("while reading ndef: {0!r}".format(error))
            self.ndef = None

    def __str__(self):
        params = list()
        params.append(str(self.idm).encode("hex"))
        params.append(str(self.pmm).encode("hex"))
        params.append(str(self.sys).encode("hex"))
        return "Type3Tag IDm=%s PMm=%s SYS=%s" % tuple(params)

    @property
    def is_present(self):
        """True if the tag is still within communication range."""
        rto = ((self.rto[0] + self.rto[1]) * self.rto[2]) + 5E-3
        try:
            cmd = "\x04" + self.idm
            return bool(self.clf.exchange(chr(len(cmd)+1) + cmd, timeout=rto))
        except nfc.clf.TimeoutError: pass
        except nfc.clf.TransmissionError: return False
        
        try:
            cmd = "\x00" + self.sys + "\x00\x00"
            return bool(self.clf.exchange(chr(len(cmd)+1) + cmd, timeout=rto))
        except nfc.clf.TimeoutError: pass
        except nfc.clf.TransmissionError: return False
        
        return False

    def poll(self, system_code):
        """Send the polling command to recognize a system on the card. The 
        *system_code* may be specified as a short integer or as a string or
        bytearray of length 2. The return value is the tuple of the two 
        bytearrays (idm, pmm) if the requested system is present or the tuple
        (None, None) if not."""

        if isinstance(system_code, int):
            system_code = bytearray([system_code/256, system_code%256])

        log.debug("poll for system {0}".format(str(system_code).encode("hex")))
        cmd = bytearray("\x06\x00" + system_code + "\x00\x00")

        try:
            rsp = self.clf.exchange(cmd, timeout=0.01)
        except nfc.clf.TimeoutError as error:
            return None, None
        except nfc.clf.DigitalProtocolError as error:
            raise IOError(repr(error))
        if not rsp.startswith(chr(len(rsp)) + "\x01"):
            raise IOError("tt3 response error")

        log.debug("<<< {0}".format(str(rsp).encode("hex")))
        return rsp[2:10], rsp[10:18]

    def read(self, blocks, service=ndef_read_service):
        """Read service data blocks from tag. The *service* argument is the
        tag type 3 service code to use, 0x000b for reading NDEF. The *blocks*
        argument holds a list of integers representing the block numbers to
        read. The data is returned as a character string."""

        log.debug("read blocks {1} from service {0}".format(service, blocks))
        cmd  = "\x06" + self.idm # ReadWithoutEncryption
        cmd += "\x01" + ("%02X%02X" % (service%256,service/256)).decode("hex")
        cmd += chr(len(blocks))
        for block in blocks:
            if block < 256: cmd += "\x80" + chr(block)
            else: cmd += "\x00" + chr(block%256) + chr(block/256)
        rto = ((self.rto[0] + self.rto[1] * len(blocks)) * self.rto[2]) + 5E-3
        log.debug("read timeout is {0} sec".format(rto))
        try:
            rsp = self.clf.exchange(chr(len(cmd)+1) + cmd, timeout=rto)
        except nfc.clf.DigitalProtocolError as error:
            raise IOError(repr(error))
        if not rsp.startswith(chr(len(rsp)) + "\x07" + self.idm):
            raise IOError("tt3 response error")
        if rsp[10] != 0 or rsp[11] != 0:
            raise IOError("tt3 cmd error {0:02x} {1:02x}".format(*rsp[10:12]))
        data = str(rsp[13:])
        log.debug("<<< {0}".format(data.encode("hex")))
        return data

    def write(self, data, blocks, service=ndef_write_service):
        """Write service data blocks to tag. The *service* argument is the
        tag type 3 service code to use, 0x0009 for writing NDEF. The *blocks*
        argument holds a list of integers representing the block numbers to
        write. The *data* argument must be a character string with length
        equal to the number of blocks times 16."""

        log.debug("write blocks {1} to service {0}".format(service, blocks))
        if len(data) != len(blocks) * 16:
            log.error("data length does not match block-count * 16")
            raise ValueError("invalid data length for given number of blocks")
        log.debug(">>> {0}".format(str(data).encode("hex")))
        cmd  = "\x08" + self.idm # ReadWithoutEncryption
        cmd += "\x01" + ("%02X%02X" % (service%256,service/256)).decode("hex")
        cmd += chr(len(blocks))
        for block in blocks:
            if block < 256: cmd += "\x80" + chr(block)
            else: cmd += "\x00" + chr(block%256) + chr(block/256)
        cmd += data
        wto = ((self.wto[0] + self.wto[1] * len(blocks)) * self.wto[2]) + 5E-3
        log.debug("write timeout is {0} sec".format(wto))
        try:
            rsp = self.clf.exchange(chr(len(cmd)+1)+cmd, timeout=wto)
        except nfc.clf.TimeoutError:
            raise IOError("communication timeout")
        if not rsp.startswith(chr(len(rsp)) + "\x09" + self.idm):
            raise IOError("tt3 response error")
        if rsp[10] != 0 or rsp[11] != 0:
            raise IOError("tt3 cmd error {0:02x} {1:02x}".format(*rsp[10:12]))

class Type3TagEmulation(object):
    def __init__(self, clf, target):
        self.clf = clf
        self.idm = target.idm
        self.pmm = target.pmm
        self.sys = target.sys
        self.services = dict()

    def __str__(self):
        return "Type3TagEmulation IDm={0} PMm={1} SYS={2}".format(
            str(self.idm).encode("hex"), str(self.pmm).encode("hex"),
            str(self.sys).encode("hex"))

    def add_service(self, service_code, block_read_func, block_write_func):
        self.services[service_code] = (block_read_func, block_write_func)

    def process_command(self, cmd):
        log.debug("cmd: " + (str(cmd).encode("hex") if cmd else str(cmd)))
        if len(cmd) != cmd[0]:
            log.error("tt3 command length error")
            return None
        if tuple(cmd[0:4]) in [(6, 0, 255, 255), (6, 0) + tuple(self.sys)]:
            log.debug("process 'polling' command")
            rsp = self.polling(cmd[2:])
            return bytearray([2 + len(rsp), 0x01]) + rsp
        if cmd[2:10] == self.idm:
            if cmd[1] == 0x04:
                log.debug("process 'request response' command")
                rsp = self.request_response(cmd[10:])
                return bytearray([10 + len(rsp), 0x05]) + self.idm + rsp
            if cmd[1] == 0x06:
                log.debug("process 'read without encryption' command")
                rsp = self.read_without_encryption(cmd[10:])
                return bytearray([10 + len(rsp), 0x07]) + self.idm + rsp
            if cmd[1] == 0x08:
                log.debug("process 'write without encryption' command")
                rsp = self.write_without_encryption(cmd[10:])
                return bytearray([10 + len(rsp), 0x09]) + self.idm + rsp
            if cmd[1] == 0x0C:
                log.debug("process 'request system code' command")
                rsp = self.request_system_code(cmd[10:])
                return bytearray([10 + len(rsp), 0x0D]) + self.idm + rsp

    def send_response(self, rsp, timeout):
        if rsp: log.debug("rsp: " + str(rsp).encode("hex"))
        return self.clf.exchange(rsp, timeout)

    def polling(self, cmd_data):
        if cmd_data[2] == 1:
            rsp = self.idm + self.pmm + self.sys
        else:
            rsp = self.idm + self.pmm
        return rsp
    
    def request_response(self, cmd_data):
        return bytearray([0])
    
    def read_without_encryption(self, cmd_data):
        service_list = cmd_data.pop(0) * [[None, None]]
        for i in range(len(service_list)):
            service_code = cmd_data[1] << 8 | cmd_data[0]
            if not service_code in self.services.keys():
                return bytearray([0xFF, 0xA1])
            service_list[i] = [service_code, 0]
            del cmd_data[0:2]
        
        service_block_list = cmd_data.pop(0) * [None]
        if len(service_block_list) > 15:
            return bytearray([0xFF, 0xA2])
        for i in range(len(service_block_list)):
            try:
                service_list_item = service_list[cmd_data[0] & 0x0F]
                service_code = service_list_item[0]
                service_list_item[1] += 1
            except IndexError:
                return bytearray([1<<(i%8), 0xA3])
            if cmd_data[0] >= 128:
                block_number = cmd_data[1]
                del cmd_data[0:2]
            else:
                block_number = cmd_data[2] << 8 | cmd_data[1]
                del cmd_data[0:3]
            service_block_list[i] = [service_code, block_number, 0]

        service_block_count = dict(service_list)
        for service_block_list_item in service_block_list:
            service_code = service_block_list_item[0]
            service_block_list_item[2] = service_block_count[service_code]
            
        block_data = bytearray()
        for i, service_block_list_item in enumerate(service_block_list):
            service_code, block_number, block_count = service_block_list_item
            # rb (read begin) and re (read end) mark an atomic read
            rb = bool(block_count == service_block_count[service_code])
            service_block_count[service_code] -= 1
            re = bool(service_block_count[service_code] == 0)
            read_func, write_func = self.services[service_code]
            one_block_data = read_func(block_number, rb, re)
            if one_block_data is None:
                return bytearray([1<<(i%8), 0xA2, 0])
            block_data.extend(one_block_data)
            
        return bytearray([0, 0, len(block_data)/16]) + block_data

    def write_without_encryption(self, cmd_data):
        service_list = cmd_data.pop(0) * [[None, None]]
        for i in range(len(service_list)):
            service_code = cmd_data[1] << 8 | cmd_data[0]
            if not service_code in self.services.keys():
                return bytearray([255, 0xA1])
            service_list[i] = [service_code, 0]
            del cmd_data[0:2]
            
        service_block_list = cmd_data.pop(0) * [None]
        for i in range(len(service_block_list)):
            try:
                service_list_item = service_list[cmd_data[0] & 0x0F]
                service_code = service_list_item[0]
                service_list_item[1] += 1
            except IndexError:
                return bytearray([1<<(i%8), 0xA3])
            if cmd_data[0] >= 128:
                block_number = cmd_data[1]
                del cmd_data[0:2]
            else:
                block_number = cmd_data[2] << 8 | cmd_data[1]
                del cmd_data[0:3]
            service_block_list[i] = [service_code, block_number, 0]

        service_block_count = dict(service_list)
        for service_block_list_item in service_block_list:
            service_code = service_block_list_item[0]
            service_block_list_item[2] = service_block_count[service_code]
            
        block_data = cmd_data[0:]
        if len(block_data) % 16 != 0:
            return bytearray([255, 0xA2])
            
        for i, service_block_list_item in enumerate(service_block_list):
            service_code, block_number, block_count = service_block_list_item
            # wb (write begin) and we (write end) mark an atomic write
            wb = bool(block_count == service_block_count[service_code])
            service_block_count[service_code] -= 1
            we = bool(service_block_count[service_code] == 0)
            read_func, write_func = self.services[service_code]
            if not write_func(block_number, block_data[i*16:(i+1)*16], wb, we):
                return bytearray([1<<(i%8), 0xA2, 0])

        return bytearray([0, 0])

    @trace
    def request_system_code(self, cmd_data):
        return '\x01' + self.sys
