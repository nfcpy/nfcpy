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

import tag

ndef_read_service = 11 # service code for NDEF reading
ndef_write_service = 9 # service code for NDEF writing

class NDEF(tag.NDEF):
    def __init__(self, tag):
        self.tag = tag
        self.data = None
        self.attr = [ord(x) for x in self.tag.read(blocks=[0])]
        if not sum(self.attr[0:14]) == self.attr[14] * 0x100 + self.attr[15]:
            log.error("checksum error in ndef attribute block")
            raise ValueError("checksum error in NDEF attribute block")
            
    @property
    def version(self):
        """The version of the NDEF mapping."""
        return "%d.%d" % (self.attr[0]>>4, self.attr[0]&0x0F)

    @property
    def capacity(self):
        """The maximum number of user bytes on the NDEF tag."""
        return (self.attr[3] * 256 + self.attr[4]) * 16

    @property
    def writeable(self):
        """Is True if new data can be written to the NDEF tag."""
        return bool(self.attr[10])

    @property
    def message(self):
        """A character string containing the NDEF message data."""
        if self.data is None:
            length = self.attr[11]*65536 + self.attr[12]*256 + self.attr[13]
            blocks = range(1, (length+15)/16 + 1)
            nb_max = self.attr[1]
            data = ""
            while len(blocks) > nb_max:
                # attr[1] has the max number of blocks for one read command
                block_list = blocks[0:nb_max]
                data += self.tag.read(blocks[0:nb_max])
                del blocks[0:nb_max]
            if len(blocks) > 0:
                data += self.tag.read(blocks)
            self.data = data[0:length]
        return self.data

    @message.setter
    def message(self, data):
        def split2(x): return [x/0x100, x%0x100]
        def split3(x): return [x/0x10000, x/0x100%0x100, x%0x100]

        if not self.writeable:
            raise IOError("tag writing disabled")

        if len(data) > self.capacity:
            raise IOError("ndef message beyond tag capacity")

        self.data = None
        self.attr[9] = 0x0F;
        self.attr[11:14] = split3(len(data))
        self.attr[14:16] = split2(sum(self.attr[0:14]))
        self.tag.write(''.join([chr(x) for x in self.attr]), [0])

        blocks = range(1, (len(data)+15)/16 + 1)
        nb_max = self.attr[2] # blocks to write at once
        length = nb_max * 16  # bytes to write at once
        offset = 0
        while len(blocks) > nb_max:
            self.tag.write(data[offset:offset+length], blocks[0:nb_max])
            del blocks[0:nb_max]
            offset += length
        if len(blocks) > 0:
            data += (-len(data) % 16) * '\x00'
            self.tag.write(data[offset:], blocks)

        self.attr[9] = 0x00; # Writing finished
        self.attr[14:16] = split2(sum(self.attr[0:14]))
        self.tag.write(''.join([chr(x) for x in self.attr]), [0])

class Type3Tag(tag.TAG):
    def __init__(self, dev, target):
        self.dev = dev
        self.idm = target["IDm"]
        self.pmm = target["PMm"]
        self.sys  = target["SYS"]
        rto, wto = self.pmm[5], self.pmm[6]
        self.rto = ((rto&0x07)+1, (rto>>3&0x07)+1, 0.302 * 4**(rto >> 6))
        self.wto = ((wto&0x07)+1, (wto>>3&0x07)+1, 0.302 * 4**(wto >> 6))
        self._ndef = None
        if self.sys == "\x12\xFC":
            try: self._ndef = NDEF(self)
            except Exception as e: log.error(str(e))

    def __str__(self):
        params = list()
        params.append(str(self.idm).encode("hex"))
        params.append(str(self.pmm).encode("hex"))
        params.append(str(self.sys).encode("hex"))
        return "Type3Tag IDm=%s PMm=%s SYS=%s" % tuple(params)

    @property
    def _is_present(self):
        """True if the tag is still within communication range."""
        rto = int((self.rto[0] + self.rto[1]) * self.rto[2]) + 5
        try:
            cmd = "\x04" + self.idm
            rsp = self.dev.tt3_exchange(chr(len(cmd)+1) + cmd, rto)
            return rsp.startswith(chr(len(rsp)) + "\x05" + self.idm)
        except IOError:
            pass
        try:
            cmd = "\x00" + self.sys + "\x00\x00"
            rsp = self.dev.tt3_exchange(chr(len(cmd)+1) + cmd, rto)
            return rsp.startswith(chr(len(rsp)) + "\x01" + self.idm)
        except IOError:
            pass

    def read(self, blocks, service=ndef_read_service):
        """Read service data blocks from tag. The *service* argument is the
        tag type 3 service code to use, 0x000b for reading NDEF. The *blocks*
        argument holds a list of integers representing the block numbers to
        read. The data is returned as a character string."""

        log.debug("read blocks " + repr(blocks))
        cmd  = "\x06" + self.idm # ReadWithoutEncryption
        cmd += "\x01" + ("%02X%02X" % (service%256,service/256)).decode("hex")
        cmd += chr(len(blocks))
        for block in blocks:
            if block < 256: cmd += "\x80" + chr(block)
            else: cmd += "\x00" + chr(block%256) + chr(block/256)
        rto = int((self.rto[0] + self.rto[1] * len(blocks)) * self.rto[2]) + 5
        log.debug("read timeout is {0} ms".format(rto))
        resp = self.dev.tt3_exchange(chr(len(cmd)+1) + cmd, rto)
        if not resp.startswith(chr(len(resp)) + "\x07" + self.idm):
            log.debug("invalid data")
            raise IOError("invalid data")
        if resp[11] != "\x00":
            log.debug("tt3 command error "+resp[11:13].encode("hex"))
            raise IOError("tt3 command error "+resp[11:13].encode("hex"))
        return resp[13:]

    def write(self, data, blocks, service=ndef_write_service):
        """Write service data blocks to tag. The *service* argument is the
        tag type 3 service code to use, 0x0009 for writing NDEF. The *blocks*
        argument holds a list of integers representing the block numbers to
        write. The *data* argument must be a character string with length
        equal to the number of blocks times 16."""

        log.debug("write blocks " + repr(blocks))
        if len(data) != len(blocks) * 16:
            log.error("data length does not match block-count * 16")
            raise ValueError("invalid data length for given number of blocks")
        cmd  = "\x08" + self.idm # ReadWithoutEncryption
        cmd += "\x01" + ("%02X%02X" % (service%256,service/256)).decode("hex")
        cmd += chr(len(blocks))
        for block in blocks:
            if block < 256: cmd += "\x80" + chr(block)
            else: cmd += "\x00" + chr(block%256) + chr(block/256)
        cmd += data
        wto = int((self.wto[0] + self.wto[1] * len(blocks)) * self.wto[2]) + 5
        log.debug("write timeout is {0} ms".format(wto))
        resp = self.dev.tt3_exchange(chr(len(cmd)+1) + cmd, wto)
        if not resp.startswith(chr(len(resp)) + "\x09" + self.idm):
            log.debug("invalid data")
            raise IOError("invalid data")
        if resp[11] != "\x00":
            log.debug("tt3 command error "+resp[11:13].encode("hex"))
            raise IOError("tt3 command error "+resp[11:13].encode("hex"))
        return

