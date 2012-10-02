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
#
# rcs956.py - common stuff for Sony RC-S956 based NFC readers
#

import logging
log = logging.getLogger(__name__)

import time
import struct
import pn53x

class rcs956(pn53x.pn53x):
    def __init__(self, bus):
        super(rcs956, self).__init__(bus)
        self.reset_mode()
        
    def diagnose(self, num_tst, in_param=""):
        return self.command(0x00, chr(num_tst) + in_param)

    def reset_mode(self):
        self.command(0x18, [1])
        self.bus.write(pn53x.pn53x.ACK)
        time.sleep(0.010)

    def read_register(self, addr):
        if type(addr) is int: addr = [addr]
        addr = ''.join([struct.pack(">H", a) for a in addr])
        return self.command(0x06, addr)

class Device(pn53x.Device):
    def __init__(self, dev):
        super(Device, self).__init__(dev)

        self.dev.reset_mode()
        cfg_data = chr(self._rwt) + chr(self._wtx) + "\x08"
        self.dev.rf_configuration(0x82, cfg_data)
        self.dev.command(0x08, "\x63\x0d\x00")
        regs = self.dev.read_register(range(0xa01b, 0xa023))
        self.dev.rf_configuration(0x0b, regs)

    def close(self):
        self.dev.reset_mode()
        super(Device, self).close()
    
    def poll_nfca(self):
        self.dev.reset_mode()
        return super(Device, self).poll_nfca()

    def poll_nfcb(self):
        self.dev.reset_mode()
        return super(Device, self).poll_nfcb()
    
    def poll_nfcf(self):
        self.dev.reset_mode()
        return super(Device, self).poll_nfcf()

    def poll_dep(self, general_bytes):
        self.dev.reset_mode()
        return super(Device, self).poll_dep(general_bytes)

    def listen(self, general_bytes, timeout):
        self.dev.reset_mode()
        try:
            data = super(Device, self).listen(general_bytes, timeout)
        except pn53x.NoResponse:
            self.dev.bus.write(pn53x.pn53x.ACK)
        else:
            if self.dev.get_general_status()[4] == 3:
                data[0] |= 0x4 # initialized as p2p target
            speed = ("106", "212", "424")[(data[0]>>4) & 0x07]
            cmode = ("passive", "active", "passive")[data[0] & 0x03]
            ttype = ("card", "p2p")[bool(data[0] & 0x04)]
            info = "activated as {0} target in {1} kbps {2} mode"
            log.info(info.format(ttype, speed, cmode))
            return str(data[18:])

    def dep_get_data(self, timeout):
        if self.dev.get_general_status()[4] == 4:
            # except first time, initiator cmd is received in set data
            timeout = 100
        return super(Device, self).dep_get_data(timeout)

    def dep_set_data(self, data, timeout):
        return super(Device, self).dep_set_data(data, timeout)

