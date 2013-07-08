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
#
# Device driver for Sony RC-S330/360/370 contactless reader
#
import logging
log = logging.getLogger(__name__)

import time
import struct

import pn53x
import nfc.clf

class ChipsetError(pn53x.ChipsetError):
    pass

class Chipset(pn53x.Chipset):
    ACK = pn53x.Chipset.ACK
    
    def __init__(self, transport):
        super(Chipset, self).__init__(transport)
        self.CMD[0x18] = "ResetCommand"
        self.reset_mode()
        
    def diagnose(self, test, test_data=None):
        if test == "line":
            if test_data is None: test_data = ""
            data = self.command(0x00, chr(0) + test_data)
            if data is None: raise ChipsetError(data)
            return data == test_data
        raise ValueError("unknown diagnose test {0!r}".format(test))

    def reset_mode(self):
        self.command(0x18, [1])
        self.transport.write(Chipset.ACK)
        time.sleep(0.010)

    def read_register(self, addr):
        if type(addr) is int: addr = [addr]
        addr = ''.join([struct.pack(">H", x) for x in addr])
        return self.command(0x06, addr)
    
    def in_data_exchange_tt3(self, data, timeout, *args, **kwargs):
        data = self.command(0x42, data, timeout)
        if data is None or data[0] != 0:
            raise ChipsetError(data)
        return data[1:], False

class Device(pn53x.Device):
    def __init__(self, chipset):
        super(Device, self).__init__(chipset)

        #cfg_data = chr(self._rwt) + chr(self._wtx) + "\x08"
        #self.dev.rf_configuration(0x82, cfg_data)
        #self.dev.command(0x08, "\x63\x0d\x00")
        #regs = self.dev.read_register(range(0xa01b, 0xa023))
        #self.dev.rf_configuration(0x0b, regs)

    def close(self):
        self.chipset.reset_mode()
        super(Device, self).close()

    def sense(self, *args, **kwargs):
        # RC-S956 requires to use InCommunicateThru for TT3 card commands
        self.chipset.reset_mode()
        target = super(Device, self).sense(*args, **kwargs)
        self.chipset.in_data_exchange = \
            self.chipset.in_data_exchange_tt3 if type(target) is nfc.clf.TTF \
            else super(Chipset, self.chipset).in_data_exchange
        return target
    
    def listen_dep(self, *args, **kwargs):
        # RS-S956 firmware bug requires SENS_RES="0101". This is currently
        # used in pn53x.py, make sure that keeps or implement it here.
        self.chipset.reset_mode()
        return super(Device, self).listen_dep(*args, **kwargs)
        
    def dep_get_data(self, timeout):
        if self.dev.get_general_status()[4] == 4:
            # except first time, initiator cmd is received in set data
            timeout = 100
        return super(Device, self).dep_get_data(timeout)

    def dep_set_data(self, data, timeout):
        return super(Device, self).dep_set_data(data, timeout)

def init(transport):
    # write ack to perform a soft reset
    # raises IOError(EACCES) if we're second
    transport.write(Chipset.ACK)
    
    chipset = Chipset(transport)
    device = Device(chipset)
    
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    if device._device_name is None:
        device._device_name = "RC-S330"
    
    return device
