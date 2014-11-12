# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2014 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
# Driver for the a NXP PN532 based contactless reader
#
import logging
log = logging.getLogger(__name__)

import time
import struct

import pn53x
from pn53x import ChipsetError
            
class Chipset(pn53x.Chipset):
    def read_register(self, addr):
        if type(addr) is int: addr = [addr]
        data = ''.join([struct.pack(">H", a) for a in addr])
        data = self.command(0x06, data, timeout=250)
        if data is None:
            raise ChipsetError(None)
        return data if len(data) > 1 else data[0]
            
    def write_register(self, addr, rval):
        if type(addr) is int: addr = [addr]
        if type(rval) is int: rval = [rval]
        data = ''.join([struct.pack(">HB", a, v) for a, v in zip(addr, rval)])
        self.command(0x08, data, timeout=250)

class Device(pn53x.Device):
    pass

def init(transport):
    chipset = Chipset(transport)
    device = Device(chipset)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device
