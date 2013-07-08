# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2011-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
# Driver for the a NXP PN531 based contactless reader
#
import logging
log = logging.getLogger(__name__)

import time
import pn53x
from pn53x import ChipsetError
            
class Chipset(pn53x.Chipset):
    pass
            
class Device(pn53x.Device):
    def __init__(self, bus):
        super(Device, self).__init__(bus)

    def close(self):
        self.chipset.close()

    def listen_dep(self, target, timeout):
        # PN531 screws up in target mode, only one run is successful.
        # Thereafter the USB descriptor and whatever else is broken.
        log.warning("listen mode is disabled for this device")
        time.sleep(timeout)
        return None

def init(transport):
    chipset = Chipset(transport)
    device = Device(chipset)
    device._vendor_name = transport.manufacturer_name
    device._device_name = transport.product_name
    return device
