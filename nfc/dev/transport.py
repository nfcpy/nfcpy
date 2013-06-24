# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2012 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
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
# transport.py
#

import logging
log = logging.getLogger(__name__)

import sys
from usb import USBError

class usb(object):
    def __init__(self, dev):
        self.dh = dev.open()
        self.usb_out = None
        self.usb_inp = None
        try:
            self.dh.setConfiguration(dev.configurations[0])
            self.dh.claimInterface(0)
        except USBError:
            raise IOError("unusable device")
        intf = dev.configurations[0].interfaces[0]
        self.usb_out = intf[0].endpoints[0].address
        self.usb_inp = intf[0].endpoints[1].address

        # try to get chip into a good state
        self.write(bytearray("\x00\x00\xFF\x00\xFF\x00")) # ack

    def close(self):
        self.dh.releaseInterface()
        self.dh = None

    def write(self, frame):
        if self.dh is not None and self.usb_out is not None:
            log.debug(">>> " + str(frame).encode("hex"))
            self.dh.bulkWrite(self.usb_out, frame)
            if len(frame) % 64 == 0:
                # send zero-length frame to end bulk transfer
                self.dh.bulkWrite(self.usb_out, '')

    def read(self, timeout):
        if self.dh is not None and self.usb_inp is not None:
            try: frame = self.dh.bulkRead(self.usb_inp, 300, timeout)
            except USBError as error:
                timeout_messages = ("No error", "Connection timed out",
                                    "usb_reap: timeout error")
                if error.args[0] in timeout_messages:
                    # normal timeout conditions (#1,2 Linux, #3 Windows)
                    return None
                usb_err = "could not set config 1: Device or resource busy"
                if error.args[0] == usb_err:
                    # timeout error if two readers used on same computer
                    return None
                log.error(error.args[0])
                return None
            else:
                frame = bytearray(frame)
                log.debug("<<< " + str(frame).encode("hex"))
                return frame

