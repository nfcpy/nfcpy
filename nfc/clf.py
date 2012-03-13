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

import dev
from dep import DEPTarget, DEPInitiator
from tt1 import Type1Tag
from tt2 import Type2Tag
from tt3 import Type3Tag
from tt4 import Type4Tag

class ContactlessFrontend(object):
    """Access a nearfield communication reader device."""

    def __init__(self, path=None):
        """Open contactless reader device identified by *path*. If
        *path* is not :const:`None` (default) or an empty string, the
        first available device is used. Otherwise *path* must match
        one of the following expressions:

        * **usb[:vendor[:product]]** with *vendor* and *product* id (hex)
        * **usb[:bus[:device]]** with usb *bus* and *device* number (dec)
        * **tty[:usb][:port]** with usb serial *port* number (dec)
        * **tty[:com][:port]** with serial *port* number (dec)

        Raises :exc:`LookupError` if no available reader device was
        found."""
        
        if not path: log.info("searching for a usable reader")
        else: log.info("searching for reader with path '{0}'".format(path))
        
        self.dev = dev.connect(path)
        if self.dev is None:
            msg = "no reader found"
            msg = " ".join([msg, "at {0}".format(path) if path else ""])
            log.error(msg)
            raise LookupError("couldn't find any usable nfc reader")

        log.info("using {0}".format(self.dev))

    def close(self):
        """Close the contacless reader device."""
        self.dev.close()
        self.dev = None

    def poll(self, protocol_data=None):
        """Search for a contactless target in proximity of the
        reader. The *protocol_data* argument determines if peer
        devices shall be included in the search. Without
        *protocol_data* only contactless tags will be considered. If
        *protocol_data* is present it must be a string which is sent
        to the peer device in the NFC-DEP initialization phase.

        Returns :class:`nfc.DEPInitiator` or a subtype of
        :class:`nfc.TAG` if a target was found, else :const:`None`.
        """
        
        target = self.dev.poll(protocol_data)
        if target is not None:
            log.debug("found target {0}".format(target))
            if target.get("type") == "DEP":
                return DEPInitiator(self.dev, target['data'])
            if target.get("type") == "TT1":
                return Type1Tag(self.dev, target)
            if target.get("type") == "TT2":
                return Type2Tag(self.dev, target)
            if target.get("type") == "TT3":
                return Type3Tag(self.dev, target)
            if target.get("type") == "TT4":
                return Type4Tag(self.dev, target)

    def listen(self, timeout, protocol_data):
        """Wait to become initialized by a peer device. The *timeout*
        value is in milliseconds and determines the approximate time
        the reader will stay discoverable. The *protocol_data*
        parameter must be byte string that is sent to the remote
        device during initialization.
        
        Returns :class:`nfc.DEPTarget` if initialized else :const:`None`."""
        
        data = self.dev.listen(protocol_data, timeout)
        if not data is None:
            log.debug("got dep master, general bytes " + data.encode("hex"))
            return DEPTarget(self.dev, data)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        if self.dev is not None:
            s = "{dev.vendor} {dev.product} on {dev.path}"
            return s.format(dev=self.dev)
        else: return self.__repr__()
