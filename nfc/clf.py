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
import nfc.dep
from tt1 import Type1Tag
from tt2 import Type2Tag
from tt3 import Type3Tag, Type3TagEmulation
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

        Raises :exc:`LookupError` if no available reader device is found.
        """
        
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

        Returns :class:`nfc.dep.Initiator` or a subtype of
        :class:`nfc.TAG` if a target was found, else :const:`None`.
        """
        
        target = self.dev.poll(protocol_data)
        if target is not None:
            log.debug("found target {0}".format(target))
            if target.get("type") == "DEP":
                return nfc.dep.Initiator(self, target['data'], target['rwt'])
            if target.get("type") == "TT1":
                return Type1Tag(self.dev, target)
            if target.get("type") == "TT2":
                return Type2Tag(self.dev, target)
            if target.get("type") == "TT3":
                return Type3Tag(self, target)
            if target.get("type") == "TT4":
                return Type4Tag(self.dev, target)

    def listen(self, timeout, *targets):
        """Wait *timeout* seconds to become initialized by a peer
        device as one of the targets listed in *target_list*. Current
        valid targets are :class:`nfc.dep.Target` and any subclass
        of :class:`nfc.tag.TagEmulation`. Note that not all
        contactless frontends support tag emulation. If the timeout
        expired before initialization the return value is
        :const:`None`, otherwise it is the initialized target object.
        """
        
        if len(targets) == 0:
            raise ValueError("need at least one target to listen for")
        
        if len(targets) > 1:
            raise NotImplemented("can't yet listen for multiple targets")

        target = targets[0]
        
        if isinstance(target, nfc.dep.Target):
            general_bytes = self.dev.listen(target.general_bytes, timeout)
            if general_bytes is not None:
                log.debug("got nfcip1 general bytes " + data.encode("hex"))
                target._gb = general_bytes
                target.clf = self
                return target
        elif isinstance(target, Type3TagEmulation):
            idm, pmm, sc, br = target.idm, target.pmm, target.sc, target.br
            data = self.dev.listen_nfcf(idm, pmm, sc, br, timeout)
            if data is not None:
                target.cmd = data
                target.clf = self
                return target
        else:
            raise ValueError("invalid or unsupported listen target type")
        
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        if self.dev is not None:
            s = "{dev.vendor} {dev.product} on {dev.path}"
            return s.format(dev=self.dev)
        else: return self.__repr__()
