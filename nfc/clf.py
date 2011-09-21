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
from tt2 import Type2Tag
from tt3 import Type3Tag

class ContactlessFrontend(object):
    """Contactless frontend is an abstraction of nearfield
    communication hardware, commonly called contactless readers. Upon
    object instantiation, contactless readers are searched and the
    first usable is claimed. Raises a LookupError exception if no
    reader was found."""

    def __init__(self, probe=[]):
        self.dev = None
        if type(probe) is str:
            probe = [probe]
        if not probe:
            probe = dev.__all__
        for name in probe:
            device = __import__("dev."+name, globals(), {}, ["device"]).device
            try: self.dev = device()
            except LookupError: pass
            else: break

        if self.dev is None:
            raise LookupError("couldn't find any usable nfc reader")

        log.debug("using driver " + repr(self.dev))

    def close(self):
        """Close the contacless reader device."""
        self.dev.close()

    def poll(self, general_bytes=None):
        """Search for a contactless target. Depending on the target
        found, poll returns an instance of :class:`nfc.DEPTarget`,
        :class:`nfc.Type1Tag`, :class:`nfc.Type2Tag` or
        :class:`nfc.Type3Tag`.  The parameter *general_bytes* may be
        used to specify the string of bytes that shall be send to an
        NFCIP-1 target device as part of the attribute request
        command. The *general_bytes* may be an empty string. If
        *general_bytes* is set to *None*, poll() will only search for
        contactless tags, i.e. not for NFCIP-1 devices."""

        target = self.dev.poll(general_bytes)
        if target is not None:
            log.debug("found target {0}".format(target))
            if target.get("type") == "DEP":
                return DEPInitiator(self.dev, target['data'])
            if target.get("type") == "TT1":
                log.info("support for type 1 tag not yet implemented")
                return None
            if target.get("type") == "TT2":
                return Type2Tag(self.dev, target)
            if target.get("type") == "TT3":
                return Type3Tag(self.dev, target)
            if target.get("type") == "TT4":
                log.info("support for type 4 tag not yet implemented")
                return None

    def listen(self, timeout, general_bytes=str()):
        """Wait *timeout* milliseconds for becoming initialized by a
        remote peer.  Returns an instance of :class:`nfc.DEPInitiator`
        on success, else None.  The parameter *general_bytes*, if
        supplied, is a string of bytes which are send to an NFCIP-1
        initiator as part of the ATR response."""

        data = self.dev.listen(general_bytes, timeout)
        if not data is None:
            log.debug("got dep master, general bytes " + data.encode("hex"))
            return DEPTarget(self.dev, data)


