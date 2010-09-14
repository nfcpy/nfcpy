# -----------------------------------------------------------------------------
# Copyright 2009,2010 Stephen Tiedemann <stephen.tiedemann@googlemail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they 
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# http://ec.europa.eu/idabc/eupl
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

    def __del__(self):
        del self.dev

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

        if not general_bytes is None:
            data = self.dev.poll_dep(general_bytes)
            if not data is None: 
                log.debug("got dep target, general bytes " + data.encode("hex"))
                return DEPInitiator(self.dev, data)

        data = self.dev.poll_tt3()
        if data and len(data) == 18:
            idm = data[0:8]; pmm = data[8:16]; sc = data[16:18]
            log.debug("got type 3 tag, service code " + sc.encode("hex"))
            return Type3Tag(self.dev, idm, pmm, sc)

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


