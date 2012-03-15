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

class NDEF(object):
    @property
    def version(self):
        """The version of the NDEF mapping as a "<major>.<minor>" number string."""
        raise NotImplemented

    @property
    def capacity(self):
        """The maximum number of user bytes on the NDEF tag."""
        raise NotImplemented

    @property
    def writeable(self):
        """True if NDEF data can be written to the tag."""
        raise NotImplemented

    @property
    def message(self):
        """A character string containing the NDEF message data."""
        raise NotImplemented

    @message.setter
    def message(self, data):
        raise NotImplemented


class TAG(object):
    @property
    def ndef(self):
        """Holds an :class:`~nfc.NDEF` object if the tag is appropriately formatted, else :const:`None`."""
        return self._ndef if hasattr(self, "_ndef") else None

    @property
    def is_present(self):
        """True if the tag is in communication range."""
        return self._is_present


