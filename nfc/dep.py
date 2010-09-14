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

class DEP(object):
    def __init__(self, dev, general_bytes, role):
        self.__dev = dev
        self.__gb = general_bytes
        self.__role = role

    @property
    def general_bytes(self):
        """The general bytes received with the ATR exchange"""
        return self.__gb

    @property
    def role(self):
        """Role in DEP communication, either 'Target' or 'Initiator'"""
        return self.__role

    @property
    def dev(self):
        return self.__dev

class DEPInitiator(DEP):
    def __init__(self, dev, general_bytes):
        DEP.__init__(self, dev, general_bytes, "Initiator")

    def exchange(self, data, timeout=100, mtu=None):
        """Send *data* bytes to the remote NFCIP-1 target device. If a 
        response is received within *timeout* milliseconds, exchange()
        returns a byte string with the response data, otherwise IOError
        exception is raised. The *mtu* parameter may be used to set a 
        specific value for the maximum number of bytes sent within a
        single DEP command, i.e. before NFCIP-1 chaining will be 
        applied."""
        return self.dev.dep_exchange(data, timeout, mtu)

class DEPTarget(DEP):
    def __init__(self, dev, general_bytes):
        DEP.__init__(self, dev, general_bytes, "Target")

    def wait_command(self, timeout=100):
        """Receive an NFCIP-1 DEP command. If a command is received within
        *timeout* milliseconds the data portion is returned as a byte 
        string, otherwise an IOError exception is raised."""
        return self.dev.dep_get_data(timeout)

    def send_response(self, data, mtu=None):
        """Send an NFCIP-1 DEP response with the byte string *data*
        as the payload. The *mtu* parameter may be used to set a 
        specifc value for the maximum number of bytes sent within a
        single DEP command, i.e. before NFCIP-1 chaining will be 
        applied."""
        self.dev.dep_set_data(data, mtu)


