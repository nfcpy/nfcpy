# -*- coding: latin-1 -*-
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

import time

class DEP(object):
    def __init__(self, dev, general_bytes, role):
        self._dev = dev
        self._gb = general_bytes
        self._role = role

    @property
    def general_bytes(self):
        """The general bytes received with the ATR exchange"""
        return self._gb

    @property
    def role(self):
        """Role in DEP communication, either 'Target' or 'Initiator'"""
        return self._role

class DEPInitiator(DEP):
    def __init__(self, dev, general_bytes):
        DEP.__init__(self, dev, general_bytes, "Initiator")

    def exchange(self, data, timeout, mtu=None):
        """Send *data* bytes to the remote NFCIP-1 target device. If a 
        response is received within *timeout* milliseconds, exchange()
        returns a byte string with the response data, otherwise IOError
        exception is raised.
        """
        log.debug("dep send {0} byte\n{1}".format(len(data), format_data(data)))
        t0 = time.time()
        data = self._dev.dep_exchange(data, timeout)
        duration = int((time.time() - t0) * 1000)
        log.debug("exchange() completed in {0} ms".format(duration))
        log.debug("dep recv {0} byte\n{1}".format(len(data), format_data(data)))
        return data

class DEPTarget(DEP):
    def __init__(self, dev, general_bytes):
        DEP.__init__(self, dev, general_bytes, "Target")

    @property
    def response_waiting_time(self):
        return self._dev.rwt

    def wait_command(self, timeout):
        """Receive an NFCIP-1 DEP command. If a command is received within
        *timeout* milliseconds the data portion is returned as a byte 
        string, otherwise an IOError exception is raised."""
        t0 = time.time()
        data = self._dev.dep_get_data(timeout)
        duration = int((time.time() - t0) * 1000)
        log.debug("wait_command() completed in {0} ms".format(duration))
        log.debug("dep recv {0} byte\n{1}".format(len(data), format_data(data)))
        return data

    def send_response(self, data, timeout):
        """Send an NFCIP-1 DEP response with the byte string *data*
        as the payload.
        """
        log.debug("dep send {0} byte\n{1}".format(len(data), format_data(data)))
        t0 = time.time()
        self._dev.dep_set_data(data, timeout)
        duration = int((time.time() - t0) * 1000)
        log.debug("send_response() completed in {0} ms".format(duration))

def format_data(data):
    import string
    printable = string.digits + string.letters + string.punctuation + ' '
    s = []
    for i in range(0, len(data), 16):
        s.append("  {offset:04x}: ".format(offset=i))
        s[-1] += ' '.join(["%02x" % ord(c) for c in data[i:i+16]]) + ' '
        s[-1] += (8 + 16*3 - len(s[-1])) * ' '
        s[-1] += ''.join([c if c in printable else '.' for c in data[i:i+16]])
    return '\n'.join(s)

