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
        exception is raised."""
        
        log.debug("send {0} byte dep cmd".format(len(data)))
        log.debug("dep raw >> " + str(data).encode("hex"))
        t0 = time.time()
        data = self._dev.dep_exchange(data, timeout)
        elapsed = int((time.time() - t0) * 1000)
        log.debug("rcvd {0} byte dep rsp in {1} ms".format(len(data), elapsed))
        log.debug("dep raw << " + str(data).encode("hex"))
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
        
        log.debug("wait up to {0} ms for a dep command".format(timeout))
        t0 = time.time()
        data = self._dev.dep_get_data(timeout)
        elapsed = int((time.time() - t0) * 1000)
        log.debug("dep raw << " + str(data).encode("hex"))
        log.debug("rcvd {0} byte cmd after {1} ms".format(len(data), elapsed))
        return data

    def send_response(self, data, timeout):
        """Send an NFCIP-1 DEP response with the byte string *data* as
        the payload."""
        
        log.debug("send {0} byte dep rsp in {1} ms".format(len(data), timeout))
        log.debug("dep raw >> " + str(data).encode("hex"))
        t0 = time.time()
        self._dev.dep_set_data(data, timeout)
        elapsed = int((time.time() - t0) * 1000)
        log.debug("sent {0} byte dep rsp in {1} ms".format(len(data), elapsed))

