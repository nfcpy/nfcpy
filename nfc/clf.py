# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2013 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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
import nfc.tag
import nfc.llcp

from time import sleep
from collections import namedtuple

TTA = namedtuple("TTA", "br, cfg, uid")
TTB = namedtuple("TTB", "br")
TTF = namedtuple("TTF", "br, idm, pmm, sys")

def __target__str__(self):
    s = "{0} br={1}".format(self.__class__.__name__, self[0])
    for p in zip(self._fields[1:], self[1:]):
        s += " {0}={1}".format(p[0], str(p[1]).encode("hex"))
    return s

TTA.__str__ = __target__str__
TTB.__str__ = __target__str__
TTF.__str__ = __target__str__

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

    def connect(self, **options):
        log.debug("connect({0})".format(options))
        
        tag_options = options.get('tag')
        p2p_options = options.get('p2p')
        assert tag_options or p2p_options
        
        if tag_options and not tag_options.get('targets'):
            tag_options['targets'] = [
                TTA(br=106, cfg=None, uid=None), TTB(br=106),
                TTF(br=424, idm=None, pmm=None, sys=None),
                TTF(br=212, idm=None, pmm=None, sys=None)]
        if p2p_options and type(p2p_options) != dict:
            p2p_options = dict()

        try:
            while True:
                if ((tag_options and self._connect_tag(tag_options)) or
                    (p2p_options and self._connect_p2p(p2p_options))):
                    return True
        except KeyboardInterrupt:
            return False

    def _connect_tag(self, options):
        target = self.sense(options.get('targets', []))
        if target is not None:
            log.debug("found target {0}".format(target))
            tag = nfc.tag.activate(self, target)
            if tag is not None:
                log.debug("connected {0}".format(tag))
                on_connected_callback = options.get('on-connected')
                if on_connected_callback is not None:
                    if on_connected_callback(tag) == True:
                        while tag.is_present:
                            sleep(0.1)
                return True
        
    def _connect_p2p(self, options):
        nfc.llcp.init(recv_miu=options.get('miu', 128),
                      send_lto=options.get('lto', 100),
                      send_agf=options.get('agf', True))
        try: options['register-services']()
        except KeyError: pass
        for role in ('target', 'initiator'):
            if role == options.get('role') or options.get('role') is None:
                DEP = eval("nfc.dep." + role.capitalize())
                if nfc.llcp.activate(mac=DEP(clf=self)):
                    try: p2p['activate-services']()
                    except KeyError: pass
                    return True
        
    def sense(self, targets):
        """Discover a contactless target device. Potential targets to
        recognize are given in the *targets* list. 
        """
        return self.dev.sense(targets)

    def listen(self, targets, timeout):
        return self.dev.listen(targets, timeout)

    def exchange(self, send_data, timeout):
        recv_data = self.dev.exchange(send_data, timeout)
        return recv_data

    def set_communication_mode(self, brm, **kwargs):
        self.dev.set_communication_mode(brm, **kwargs)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        if self.dev is not None:
            s = "{dev.vendor} {dev.product} on {dev.path}"
            return s.format(dev=self.dev)
        else: return self.__repr__()

class DigitalProtocolError(Exception):
    info = {
        "4.4.1.3"   : "NFCA frame checksum error",
        "4.6.3.3"   : "SENS_RES has invalid encoding",
    
        "6.4.1.8"   : "NFCF frame checksum",

        "8.6.2.1"   : "T1TP invalid header rom byte 0",
    
        "9.6.2"     : "T2TP undefined read response",
        "9.6.2.3"   : "T2TP read command returned nack",
        "9.7.2"     : "T2TP undefined write response error",
        "9.7.2.1"   : "T2TP write command returned nack",
        "9.8.3.1"   : "T2TP sector select 1 returned nack",
        "9.8.3.3"   : "T2TP sector select 2 returned data",
        "9.9.1.3"   : "T2TP frame delay time expired",
    
        "10.6"      : "T3TP maximum response time",
        "10.6.1.1"  : "T3TP check command timeout",
        "10.6.1.3"  : "T3TP update command timeout",

        "14.4.1.1"  : "[NFC-DEP] first byte must be SB=F0h for NFC-A",
        "14.4.1.2"  : "[NFC-DEP] length byte must equal data length + 1",
        "14.4.1.3"  : "[NFC-DEP] length byte must be 3 <= LEN <= 255",

        "14.6.1.1"  : "[NFC-DEP] ATR_REQ would be more than 64 byte",
        "14.6.1.2"  : "[NFC-DEP] ATR_REQ received with more than 64 byte",
        "14.6.1.3"  : "[NFC-DEP] ATR_RES received with more than 64 byte",
        "14.6.1.4"  : "[NFC-DEP] ATR_RES would be more than 64 byte",
        "14.6.2.1"  : "[NFC-DEP] Initiator must copy nfcid2t to nfcid3i",
        "14.6.2.2"  : "[NFC-DEP] NFCID3i differs from NFCID2t",
        "14.7.2.2"  : "[NFC-DEP] Target must return same DID as in PSL_REQ",
        "14.8.4.2"  : "[NFC-DEP] RTOX must be in range 1 <= x <= 59",
        "14.12.2.1" : "[NFC-DEP] more information must be acknowledged",
        "14.12.3.3" : "[NFC-DEP] wrong packet number",
        "14.12.4.2" : "[NFC-DEP] invalid response to supervisory a request",
        "14.12.4.3" : "[NFC-DEP] unexpected or out-of-sequence ACK PDU",
        "14.12.4.4" : "[NFC-DEP] received RTOX response to NACK or ATN",
        "14.12.4.5" : "[NFC-DEP] received NACK PDU from Target",
        "14.12.4.6" : "[NFC-DEP] expected INF PDU after sending",
        "14.12.4.7" : "[NFC-DEP] chaing must be continued after ACK",
        "14.12.5.4" : "[NFC-DEP] unrecoverable transmission error",
        "14.12.5.6" : "[NFC-DEP] unrecoverable timeout error",
        
        "Table-86"  : "[NFC-DEP] invalid target response",
        "Table-98"  : "[NFC-DEP]: invalid format of PSL_REQ",
        "Table-102" : "[NFC-DEP]: invalid format of PSL_RES",
    }

    def __init__(self, requirement=None):
        self.requirement = requirement
        
    def __str__(self):
        return self.info.get(self.requirement, self.requirement)

    def __repr__(self):
        return "{0}({1!r})".format(self.__class__.__name__, self.requirement)
    
class ProtocolError(DigitalProtocolError): pass
class TransmissionError(DigitalProtocolError): pass
class TimeoutError(DigitalProtocolError): pass

