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

import time
import threading

class TTA(object):
    """Represents a Type A target. The integer *br* is the
    bitrate. The bytearray *cf* is the two byte SENS_RES data plus the
    one byte SEL_RES data for a tag type 1/4 tag. The bytearray *uid*
    is the target UID. The bytearray *ats* is the answer to select
    data of a type 4 tag if the chipset does activation as part of
    discovery."""
    def __init__(self, br=None, cfg=None, uid=None, ats=None):
        self.br = br
        self.cfg = cfg
        self.uid = uid
        self.ats = ats

    def __str__(self):
        hx = lambda x: str(x) if x is None else str(x).encode("hex")
        return "TTA br={0} cfg={1} uid={2} ats={3}".format(
            self.br, hx(self.cfg), hx(self.uid), hx(self.ats))

class TTB(object):
    """Represents a Type B target. The integer *br* is the
    bitrate. Type B targets are not yet supported in nfcpy, for the
    simple reason that no cards for testing are available."""
    def __init__(self, br=None):
        self.br = br

    def __str__(self):
        return "TTA br={0}".format(self.br)

class TTF(object):
    """Represents a Type F target. The integer *br* is the
    bitrate. The bytearray *idm* is the 8 byte manufacture id. The
    bytearray *pmm* is the 8 byte manufacture parameter. The bytearray
    *sys* is the 2 byte system code."""
    def __init__(self, br=None, idm=None, pmm=None, sys=None):
        self.br = br
        self.idm = idm
        self.pmm = pmm
        self.sys = sys

    def __str__(self):
        hx = lambda x: str(x) if x is None else str(x).encode("hex")
        return "TTF br={0} idm={1} pmm={2} sys={3}".format(
            self.br, hx(self.idm), hx(self.pmm), hx(self.sys))

class DEP(object):
    """Represents a DEP target. The integer *br* is the bitrate. The
    bytearray *gb* is the ATR general bytes."""
    def __init__(self, br=None, gb=None):
        self.br = br
        self.gb = gb

    def __str__(self):
        hx = lambda x: str(x) if x is None else str(x).encode("hex")
        return "DEP br={0} gb={1}".format(self.br, hx(self.gb))

class ContactlessFrontend(object):
    """The contactless frontend is the main interface class for
    working with contactless reader devices. A reader device is opened
    automatically upon instance creation, see :meth:`.open` for how
    *path* is interpeted."""
    
    def __init__(self, path=None):
        self.lock = threading.Lock()
        self.open(path)
        
    def open(self, path=None):
        """Open contactless reader device identified by *path*. If
        *path* is not :const:`None` (default) or an empty string, the
        first available device is used. Otherwise *path* must match
        one of the following expressions:

        * ``usb[:vendor[:product]]`` with *vendor* and *product* id (hex)
        * ``usb[:bus[:device]]`` with usb *bus* and *device* number (dec)
        * ``tty[:usb[:port]]`` with usb serial *port* number (dec)
        * ``tty[:com[:port]]`` with serial *port* number (dec)
        * ``udp[:host[:port]]`` with *host* IP or name and *port* number

        :raises `LookupError`: if no available reader device is found.
        """
        if not path: log.info("searching for a usable reader")
        else: log.info("searching for reader with path '{0}'".format(path))

        with self.lock:
            self.dev = dev.connect(path)
            if self.dev is None:
                msg = "no reader found"
                msg = " ".join([msg, "at {0}".format(path) if path else ""])
                log.error(msg)
                raise LookupError("couldn't find any usable nfc reader")

            log.info("using {0}".format(self.dev))

    def close(self):
        """Close the contacless reader device."""
        with self.lock:
            self.dev.close()
            self.dev = None

    def connect(self, **options):
        """Connect with a contactless target or become connected as a
        contactless target. Connect blocks the calling thread until an
        activation and deactivation has completed. Connect options are
        given as keyword arguments with dictionary values and at least
        one option must be present. Possible options are:
        
        * ``rdwr={key: value, ...}`` - options for reader/writer operation
        * ``llcp={key: value, ...}`` - options for peer to peer mode operation
        * ``card={key: value, ...}`` - options for card emulation operation

        **Reader/Writer Options**

        'targets': sequence
          A list of target specifications with each target of either
          type :class:`~nfc.clf.TTA`, :class:`~nfc.clf.TTB`, or
          :class:`~nfc.clf.TTF`. A default set is choosen if 'targets'
          is not provided.
          
        'on-startup': function
          A function that will be called with the list of targets
          (from 'targets') to search for. Must return a list of
          targets or :const:`None`. Only the targets returned are
          finally considered.
          
        'on-connect': function
          A function object that will be called with an activated
          :class:`~nfc.tag.Tag` object.
        
        >>> import nfc
        >>> def connected(tag):
        ...     print tag
        ...     return True
        ...
        >>> clf = nfc.ContactlessFrontend()
        >>> clf.connect(rdwr={'on-connect': connected})
        Type3Tag IDm=01010501b00ac30b PMm=03014b024f4993ff SYS=12fc
        True
        
        **Peer To Peer Options**

        'on-startup': function
          A function that is called before an attempt is made to
          establish peer to peer communication. The function receives
          the initialized :class:`~nfc.llcp.llc.LogicalLinkController`
          instance as parameter, which may then be used to allocate
          and bind communication sockets for service applications. The
          return value must be either the
          :class:`~nfc.llcp.llc.LogicalLinkController` instance or
          :const:`None` to effectively remove llcp from the options
          considered.
          
        'on-connect': function
          A function that is be called when peer to peer communication
          was established. The function receives the connected
          :class:`~nfc.llcp.llc.LogicalLinkController` instance as
          parameter, which may then be used to allocate communication
          sockets with
          :meth:`~nfc.llcp.llc.LogicalLinkController.socket` and spawn
          working threads to perform communication. The callback must
          return more or less immediately with :const:`True` unless
          the logical link controller run loop is handled within the
          callback.
          
        'role': string
          Defines which role the local LLC shall take for the data
          exchange protocol activation. Possible values are
          'initiator' and 'target'.  The default is to alternate
          between both roles until communication is established.
          
        'miu': integer
          Defines the maximum information unit size that will be
          supported and announced to the remote LLC. The default value
          is 128.
          
        'lto': integer
          Defines the link timeout value (in milliseconds) that will
          be announced to the remote LLC. The default value is 100
          milliseconds.
          
        'agf': boolean
          Defines if the local LLC performs PDU aggregation and may
          thus send Aggregated Frame (AGF) PDUs to the remote LLC. The
          dafault is to use aggregation.
        
        >>> import nfc
        >>> import threading
        >>> def worker(socket):
        ...     socket.sendto("Hi there!", address=16)
        ...     socket.close()
        ...
        >>> def connected(llc):
        ...     socket = llc.socket(nfc.llcp.LOGICAL_DATA_LINK)
        ...     threading.Thread(target=worker, args=(socket,)).start()
        ...     return True
        ...
        >>> clf = nfc.ContactlessFrontend()
        >>> clf.connect(llcp={'on-connect': connected})
        
        **Card Emulation Options**

        'targets': sequence
          A list of target specifications with each target of either
          type :class:`~nfc.clf.TTA`, :class:`~nfc.clf.TTB`, or
          :class:`~nfc.clf.TTF`. The list of targets is processed
          sequentially. Defaults to an empty list.
          
        'on-startup': function
          A function that will be called with the list of targets
          (from 'targets') to emulate. Must return a list of one
          target choosen or :const:`None`.
          
        'on-connect': function
          A function that will be called with an activated
          :class:`~nfc.tag.TagEmulation` instance as first parameter and
          the first command received as the second parameter.

        'timeout': integer
          The timeout in seconds to wait for for each target to become
          initialized. The default value is 1 second.

        >>> import nfc
        >>>
        >>> def connected(tag, command):
        ...     print tag
        ...     print str(command).enccode("hex")
        ...
        >>> clf = nfc.ContactlessFrontend()
        >>> idm = bytearray.fromhex("01010501b00ac30b")
        >>> pmm = bytearray.fromhex("03014b024f4993ff")
        >>> sys = bytearray.fromhex("12fc")
        >>> target = nfc.clf.TTF(212, idm, pmm, sys)
        >>> clf.connect(card={'targets': [target], 'on-connect': connected})
        Type3TagEmulation IDm=01010501b00ac30b PMm=03014b024f4993ff SYS=12fc
        100601010501b00ac30b010b00018000
        True
        
        """
        log.debug("connect({0})".format(options))
        
        rdwr_options = options.get('rdwr')
        llcp_options = options.get('llcp')
        card_options = options.get('card')
        
        if isinstance(rdwr_options, dict):
            rdwr_options.setdefault('targets', [
                    TTA(br=106, cfg=None, uid=None), TTB(br=106),
                    TTF(br=424, idm=None, pmm=None, sys=None),
                    TTF(br=212, idm=None, pmm=None, sys=None)])
            if 'on-startup' in rdwr_options:
                targets = rdwr_options.get('targets')
                targets = rdwr_options['on-startup'](self, targets)
                if targets is None: rdwr_options = None
                else: rdwr_options['targets'] = targets
            if rdwr_options is not None:
                if not 'on-connect' in rdwr_options:
                    rdwr_options['on-connect'] = lambda tag: True
        elif rdwr_options is not None:
            raise TypeError("rdrw_options must be a dictionary")
        
        if isinstance(llcp_options, dict):
            llc = nfc.llcp.llc.LogicalLinkController(
                recv_miu=llcp_options.get('miu', 128),
                send_lto=llcp_options.get('lto', 100),
                send_agf=llcp_options.get('agf', True))
            if 'on-startup' in llcp_options:
                llc = llcp_options['on-startup'](self, llc)
                if llc is None: llcp_options = None
            if llcp_options is not None:
                if not 'on-connect' in llcp_options:
                    llcp_options['on-connect'] = lambda llc: True
        elif llcp_options is not None:
            raise TypeError("llcp_options must be a dictionary")

        if isinstance(card_options, dict):
            if 'on-startup' in card_options:
                targets = card_options.get('targets', [])
                targets = card_options['on-startup'](self, targets)
                if targets is None: card_options = None
                else: card_options['targets'] = targets
            if card_options is not None:
                if not card_options.get('targets'):
                    log.error("a target must be specified to connect as tag")
                    return False
                if not 'on-connect' in card_options:
                    card_options['on-connect'] = lambda tag, command: True
        elif card_options is not None:
            raise TypeError("card_options must be a dictionary")

        some_options = rdwr_options or llcp_options or card_options
        if not some_options:
            log.warning("no options left to connect")
        try:
            while some_options:
                if ((llcp_options and self._llcp_connect(llcp_options, llc)) or
                    (rdwr_options and self._rdwr_connect(rdwr_options)) or
                    (card_options and self._card_connect(card_options))):
                    return True
        except KeyboardInterrupt:
            return False

    def _rdwr_connect(self, options):
        target = self.sense(options.get('targets', []))
        if target is not None:
            log.debug("found target {0}".format(target))
            tag = nfc.tag.activate(self, target)
            if tag is not None:
                log.debug("connected to {0}".format(tag))
                if options['on-connect'](tag=tag):
                    while tag.is_present: time.sleep(0.1)
                return True
        
    def _llcp_connect(self, options, llc):
        for role in ('target', 'initiator'):
            if options.get('role') is None or options.get('role') == role:
                DEP = eval("nfc.dep." + role.capitalize())
                if llc.activate(mac=DEP(clf=self)):
                    log.debug("connected {0}".format(llc))
                    if options['on-connect'](llc=llc): llc.run()
                    return True
        
    def _card_connect(self, options):
        timeout = options.get('timeout', 1.0)
        for target in options.get('targets'):
            activated = self.listen(target, timeout)
            if activated:
                target, command = activated
                log.debug("activated as target {0}".format(target))
                tag = nfc.tag.emulate(self, target)
                if tag is not None:
                    log.debug("connected as {0}".format(tag))
                    options['on-connect'](tag=tag, command=command)
                return True
        
    @property
    def capabilities(self):
        return self.dev.capabilities

    def sense(self, targets, **kwargs):
        """Send discovery and activation requests to find a
        target. Targets is a list of target specifications (TTA, TTB,
        TTF). Not all readers may support all possible target
        types. The return value is an activated target with a possibly
        updated specification (bitrate) or None.

        Additional keyword arguments are driver specific.

        .. note:: This is a direct interface to the
           driver and not needed if :meth:`connect` is used.
        """
        with self.lock:
            return self.dev.sense(targets, **kwargs)

    def listen(self, target, timeout):
        """Listen for *timeout* seconds to become initialized as a
        *target*. The *target* must be set to one of
        :class:`nfc.clf.TTA`, :class:`nfc.clf.TTB`,
        :class:`nfc.clf.TTF`, or :class:`nfc.clf.DEP` (note that
        target type support depends on the hardware capabilities). The
        return value is :const:`None` if *timeout* elapsed without
        activation or a tuple (target, command) where target is the
        activated target (which may differ from the requested target,
        see below) and command is the first command received from the
        initiator.

        If an activated target is returned, the target type and
        attributes may differ from the *target* requested. This is
        especically true if activation as a :class:`nfc.clf.DEP`
        target is requested but the contactless frontend does not have
        a hardware implementation of the data exchange protocol and
        returns a :class:`nfc.clf.TTA` or :class:`nfc.clf.TTF` target
        instead.

        .. note:: This is a direct interface to the
           driver and not needed if :meth:`connect` is used.
        """
        with self.lock:
            log.debug("listen for {0:.3f} sec as target {1}"
                      .format(timeout, target))
        
            if type(target) is TTA:
                return self.dev.listen_tta(target, timeout)
            if type(target) is TTB:
                return self.dev.listen_ttb(target, timeout)
            if type(target) is TTF:
                return self.dev.listen_ttf(target, timeout)
            if type(target) is DEP:
                return self.dev.listen_dep(target, timeout)

    def exchange(self, send_data, timeout):
        """Exchange data with an activated target (data is a command
        frame) or as an activated target (data is a response
        frame). Returns a target response frame (if data is send to an
        activated target) or a next command frame (if data is send
        from an activated target). Returns None if the communication
        link broke during exchange (if data is sent as a target). The
        timeout is the number of seconds to wait for data to return,
        if the timeout expires an nfc.clf.TimeoutException is
        raised. Other nfc.clf.DigitalProtocolExceptions may be raised
        if an error is detected during communication.

        .. note:: This is a direct interface to the
           driver and not needed if :meth:`connect` is used.
        """
        with self.lock:
            return self.dev.exchange(send_data, timeout)

    def set_communication_mode(self, brm, **kwargs):
        """Set the hardware communication mode. The effect of calling
        this method depends on the hardware support, some drivers may
        purposely ignore this function. If supported, the parameter
        *brm* specifies the communication mode to choose as a string
        composed of the bitrate and modulation type, for example
        '212F' shall switch to 212 kbps Type F communication. Other
        communication parameters may be changed with optional keyword
        arguments. Currently implemented by the RC-S380 driver are the
        parameters 'add-crc' and 'check-crc' when running as
        initator. It is possible to set *brm* to an empty string if
        bitrate and modulation shall not be changed but only optional
        parameters executed.

        .. note:: This is a direct interface to the
           driver and not needed if :meth:`connect` is used.
        """
        with self.lock:
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
        
        "Table-86"  : "[NFC-DEP] invalid command/response code",
        "Table-98"  : "[NFC-DEP] invalid format of PSL_REQ",
        "Table-102" : "[NFC-DEP] invalid format of PSL_RES",
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

