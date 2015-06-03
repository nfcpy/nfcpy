# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009-2015 Stephen Tiedemann <stephen.tiedemann@gmail.com>
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

import os
import time
import errno
import threading

import nfc.tag
import nfc.dep
import nfc.llcp
from . import device

class ContactlessFrontend(object):
    """This class is the main interface for working with contactless
    devices. Through its :meth:`connect` method it provides unified
    access to the different contactless interface drivers and allows
    to discover remote devices and obtain appropriate upper level
    protocol instances to further exchange content. The lower level
    :meth:`sense`, :meth:`listen` and :meth:`exchange` methods allow
    implementation of non-standard data exchanges.

    An instance of the :class:`ContactlessFrontend` class manages a
    single contactless device locally connect through either USB, TTY
    or COM port. A special UDP port driver allows for emulation of a
    contactless device that connects through UDP to another emulated
    contactless device for test and development of higher layer
    functions.

    A locally connected contactless device can be opened by either
    supplying a *path* argument when an an instance of the contactless
    frontend class is created or by calling :meth:`open` at a later
    time. In either case the *path* argument must be constructed as
    described in :meth:`open` and the same exceptions may occur. The
    difference is that :meth:`open` returns False if a device could
    not be found whereas the initialization method raises
    :exc:`~exceptions.IOError` with :data:`errno.ENODEV`.

    The methods of the :class:`ContactlessFrontend` class are
    thread-safe.

    """
    def __init__(self, path=None):
        self.device = None
        self.lock = threading.Lock()
        self.sensed_target = None
        if path and not self.open(path):
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        
    def open(self, path):
        """Open a contactless reader identified by the search *path*.

        The :meth:`open` method searches and then opens a contactless
        reader device for further communication. The *path* argument
        can be flexibly constructed to identify more or less precisely
        the device to open. A *path* that only partially identifies a
        device is completed by search. The first device that is found
        and successfully opened causes :meth:`open` to return True. If
        no device is found return value is False. If a device was
        found but could not be opened then :meth:`open` returns False
        if *path* was partial or raise :exc:`~exceptions.IOError` if
        *path* was fully qualified. Typical I/O error reasons are
        :data:`errno.EACCES` if the calling process has insufficient
        access rights or :data:`errno.EBUSY` if the device is used by
        another process.
        
        A path is constructed as follows:
        
        ``usb[:vendor[:product]]``
        
           with optional *vendor* and *product* as four digit
           hexadecimal numbers. For example, ``usb:054c:06c3`` would
           open the first Sony RC-S380 reader while ``usb:054c`` would
           open the first Sony reader found on USB.
        
        ``usb[:bus[:device]]``
        
           with optional *bus* and *device* number as three-digit
           decimals. For example, ``usb:001:023`` would open the
           device enumerated as number 23 on bus 1 while ``usb:001``
           would open the first device found on bust 1. Note that a
           new device number is generated every time the device is
           plugged into USB. Bus and device numbers are shown by
           ``lsusb``.
        
        ``tty:port:driver``
        
           with mandatory *port* and *driver* name. This is for Posix
           systems to open the serial port ``/dev/tty<port>`` and use
           the driver module ``nfc/dev/<driver>.py`` for access. For
           example, ``tty:USB0:arygon`` would open ``/dev/ttyUSB0``
           and load the Arygon APPx/ADRx driver.
        
        ``com:port:driver``
        
           with mandatory *port* and *driver* name. This is for
           Windows systems to open the serial port ``COM<port>`` and
           use the driver module ``nfc/dev/<driver>.py`` for access.
        
        ``udp[:host][:port]``
        
           with optional *host* name or address and *port*
           number. This will emulate a communication channel over
           UDP/IP. The defaults for *host* and *port* are
           ``localhost:54321``.

        """
        if not isinstance(path, str):
            raise TypeError("expecting a string type argument *path*")
        if not len(path) > 0:
            raise ValueError("argument *path* must not be empty")

        # Close current device driver if this is not the first
        # open. This allows to use several devices sequentially or
        # re-initialize a device.
        self.close()

        # Acquire the lock and search for a device on *path*
        with self.lock:
            log.info("searching for reader on path " + path)
            self.device = device.connect(path)

        if self.device is None:
            log.error("no reader available on path " + path)
        else:
            log.info("using {0}".format(self.device))

        return bool(self.device)

    def close(self):
        """Close the contacless reader device."""
        with self.lock:
            if self.device is not None:
                try: self.device.close()
                except IOError: pass
                self.device = None

    def connect(self, **options):
        """Connect with a Target or Initiator

        The calling thread is blocked until a single activation and
        deactivation has completed or a callback function supplied as
        the keyword argument ``terminate`` returns :const:`True`. The
        result of the terminate function also applies to the loop run
        after activation, so the example below will let
        :meth:`~connect()` return after 10 seconds from either waiting
        for a peer device or when connected. ::

        >>> import nfc, time
        >>> clf = nfc.ContactlessFrontend('usb')
        >>> after5s = lambda: time.time() - started > 5
        >>> started = time.time(); clf.connect(llcp={}, terminate=after5s)

        Connect options are given as keyword arguments with dictionary
        values. Possible options are:
        
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
          default is to use aggregation.

        'brs': integer

          When in the Initiator role, the bit rate selector specifies
          the bitrate to negotiate with the remote target as a
          zero-based index of the tuple (106, 212, 424) kbps. The
          default value is 2 (424 kbps). This parameter has no effect
          for the local device in DEP Target role.

        'acm': boolean

          When in the Initiator role, a DEP Target may be initialized
          in active communication mode if this parameter is set to
          True. The default value is False. This parameter has no
          effect for the local device in DEP Target role.
        
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

        'on-release': function

          A function that will be called when the activated tag has
          been released by it's Initiator, basically that is when the
          tag has been removed from the Initiator's RF field.

        'timeout': integer
        
          The timeout in seconds to wait for for each target to become
          initialized. The default value is 1 second.

        >>> import nfc
        >>> def connected(tag, command):
        ...     print tag
        ...     print str(command).encode("hex")
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
        
        Connect returns :const:`None` if no options were to execute,
        :const:`False` if interrupted by a :exc:`KeyboardInterrupt`,
        or :const:`True` if terminated normally and the 'on-connect'
        callback function had returned :const:`True`. If the
        'on-connect' callback had returned :const:`False` the return
        value of connect() is the same parameters as were provided to
        the callback function.

        Connect raises :exc:`IOError(errno.ENODEV)` if called before a
        contactless reader was opened.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        
        log.debug("connect({0})".format(options))

        terminate = options.get('terminate', lambda: False)
        rdwr_options = options.get('rdwr')
        llcp_options = options.get('llcp')
        card_options = options.get('card')

        if isinstance(rdwr_options, dict):
            rdwr_options.setdefault('targets', [TTA(106), TTB(106), TTF(212)])
            if 'on-startup' in rdwr_options:
                targets = rdwr_options.get('targets')
                targets = rdwr_options['on-startup'](self, targets)
                if targets is None: rdwr_options = None
                else: rdwr_options['targets'] = targets
            if rdwr_options is not None:
                if not 'on-connect' in rdwr_options:
                    rdwr_options['on-connect'] = lambda tag: True
        elif rdwr_options is not None:
            raise TypeError("argument *rdwr* must be a dictionary")
        
        if isinstance(llcp_options, dict):
            llc = nfc.llcp.llc.LogicalLinkController(
                recv_miu=llcp_options.get('miu', 128),
                send_lto=llcp_options.get('lto', 100),
                send_agf=llcp_options.get('agf', True),
                symm_log=llcp_options.get('symm-log', True))
            if 'on-startup' in llcp_options:
                llc = llcp_options['on-startup'](self, llc)
                if llc is None: llcp_options = None
            if llcp_options is not None:
                if not 'on-connect' in llcp_options:
                    llcp_options['on-connect'] = lambda llc: True
        elif llcp_options is not None:
            raise TypeError("argument *llcp* must be a dictionary")

        if isinstance(card_options, dict):
            if 'on-startup' in card_options:
                targets = card_options.get('targets', [])
                targets = card_options['on-startup'](self, targets)
                if targets is None: card_options = None
                else: card_options['targets'] = targets
            if card_options is not None:
                if not card_options.get('targets'):
                    log.error("a target must be specified to connect as tag")
                    return None
                if not 'on-connect' in card_options:
                    card_options['on-connect'] = lambda tag, command: True
        elif card_options is not None:
            raise TypeError("argument *card* must be a dictionary")

        some_options = rdwr_options or llcp_options or card_options
        if not some_options:
            log.warning("no options left to connect")
            return None
        
        try:
            while not terminate():
                if llcp_options:
                    result = self._llcp_connect(llcp_options, llc, terminate)
                    if bool(result) is True: return result
                if rdwr_options:
                    result = self._rdwr_connect(rdwr_options, terminate)
                    if bool(result) is True: return result
                if card_options:
                    result = self._card_connect(card_options, terminate)
                    if bool(result) is True: return result
        except KeyboardInterrupt as error:
            log.debug(error)
            return False
        except IOError as error:
            log.error(error)
            return False

    def _rdwr_connect(self, options, terminate):
        target = self.sense(*options.get('targets', []),
                            iterations=5, interval=0.5)
        if target is not None:
            log.debug("found target {0}".format(target))
            tag = nfc.tag.activate(self, target)
            if tag is not None:
                log.debug("connected to {0}".format(tag))
                callback = options['on-connect']
                if callback and callback(tag):
                    while not terminate() and tag.is_present:
                        time.sleep(0.1)
                    return True
                else:
                    return tag
        
    def _llcp_connect(self, options, llc, terminate):
        for role in ('target', 'initiator'):
            if options.get('role') is None or options.get('role') == role:
                DEP = eval("nfc.dep." + role.capitalize())
                dep_cfg = ('brs', 'acm', 'rwt', 'lrt', 'lri')
                dep_cfg = {k: options[k] for k in dep_cfg if k in options}
                if llc.activate(mac=DEP(clf=self), **dep_cfg):
                    log.debug("connected {0}".format(llc))
                    callback = options['on-connect']
                    if callback and callback(llc):
                        llc.run(terminate=terminate)
                        return True
                    else:
                        return llc
        
    def _card_connect(self, options, terminate):
        timeout = options.get('timeout', 1.0)
        for target in options.get('targets'):
            activated = self.listen(target, timeout)
            if activated:
                target, command = activated
                log.debug("activated as target {0}".format(target))
                tag = nfc.tag.emulate(self, target)
                if tag is not None:
                    log.debug("connected as {0}".format(tag))
                    callback = options['on-connect']
                    if callback and callback(tag, command):
                        while not terminate():
                            response = (tag.process_command(command)
                                        if command is not None else None)
                            try:
                                command = tag.send_response(response, timeout=1)
                            except nfc.clf.TimeoutError:
                                command = None
                            except nfc.clf.DigitalError as error:
                                log.error(error)
                                break
                            else:
                                if command is None: break
                        callback = options.get('on-release', lambda tag: True)
                        return callback(tag=tag)
                    else:
                        return tag
        
    def sense(self, *targets, **options):
        """Discover a contactless card or listening device.
        
        The :meth:`sense` method provides low-level access to the
        contactless frontend driver. It is not intended for use by a
        regular application but rather for special cases where the
        :meth:`connect` method may be limiting, like in testing.
        
        All positional arguments constitute the list of *targets* that
        may be discovered. The possible target types are :class:`TTA`,
        :class:`TTB`, :class:`TTF`, and :class:`DEP`, each must at
        least provide the bitrate at which to search. All keyword
        arguments are interpreted as *options*. Currently recognized
        options are the number of ``iterations`` and the ``interval``
        between iterations of the sense loop specified by *targets*.
        The following example performs a sense loop with a single Type
        A Target for 5 times with 200 milliseconds between the start
        of each loop.
        
        >>> import nfc
        >>> clf = nfc.ContactlessFrontend("usb")
        >>> print(clf.sense(nfc.clf.TTA(106), iterations=5, interval=0.2))
        106A(sdd_res=04497622D93881, sel_res=00, sens_res=4400)
        
        The search for a Type A Target can be restricted with an
        ``sdd_req`` parameter that provides the UID/NFCID of the card
        or listening device. The length of an ``sdd_req`` parameter
        must be 4, 7, or 10 byte.
        
        >>> target = nfc.clf.TTA(106)
        >>> target.sdd_req = bytearray.fromhex("04497622D93881")
        >>> print(clf.sense(target))
        106A(sdd_res=04497622D93881, sel_res=00, sens_res=4400)

        A Type B Target search may request a specific application
        family by providing the ``sens_req`` parameter. Note that only
        the first byte (AFI) is guaranteed to be send as
        requested. The second byte (PARAM) is usually ignored because
        none of the supported hardware can be set accordingly.
        
        >>> target = nfc.clf.TTB(106)
        >>> print(clf.sense(target))
        106B(sens_res=50E5DD3DC900000011008185)
        >>> target.sens_req = bytearray.fromhex("0000")
        >>> print(clf.sense(target))
        106B(sens_res=50E5DD3DC900000011008185)
        
        A Type F Target search is by default done with a polling
        command that requests a response regardless of system code,
        does not ask for any additional response data and allows only
        a single timeslot. To request additional information or poll
        only for a specific system code, the ``sens_req`` parameter
        must be supplied.
        
        >>> ba = lambda s: bytearray.fromhex(s)
        >>> print(clf.sense(nfc.clf.TTF(212)))
        424F(sens_res=0101010701260cca020f0d23042f7783ff)
        >>> print(clf.sense(nfc.clf.TTF(212, sens_req=ba("00FFFF0100"))))
        424F(sens_res=0101010701260cca020f0d23042f7783ff12fc)
        >>> print(clf.sense(nfc.clf.TTF(212, sens_req=ba("0012FC0000"))))
        424F(sens_res=0101010701260cca020f0d23042f7783ff)
        
        A Data Exchange Protocol (DEP) Target search is requested with
        a :class:`DEP` target that can be configured for a bitrate of
        106, 212, or 424 kbps. The choice of passive or active
        communication mode depends on whether a DEP configured TTA or
        TTF target (passive DEP target) was discovered in a preceeding
        call to :meth:`sense`. If no passive DEP target was captured
        then activation is attempted in active communication mode
        with, by default, a random NFCID3 and no General Bytes in the
        ATR_REQ.

        >>> print(clf.sense(nfc.clf.DEP(106)))
        DEP 106A(atr_res=D5016B509488C06EDD2616320000000732)
        
        The ``atr_req`` parameter can be used to change the ATR_REQ
        command. It should be noted that for active communication mode
        most drivers are only able to set the NFCID3 and General
        Bytes.

        >>> ba = lambda s: bytearray.fromhex(s)
        >>> nfcid3 = ba("01 02 03 04 05 06 07 08 09 10")
        >>> gbytes = ba("46666D 010110")
        >>> atr = ba("D400") + nfcid3 + ba("00000032") + gbytes
        >>> print(clf.sense(nfc.clf.DEP(106, atr_req=atr)))
        DEP 106A(atr_res=D5016B509488C06EDD261632000000073246666D010111)

        The ``psl_req`` parameter can be used to switch to a different
        communication speed after the initial discovery.

        >>> print(clf.sense(nfc.clf.DEP(106, psl_req=ba("D404001203"))))
        DEP 424F(atr_res=D5016B509488C06EDD2616320000000732)

        Activation of a DEP Target in passive communication mode
        requires two calls to :meth:`sense`, first to discover a DEP
        configured Type A or Type F Target and then to perform the DEP
        activation. If ``atr_req`` is not set in the DEP target
        argument, the NFCID3 is randomly generated when a Type A
        Target was captured or copied from the ``sens_res`` when a
        Type F Target was captured.

        >>> target = clf.sense(nfc.clf.TTF(212), nfc.clf.TTA(106))
        >>> if target:
        ...     target = clf.sense(nfc.clf.DEP(target.bitrate))
        ...     print(target)

        The ``atr_req`` parameter overwrites the default ATR_REQ
        command. In case of a captured Type F Target the first 8
        NFCID3 bytes are replaced with the NFCID2 from the
        ``sens_res`` response. Note that some drivers modify other
        parts of the ATR_REQ to account for hardware limitations.

        Again, the ``psl_req`` parameter can be used to switch to a
        different communication speed after the ATR exchange, and
        drivers may also modify the ``psl_req`` (for the maximum
        payload size) if restricted by hardware.

        The bitrate for ATR and possibly PSL exchange is determined by
        the captured Type A or Type F Target. It is not required
        to be set in the :class:`DEP` target argument.
        
        >>> ba = lambda s: bytearray.fromhex(s)
        >>> atr = ba("D400 01020304050607080910 00000032 46666D010110")
        >>> psl = ba("D404001203")
        >>> target = clf.sense(nfc.clf.TTF(212), nfc.clf.TTA(106))
        >>> if target:
        ...     target = clf.sense(nfc.clf.DEP(atr_req=atr, psl_req=psl))
        ...     print(target)
        
        All information about a captured target is deleted and the RF
        field deactivated if :meth:`sense` is called with no target
        arguments. One use case would be to build a sense loop that
        discovers Type A, B, or F Targets and active mode DEP Targets.

        >>> from nfc.clf import TTA, TTB, TTF, DEP
        >>> targets = [DEP(106), TTA(106), TTB(106), TTF(212)]
        >>> active_dep_only = True
        >>> target = None
        >>> while target is None:
        ...     if active_dep_only: clf.sense()
        ...     target = clf.sense(*targets)
        
        In the example above, if ``active_dep_only = False`` then a
        DEP Target could also be discovered in passive communication
        mode during the second or a later execution of the while loop.

        Note that the ``iterations`` and ``interval`` options are also
        considered when no *targets* are specified, to roughly the
        same result as a sleep for ``interval * (iterations-1)``
        seconds.

        Errors found in the *targets* argument list raise exceptions
        only if exactly one target is given. If multiple targets are
        provided, any target that is not supported or has invalid
        attributes is just ignored (but is logged as a debug message).
        
        **Exceptions**
        
        * :exc:`~exceptions.IOError` (ENODEV) when a local device has
          not been opened or got lost.
        
        * :exc:`~exceptions.TypeError` if only a single target is
          specified with a bitrate/type combination that is not
          supported.

        * :exc:`~exceptions.ValueError` if only a single target is
          specified and it contains an invalid parameter.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        for target in targets:
            if not isinstance(target, TechnologyType):
                raise ValueError("all targets must be TechnologyType objects")

        SENSE = {TTA: self.device.sense_tta, TTB: self.device.sense_ttb,
                 TTF: self.device.sense_ttf, DEP: self._sense_dep}

        with self.lock:
            self.listen_target = None
            if not (len(targets) and type(targets[0]) is DEP):
                self.device.mute() # deactivate the rf field
                self.sensed_target = None
            for i in xrange(max(1, options.get('iterations', 1))):
                started = time.time()
                for target in targets:
                    log.debug("sense {0}".format(target))
                    try:
                        self.sensed_target = SENSE[type(target)](target)
                    except (TypeError, ValueError):
                        if len(targets) == 1: raise
                    else:
                        if self.sensed_target is not None:
                            log.debug("found {0}".format(self.sensed_target))
                            return self.sensed_target
                if len(targets):
                    self.device.mute() # deactivate the rf field
                if i < options.get('iterations', 1) - 1:
                    elapsed = time.time() - started
                    time.sleep(max(0, options.get('interval', 0.1)-elapsed))

    def _sense_dep(self, target):
        passive_target = None
        if not (target.atr_req and len(target.atr_req) >= 16):
            target.atr_req = "\xD4\x00" + os.urandom(8) + bytearray(5) + "\x30"
        if type(self.sensed_target) in (TTA, TTF):
            passive_target = self.sensed_target
            if type(self.sensed_target) is TTF:
                target.atr_req[2:10] = passive_target.sens_res[1:9]
        target.atr_req[10:12] = bytearray("ST")
        return self.device.sense_dep(target, passive_target)

    def listen(self, target, timeout):
        """Listen *timeout* seconds to activate as a target.

        The :meth:`listen` method provides low-level access to the
        contactless frontend driver. It is not intended for use by a
        regular application but rather for special cases where the
        :meth:`connect` method may be limiting, like in testing.
        
        To emulate a card or listening device the contactless frontend
        is set to listen *timeout* secods in the *target* technology
        type. The *timeout* argument may be a float to specify
        fractions of seconds. The *target* must be an instance of a
        subclass of :class:`TechnologyType` and provide technology
        dependent activation responses. Which technology types may be
        used depends on the local hardware and driver support. Most
        devices support to listen as a :class:`DEP` target and some
        can also be set to listen as a :class:`TTA` or :class:`TTF`
        target.

        To listen as a :class:`TTA` target the ``sens_res``,
        ``sdd_res`` and ``sel_res`` parameters must be set. The
        example below will emulate a Type 2 Tag.

        >>> import nfc
        >>> clf = nfc.ContactlessFrontend("usb")
        >>> tta = nfc.clf.TTA(106, sens_res=bytearray.fromhex("0101"))
        >>> tta.sdd_res = bytearray.fromhex("08010203")
        >>> tta.sel_res = bytearray.fromhex("00") # Type 2 Tag
        >>> target = clf.listen(tta, timeout=1.5)
        >>> if target is not None:
        ...     print target

        To listen as a :class:`TTF` target the FeliCa polling response
        must be given as ``sens_res``.
        
        >>> import nfc
        >>> clf = nfc.ContactlessFrontend("usb")
        >>> (idm, pmm, sys) = ("02FE010203040506", "FFFFFFFFFFFFFFFF", "12FC")
        >>> sens_res = bytearray.fromhex("01" + idm + pmm + sys)
        >>> target = clf.listen(nfc.clf.TTF(212, sens_res=sens_res), 1.5)
        >>> if target is not None:
        ...     print target

        When listening as a :class:`DEP` target the activation
        parameters for passive communication mode must be set as
        ``tta`` and ``ttf`` attributes with their respective
        technology type classes. A :class:`DEP` target will always
        listen for all supported bitrates, regardless of whether the
        bitrate parameter is set. Compared to the tag activations
        above, the :class:`TTA` and :class:`TTF` targets must also
        provide the ``atr_res`` response data. If activated, the
        return value is a :class:`DEP` target with the bitrate set as
        established. For passive activation (where the local device
        sends by modulating the Initiator's RF field) the technology
        type at which the inital activation was received is returned
        as the ``tta`` or ``ttf`` attribute of the :class:`DEP`
        target.
        
        >>> import nfc
        >>> from nfc.clf import TTA, TTF, DEP
        >>> ba = lambda xs: bytearray.fromhex(xs)
        >>> clf = nfc.ContactlessFrontend("usb")
        >>> sensa_res, sdd_res, sel_res = ba("0101"), ba("08010203"), ba("40")
        >>> sensf_res = ba("01 01FE010203040506 0000000000000000 FFFF")
        >>> atr_res = ba("D501 01FE0102030405060708 0000000832 46666d010110")
        >>> tta = TTA(sens_res=sensa_res, sdd_res=sdd_res, sel_res=sel_res)
        >>> ttf = TTF(sens_res=sensf_res)
        >>> tta.atr_res = ttf.atr_res = atr_res
        >>> dep = DEP(tta=tta, ttf=ttf)
        >>> target = clf.listen(dep, timeout=2.5)
        >>> if target is not None:
        ...     print target

        Activation in active communication mode (where always the
        sending device generates the RF field) is enabled if also the
        :class:`DEP` *target* contains the ``atr_res`` response data
        attribute. Note that it is not possible for a target to
        force active communication mode.

        >>> tta.atr_res = ttf.atr_res = atr_res
        >>> dep = DEP(atr_res=atr_res, tta=tta, ttf=ttf)
        >>> target = clf.listen(dep, timeout=2.5)
        >>> if target is not None:
        ...     print target

        **Exceptions**
        
        * :exc:`~exceptions.IOError` :const:`errno.ENODEV` when a
          local device has not been opened or got lost.

        * :exc:`~exceptions.TypeError` if *target* is not an instance
          of :class:`TTA`, :class:`TTB`, :class:`TTF`, or
          :class:`DEP`.

        * :exc:`~exceptions.ValueError` if *target* does not contain a
          required response attribute.

        * :exc:`~exceptions.NotImplementedError` if listen for
          *target* is not supported by the device.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        with self.lock:
            info = "listen {0:.3f} seconds for {1}"
            self.listen_target = self.sensed_target = None
            if type(target) is TTA:
                log.debug(info.format(timeout, target.brty))
                self.listen_target = self.device.listen_tta(target, timeout)
            elif type(target) is TTB:
                log.debug(info.format(timeout, target.brty))
                self.listen_target = self.device.listen_ttb(target, timeout)
            elif type(target) is TTF:
                log.debug(info.format(timeout, target.brty))
                self.listen_target = self.device.listen_ttf(target, timeout)
            elif type(target) is DEP:
                log.debug(info.format(timeout, "DEP"))
                self.listen_target = self.device.listen_dep(target, timeout)
            else:
                raise TypeError("target is not a recognized technology type")
            return self.listen_target

    def exchange(self, send_data, timeout):
        """Exchange data with an activated target (*send_data* is a command
        frame) or as an activated target (*send_data* is a response
        frame). Returns a target response frame (if data is send to an
        activated target) or a next command frame (if data is send
        from an activated target). Returns None if the communication
        link broke during exchange (if data is sent as a target). The
        timeout is the number of seconds to wait for data to return,
        if the timeout expires an nfc.clf.TimeoutException is
        raised. Other nfc.clf.DigitalError exceptions may be raised if
        an error is detected during communication.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
        
        with self.lock:
            log.debug(">>> %s %.3fs" % (str(send_data).encode("hex"), timeout))
            if self.sensed_target:
                exchange = self.device.send_cmd_recv_rsp
                target = self.sensed_target
            elif self.listen_target:
                exchange = self.device.send_rsp_recv_cmd
                target = self.listen_target
            else:
                log.error("no active target for data exchange")
                return None
            rcvd_data = exchange(target, send_data, timeout)
            log.debug("<<< %s" % str(rcvd_data).encode("hex"))
            return rcvd_data

    @property
    def max_send_data_size(self):
        """The maximum number of octets that can be send with the
        :meth:`exchange` method in the established operating mode.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        return self.device.max_send_data_size

    @property
    def max_recv_data_size(self):
        """The maximum number of octets that can be received with the
        :meth:`exchange` method in the established operating mode.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        return self.device.max_recv_data_size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        if self.device is not None:
            s = "{dev.vendor_name} {dev.product_name} on {dev.path}"
            return s.format(dev=self.device)
        else: return self.__repr__()

###############################################################################
#
# Technology Type Classes
#
###############################################################################

class TechnologyType(object):
    """The base class for all technology types. A technology type class
    holds various attributes needed on input and returned from the
    :meth:`sense` and :meth:`listen` methods. Parameters depend on
    context and stage. Reading an attribute that is not set yields
    *None* (and not an AttributeError exception).

    """
    def __init__(self, bitrate=None, **kwargs):
        self.bitrate = bitrate if bitrate else 0
        for name in kwargs:
            self.__dict__[name] = kwargs[name]

    @property
    def brty(self):
        """A string that combines bitrate and technology type, e.g. '106A'."""
        ty = self.__class__.__name__[-1:]
        return "{0}{1}".format(self.bitrate if self.bitrate else '', ty)

    def __getattr__(self, name):
        return None

    def __eq__(self, other):
        return type(self) == type(other) and self.__dict__ == other.__dict__

    def __len__(self):
        return len(self.__dict__) - 1

    def __str__(self):
        attrs = []
        for name in sorted(self.__dict__.keys()):
            if name == "bitrate": continue
            value = self.__dict__[name]
            if isinstance(value, (bytearray, str)):
                value = str(value).encode("hex").upper()
            attrs.append("{0}={1}".format(name, value))
        return "{brty}({attrs})".format(brty=self.brty, attrs=', '.join(attrs))

class TTA(TechnologyType):
    """Parameters for Technology Type A."""

class TTB(TechnologyType):
    """Parameters for Technology Type B."""

class TTF(TechnologyType):
    """Parameters for Technology Type F."""

class DEP(TechnologyType):
    """Parameters for Data Exchange Protocol."""
    
    @property
    def brty(self):
        return ('', '106A', '212F', '', '424F')[self.bitrate//106]

    def __str__(self):
        return 'DEP ' + super(DEP, self).__str__()

###############################################################################
#
# Exception Classes
#
###############################################################################

class DigitalError(Exception):
    """Base class for NFC Forum Digital Specification errors.

    """
    pass
    
class ProtocolError(DigitalError):
    """Raised when an NFC Forum Digital Specification protocol error
    occured.

    """
    pass

class TransmissionError(DigitalError):
    """Raised when an NFC Forum Digital Specification transmission error
    occured.

    """
    pass

class TimeoutError(DigitalError):
    """Raised when an NFC Forum Digital Specification timeout error
    occured.

    """
    pass
