# -*- coding: latin-1 -*-
# -----------------------------------------------------------------------------
# Copyright 2009, 2017 Stephen Tiedemann <stephen.tiedemann@gmail.com>
#
# Licensed under the EUPL, Version 1.1 or - as soon they
# will be approved by the European Commission - subsequent
# versions of the EUPL (the "Licence");
# You may not use this work except in compliance with the
# Licence.
# You may obtain a copy of the Licence at:
#
# https://joinup.ec.europa.eu/software/page/eupl
#
# Unless required by applicable law or agreed to in
# writing, software distributed under the Licence is
# distributed on an "AS IS" basis,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied.
# See the Licence for the specific language governing
# permissions and limitations under the Licence.
# -----------------------------------------------------------------------------
import nfc.tag
import nfc.dep
import nfc.llcp
from . import device

import binascii
import os
import re
import time
import errno
import threading

import logging
log = logging.getLogger(__name__)


def print_data(data):
    return 'None' if data is None else binascii.hexlify(data).decode('latin')


class ContactlessFrontend(object):
    """This class is the main interface for working with contactless
    devices. The :meth:`connect` method provides easy access to the
    contactless functionality through automated discovery of remote
    cards and devices and activation of appropiate upper level
    protocols for further interaction. The :meth:`sense`,
    :meth:`listen` and :meth:`exchange` methods provide a low-level
    interface for more specialized tasks.

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
        self.target = None
        self.lock = threading.Lock()
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
            if self.device:
                log.info("using {0}".format(self.device))
            else:
                log.error("no reader available on path " + path)
            return bool(self.device)

    def close(self):
        """Close the contacless reader device."""
        with self.lock:
            if self.device is not None:
                try:
                    self.device.close()
                except IOError:
                    pass
                self.device = None

    def connect(self, **options):
        """Connect with a Target or Initiator

        The calling thread is blocked until a single activation and
        deactivation has completed or a callback function supplied as
        the keyword argument ``terminate`` returns a true value. The
        example below makes :meth:`~connect()` return after 5 seconds,
        regardless of whether a peer device was connected or not.

        >>> import nfc, time
        >>> clf = nfc.ContactlessFrontend('usb')
        >>> after5s = lambda: time.time() - started > 5
        >>> started = time.time(); clf.connect(llcp={}, terminate=after5s)

        Connect options are given as keyword arguments with dictionary
        values. Possible options are:

        * ``rdwr={key: value, ...}`` - options for reader/writer
        * ``llcp={key: value, ...}`` - options for peer to peer
        * ``card={key: value, ...}`` - options for card emulation

        **Reader/Writer Options**

        'targets' : iterable
           A list of bitrate and technology type strings that will
           produce the :class:`~nfc.clf.RemoteTarget` objects to
           discover. The default is ``('106A', '106B', '212F')``.

        'on-startup' : function(targets)
           This function is called before any attempt to discover a
           remote card. The *targets* argument provides a list of
           :class:`RemoteTarget` objects prepared from the 'targets'
           bitrate and technology type strings. The function must
           return a list of of those :class:`RemoteTarget` objects
           that shall be finally used for discovery, those targets may
           have additional attributes. An empty list or anything else
           that evaluates false will remove the 'rdwr' option
           completely.

        'on-discover' : function(target)
           This function is called when a :class:`RemoteTarget` has
           been discovered. The *target* argument contains the
           technology type specific discovery responses and should be
           evaluated for multi-protocol support. The target will be
           further activated only if this function returns a true
           value. The default function depends on the 'llcp' option,
           if present then the function returns True only if the
           target does not indicate peer to peer protocol support,
           otherwise it returns True for all targets.

        'on-connect' : function(tag)
           This function is called when a remote tag has been
           activated. The *tag* argument is an instance of class
           :class:`nfc.tag.Tag` and can be used for tag reading and
           writing within the callback or in a separate thread. Any
           true return value instructs :meth:`connect` to wait until
           the tag is no longer present and then return True, any
           false return value implies immediate return of the
           :class:`nfc.tag.Tag` object.

        'on-release' : function(tag)
           This function is called when the presence check was run
           (the 'on-connect' function returned a true value) and
           determined that communication with the *tag* has become
           impossible, or when the 'terminate' function returned a
           true value. The *tag* object may be used for cleanup
           actions but not for communication.

        'iterations' : integer
           This determines the number of sense cycles performed
           between calls to the terminate function. Each iteration
           searches once for all specified targets. The default value
           is 5 iterations and between each iteration is a waiting
           time determined by the 'interval' option described below.
           As an effect of math there will be no waiting time if
           iterations is set to 1.

        'interval' : float
           This determines the waiting time between iterations. The
           default value of 0.5 seconds is considered a sensible
           tradeoff between responsiveness in terms of tag discovery
           and power consumption. It should be clear that changing
           this value will impair one or the other. There is no free
           beer.

        'beep-on-connect': boolean
            If the device supports beeping or flashing an LED,
            automatically perform this functionality when a tag is
            successfully detected AND the 'on-connect' function
            returns a true value. Defaults to True.

        .. sourcecode:: python

           import nfc

           def on_startup(targets):
               for target in targets:
                   target.sensf_req = bytearray.fromhex("0012FC0000")
               return targets

           def on_connect(tag):
               print(tag)

           rdwr_options = {
               'targets': ['212F', '424F'],
               'on-startup': on_startup,
               'on-connect': on_connect,
           }
           with nfc.ContactlessFrontend('usb') as clf:
               tag = clf.connect(rdwr=rdwr_options)
               if tag.ndef:
                   print(tag.ndef.message.pretty())

        **Peer To Peer Options**

        'on-startup' : function(llc)
           This function is called before any attempt to establish
           peer to peer communication. The *llc* argument provides the
           :class:`~nfc.llcp.llc.LogicalLinkController` that may be
           used to allocate and bind listen sockets for local
           services. The function should return the *llc* object if
           activation shall continue. Any other value removes the
           'llcp' option.

        'on-connect' : function(llc)
           This function is called when peer to peer communication is
           successfully established. The *llc* argument provides the
           now activated :class:`~nfc.llcp.llc.LogicalLinkController`
           ready for allocation of client communication sockets and
           data exchange in separate work threads. The function should
           a true value return more or less immediately, unless it
           wishes to handle the logical link controller run loop by
           itself and anytime later return a false value.

        'on-release' : function(llc)
           This function is called when the symmetry loop was run (the
           'on-connect' function returned a true value) and determined
           that communication with the remote peer has become
           impossible, or when the 'terminate' function returned a
           true value. The *llc* object may be used for cleanup
           actions but not for communication.

        'role' : string
           This attribute determines whether the local device will
           restrict itself to either ``'initiator'`` or ``'target'``
           mode of operation. As Initiator the local device will try
           to discover a remote device. As Target it waits for being
           discovered. The default is to alternate between both roles.

        'miu' : integer
           This attribute sets the maximum information unit size that
           is announced to the remote device during link activation.
           The default and also smallest possible value is 128 bytes.

        'lto' : integer
           This attribute sets the link timeout value (given in
           milliseconds) that is announced to the remote device during
           link activation. It informs the remote device that if the
           local device does not return a protocol data unit before
           the timeout expires, the communication link is broken and
           can not be recovered. The *lto* is an important part of the
           user experience, it ultimately tells when the user should
           no longer expect communication to continue. The default
           value is 500 millisecond.

        'agf' : boolean
           Some early phone implementations did not properly handle
           aggregated protocol data units. This attribute allows to
           disable the use af aggregation at the cost of efficiency.
           Aggregation is disabled with a false value. The default
           is to use aggregation.

        'brs' : integer
           For the local device in Initiator role the bit rate
           selector determines the the bitrate to negotiate with the
           remote Target. The value may be 0, 1, or 2 for 106, 212, or
           424 kbps, respectively. The default is to negotiate 424
           kbps.

        'acm' : boolean
           For the local device in Initiator role this attribute
           determines whether a remote Target may also be activated in
           active communication mode. In active communication mode
           both peer devices mutually generate a radio field when
           sending. The default is to use passive communication mode.

        'rwt' : float
           For the local device in Target role this attribute sets the
           response waiting time announced during link activation. The
           response waiting time is a medium access layer (NFC-DEP)
           value that indicates when the remote Initiator shall
           attempt error recovery after missing a Target response. The
           value is the waiting time index *wt* that determines the
           effective response waiting time by the formula ``rwt =
           4096/13.56E6 * pow(2, wt)``. The value shall not be greater
           than 14. The default value is 8 and yields an effective
           response waiting time of 77.33 ms.

        'lri' : integer
           For the local device in Initiator role this attribute sets
           the length reduction for medium access layer (NFC-DEP)
           information frames. The value may be 0, 1, 2, or 3 for a
           maximum payload size of 64, 128, 192, or 254 bytes,
           respectively. The default value is 3.

        'lrt' : integer
           For the local device in Target role this attribute sets
           the length reduction for medium access layer (NFC-DEP)
           information frames. The value may be 0, 1, 2, or 3 for a
           maximum payload size of 64, 128, 192, or 254 bytes,
           respectively. The default value is 3.

        .. sourcecode:: python

           import nfc
           import nfc.llcp
           import threading

           def server(socket):
               message, address = socket.recvfrom()
               socket.sendto("It's me!", address)
               socket.close()

           def client(socket):
               socket.sendto("Hi there!", address=32)
               socket.close()

           def on_startup(llc):
               socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
               socket.bind(address=32)
               threading.Thread(target=server, args=(socket,)).start()
               return llc

           def on_connect(llc):
               socket = nfc.llcp.Socket(llc, nfc.llcp.LOGICAL_DATA_LINK)
               threading.Thread(target=client, args=(socket,)).start()
               return True

           llcp_options = {
               'on-startup': on_startup,
               'on-connect': on_connect,
           }
           with nfc.ContactlessFrontend('usb') as clf:
               clf.connect(llcp=llcp_options)
               print("link terminated")

        **Card Emulation Options**

        'on-startup' : function(target)
           This function is called to prepare a local target for
           discovery. The input argument is a fresh instance of an
           unspecific :class:`LocalTarget` that can be set to the
           desired bitrate and modulation type and populated with the
           type specific discovery responses (see :meth:`listen` for
           response data that is needed). The fully specified target
           object must then be returned.

        'on-discover' : function(target)
           This function is called when the :class:`LocalTarget` has
           been discovered. The *target* argument contains the
           technology type specific discovery commands. The target
           will be further activated only if this function returns a
           true value. The default function always returns True.

        'on-connect' : function(tag)
           This function is called when the local target was
           discovered and a :class:`nfc.tag.TagEmulation` object
           successfully initialized. The function receives the
           emulated *tag* object which stores the first command
           received after inialization as ``tag.cmd``. The function
           should return a true value if the tag.process_command() and
           tag.send_response() methods shall be called repeatedly
           until either the remote device terminates communication or
           the 'terminate' function returns a true value. The function
           should return a false value if the :meth:`connect` method
           shall return immediately with the emulated *tag* object.

        'on-release' : function(tag)
           This function is called when the Target was released by the
           Initiator or simply moved away, or if the terminate
           callback function has returned a true value. The emulated
           *tag* object may be used for cleanup actions but not for
           communication.

        .. sourcecode:: python

           import nfc

           def on_startup(target):
               idm = bytearray.fromhex("01010501b00ac30b")
               pmm = bytearray.fromhex("03014b024f4993ff")
               sys = bytearray.fromhex("1234")
               target.brty = "212F"
               target.sensf_res = chr(1) + idm + pmm + sys
               return target

           def on_connect(tag):
               print("discovered by remote reader")
               return True

           def on_release(tag):
               print("remote reader is gone")
               return True

           card_options = {
               'on-startup': on_startup,
               'on-connect': on_connect,
               'on-release': on_release,
           }
           with nfc.ContactlessFrontend('usb') as clf:
               clf.connect(card=card_options)

        **Return Value**

        The :meth:`connect` method returns :const:`None` if there were
        no options left after the 'on-startup' functions have been
        executed or when the 'terminate' function returned a true
        value. It returns :const:`False` when terminated by any of the
        following exceptions: :exc:`~exceptions.KeyboardInterrupt`,
        :exc:`~exceptions.IOError`, :exc:`UnsupportedTargetError`.

        The :meth:`connect` method returns a :class:`~nfc.tag.Tag`,
        :class:`~nfc.llcp.llc.LogicalLinkController`, or
        :class:`~nfc.tag.TagEmulation` object if the associated
        'on-connect' function returned a false value to indicate that
        it will handle presence check, peer to peer symmetry loop, or
        command/response processing by itself.

        """
        if self.device is None:
            raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

        log.debug("connect{0}".format(
            tuple([k for k in options if options[k]])))

        terminate = options.get('terminate', lambda: False)
        rdwr_options = options.get('rdwr')
        llcp_options = options.get('llcp')
        card_options = options.get('card')

        try:
            assert isinstance(rdwr_options, (dict, type(None))), "rdwr"
            assert isinstance(llcp_options, (dict, type(None))), "llcp"
            assert isinstance(card_options, (dict, type(None))), "card"
        except AssertionError as error:
            raise TypeError("argument '%s' must be a dictionary" % error)

        if llcp_options is not None:
            llcp_options = dict(llcp_options)
            llcp_options.setdefault('on-startup', lambda llc: llc)
            llcp_options.setdefault('on-connect', lambda llc: True)
            llcp_options.setdefault('on-release', lambda llc: True)

            llc = nfc.llcp.llc.LogicalLinkController(**llcp_options)
            llc = llcp_options['on-startup'](llc)
            if isinstance(llc, nfc.llcp.llc.LogicalLinkController):
                llcp_options['llc'] = llc
            else:
                log.debug("removing llcp_options after on-startup")
                llcp_options = None

        if rdwr_options is not None:
            def on_discover(target):
                if target.sel_res and target.sel_res[0] & 0x40:
                    return False
                elif target.sensf_res and target.sensf_res[1:3] == b"\x01\xFE":
                    return False
                else:
                    return True

            rdwr_options = dict(rdwr_options)
            rdwr_options.setdefault('targets', ['106A', '106B', '212F'])
            rdwr_options.setdefault('on-startup', lambda targets: targets)
            rdwr_options.setdefault('on-discover', on_discover)
            rdwr_options.setdefault('on-connect', lambda tag: True)
            rdwr_options.setdefault('on-release', lambda tag: True)
            rdwr_options.setdefault('iterations', 5)
            rdwr_options.setdefault('interval', 0.5)
            rdwr_options.setdefault('beep-on-connect', True)

            targets = [RemoteTarget(brty) for brty in rdwr_options['targets']]
            targets = rdwr_options['on-startup'](targets)
            if targets and all([isinstance(o, RemoteTarget) for o in targets]):
                rdwr_options['targets'] = targets
            else:
                log.debug("removing rdwr_options after on-startup")
                rdwr_options = None

        if card_options is not None:
            card_options = dict(card_options)
            card_options.setdefault('on-startup', lambda target: None)
            card_options.setdefault('on-discover', lambda target: True)
            card_options.setdefault('on-connect', lambda tag: True)
            card_options.setdefault('on-release', lambda tag: True)

            target = nfc.clf.LocalTarget()
            target = card_options['on-startup'](target)
            if isinstance(target, LocalTarget):
                card_options['target'] = target
            else:
                log.debug("removing card_options after on-startup")
                card_options = None

        if not (rdwr_options or llcp_options or card_options):
            log.warning("no options to connect")
            return None

        log.debug("connect options after startup: %s",
                  ', '.join(filter(bool, ["rdwr" if rdwr_options else None,
                                          "llcp" if llcp_options else None,
                                          "card" if card_options else None])))

        try:
            while not terminate():
                if rdwr_options:
                    result = self._rdwr_connect(rdwr_options, terminate)
                    if bool(result) is True:
                        return result
                if llcp_options:
                    result = self._llcp_connect(llcp_options, terminate)
                    if bool(result) is True:
                        return result
                if card_options:
                    result = self._card_connect(card_options, terminate)
                    if bool(result) is True:
                        return result
        except IOError as error:
            log.error(error)
            return False
        except UnsupportedTargetError as error:
            log.info(error)
            return False
        except KeyboardInterrupt:
            log.debug("terminated by keyboard interrupt")
            return False

    def _rdwr_connect(self, options, terminate):
        target = self.sense(*options['targets'],
                            iterations=options['iterations'],
                            interval=options['interval'])
        if target is not None:
            log.debug("discovered target {0}".format(target))
            if options['on-discover'](target):
                tag = nfc.tag.activate(self, target)
                if tag is not None:
                    log.debug("connected to {0}".format(tag))
                    if options['on-connect'](tag):
                        if options['beep-on-connect']:
                            self.device.turn_on_led_and_buzzer()
                        while not terminate() and tag.is_present:
                            time.sleep(0.1)
                        self.device.turn_off_led_and_buzzer()
                        return options['on-release'](tag)
                    else:
                        return tag

    def _llcp_connect(self, options, terminate):
        llc = options['llc']
        for role in ('target', 'initiator'):
            if options.get('role') is None or options.get('role') == role:
                DEP = eval("nfc.dep." + role.capitalize())
                dep_cfg = ('brs', 'acm', 'rwt', 'lrt', 'lri')
                dep_cfg = {k: options[k] for k in dep_cfg if k in options}
                if llc.activate(mac=DEP(clf=self), **dep_cfg):
                    log.debug("connected {0}".format(llc))
                    if options['on-connect'](llc):
                        llc.run(terminate=terminate)
                        return options['on-release'](llc)
                    else:
                        return llc

    def _card_connect(self, options, terminate):
        timeout = options.get('timeout', 1.0)
        target = self.listen(options['target'], timeout)
        if target and options['on-discover'](target):
            log.debug("activated as {0}".format(target))
            tag = nfc.tag.emulate(self, target)
            if isinstance(tag, nfc.tag.TagEmulation):
                log.debug("connected as {0}".format(tag))
                if options['on-connect'](tag):
                    tag_rsp = tag.process_command(tag.cmd)
                    while not terminate():
                        try:
                            tag_cmd = tag.send_response(tag_rsp, None)
                            tag_rsp = tag.process_command(tag_cmd)
                        except nfc.clf.BrokenLinkError as error:
                            log.debug(error)
                            break
                        except nfc.clf.CommunicationError as error:
                            log.debug(error)
                            tag_rsp = None
                    return options['on-release'](tag)
                else:
                    return tag

    def sense(self, *targets, **options):
        """Discover a contactless card or listening device.

        .. note:: The :meth:`sense` method is intended for experts
                  with a good understanding of the commands and
                  responses exchanged during target activation (the
                  notion used for commands and responses follows the
                  NFC Forum Digital Specification). If the greater
                  level of control is not needed it is recommended to
                  use the :meth:`connect` method.

        All positional arguments build the list of potential *targets*
        to discover and must be of type :class:`RemoteTarget`. Keyword
        argument *options* may be the number of ``iterations`` of the
        sense loop set by *targets* and the ``interval`` between
        iterations. The return value is either a :class:`RemoteTarget`
        instance or :const:`None`.

        >>> import nfc, nfc.clf
        >>> from binascii import hexlify
        >>> clf = nfc.ContactlessFrontend("usb")
        >>> target1 = nfc.clf.RemoteTarget("106A")
        >>> target2 = nfc.clf.RemoteTarget("212F")
        >>> print(clf.sense(target1, target2, iterations=5, interval=0.2))
        106A(sdd_res=04497622D93881, sel_res=00, sens_res=4400)

        A **Type A Target** is specified with the technology letter
        ``A`` following the bitrate to be used for the SENS_REQ
        command (almost always must the bitrate be 106 kbps). To
        discover only a specific Type A target, the NFCID1 (UID) can
        be set with a 4, 7, or 10 byte ``sel_req`` attribute (cascade
        tags are handled internally).

        >>> target = nfc.clf.RemoteTarget("106A")
        >>> print(clf.sense(target))
        106A sdd_res=04497622D93881 sel_res=00 sens_res=4400
        >>> target.sel_req = bytearray.fromhex("04497622D93881")
        >>> print(clf.sense(target))
        106A sdd_res=04497622D93881 sel_res=00 sens_res=4400
        >>> target.sel_req = bytearray.fromhex("04497622")
        >>> print(clf.sense(target))
        None

        A **Type B Target** is specified with the technology letter
        ``B`` following the bitrate to be used for the SENSB_REQ
        command (almost always must the bitrate be 106 kbps). A
        specific application family identifier can be set with the
        first byte of a ``sensb_req`` attribute (the second byte PARAM
        is ignored when it can not be set to local device, 00h is a
        safe value in all cases).

        >>> target = nfc.clf.RemoteTarget("106B")
        >>> print(clf.sense(target))
        106B sens_res=50E5DD3DC900000011008185
        >>> target.sensb_req = bytearray.fromhex("0000")
        >>> print(clf.sense(target))
        106B sens_res=50E5DD3DC900000011008185
        >>> target.sensb_req = bytearray.fromhex("FF00")
        >>> print(clf.sense(target))
        None

        A **Type F Target** is specified with the technology letter
        ``F`` following the bitrate to be used for the SENSF_REQ
        command (the typically supported bitrates are 212 and 424
        kbps). The default SENSF_REQ command allows all targets to
        answer, requests system code information, and selects a single
        time slot for the SENSF_RES response. This can be changed with
        the ``sensf_req`` attribute.

        >>> target = nfc.clf.RemoteTarget("212F")
        >>> print(clf.sense(target))
        212F sensf_res=0101010601B00ADE0B03014B024F4993FF12FC
        >>> target.sensf_req = bytearray.fromhex("0012FC0000")
        >>> print(clf.sense(target))
        212F sensf_res=0101010601B00ADE0B03014B024F4993FF
        >>> target.sensf_req = bytearray.fromhex("00ABCD0000")
        >>> print(clf.sense(target))
        None

        An **Active Communication Mode P2P Target** search is selected
        with an ``atr_req`` attribute. The choice of bitrate and
        modulation type is 106A, 212F, and 424F.

        >>> atr = bytearray.fromhex("D4000102030405060708091000000030")
        >>> target = clf.sense(nfc.clf.RemoteTarget("106A", atr_req=atr))
        >>> if target and target.atr_res:
        >>>     print(hexlify(target.atr_res).decode())
        d501c023cae6b3182afe3dee0000000e3246666d01011103020013040196
        >>> target = clf.sense(nfc.clf.RemoteTarget("424F", atr_req=atr))
        >>> if target and target.atr_res:
        >>>     print(hexlify(target.atr_res).decode())
        d501dc0104f04584e15769700000000e3246666d01011103020013040196

        Some drivers must modify the ATR_REQ to cope with hardware
        limitations, for example change length reduction value to
        reduce the maximum size of target responses. The ATR_REQ that
        has been send is given by the ``atr_req`` attribute of the
        returned RemoteTarget object.

        A **Passive Communication Mode P2P Target** responds to 106A
        discovery with bit 6 of SEL_RES set to 1, and to 212F/424F
        discovery (when the request code RC is 0 in the SENSF_REQ
        command) with an NFCID2 that starts with 01FEh in the
        SENSF_RES response. Responses below are from a Nexus 5
        configured for NFC-DEP Protocol (SEL_RES bit 6 is set) and
        Type 4A Tag (SEL_RES bit 5 is set).

        >>> print(clf.sense(nfc.clf.RemoteTarget("106A")))
        106A sdd_res=08796BEB sel_res=60 sens_res=0400
        >>> sensf_req = bytearray.fromhex("00FFFF0000")
        >>> print(clf.sense(nfc.clf.RemoteTarget("424F", sensf_req=sensf_req)))
        424F sensf_res=0101FE1444EFB88FD50000000000000000

        Errors found in the *targets* argument list raise exceptions
        only if exactly one target is given. If multiple targets are
        provided, any target that is not supported or has invalid
        attributes is just ignored (but is logged as a debug message).

        **Exceptions**

        * :exc:`~exceptions.IOError` (ENODEV) when a local contacless
          communication device has not been opened or communication
          with the local device is no longer possible.

        * :exc:`nfc.clf.UnsupportedTargetError` if the single target
          supplied as input is not supported by the active driver.
          This exception is never raised when :meth:`sense` is called
          with multiple targets, those unsupported are then silently
          ignored.

        """
        def sense_tta(target):
            if target.sel_req and len(target.sel_req) not in (4, 7, 10):
                raise ValueError("sel_req must be 4, 7, or 10 byte")
            target = self.device.sense_tta(target)
            log.debug("found %s", target)
            if target and len(target.sens_res) != 2:
                error = "SENS Response Format Error (wrong length)"
                log.debug(error)
                raise ProtocolError(error)
            if target and target.sens_res[0] & 0b00011111 == 0:
                if target.sens_res[1] & 0b00001111 != 0b1100:
                    error = "SENS Response Data Error (T1T config)"
                    log.debug(error)
                    raise ProtocolError(error)
                if not target.rid_res:
                    error = "RID Response Error (no response received)"
                    log.debug(error)
                    raise ProtocolError(error)
                if len(target.rid_res) != 6:
                    error = "RID Response Format Error (wrong length)"
                    log.debug(error)
                    raise ProtocolError(error)
                if target.rid_res[0] >> 4 != 0b0001:
                    error = "RID Response Data Error (invalid HR0)"
                    log.debug(error)
                    raise ProtocolError(error)
            return target

        def sense_ttb(target):
            return self.device.sense_ttb(target)

        def sense_ttf(target):
            return self.device.sense_ttf(target)

        def sense_dep(target):
            if len(target.atr_req) < 16:
                raise ValueError("minimum atr_req length is 16 byte")
            if len(target.atr_req) > 64:
                raise ValueError("maximum atr_req length is 64 byte")
            return self.device.sense_dep(target)

        for target in targets:
            if not isinstance(target, RemoteTarget):
                raise ValueError("invalid target argument type: %r" % target)

        with self.lock:
            if self.device is None:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            self.target = None  # forget captured target
            self.device.mute()  # deactivate the rf field

            for i in range(max(1, options.get('iterations', 1))):
                started = time.time()
                for target in targets:
                    log.debug("sense {0}".format(target))
                    try:
                        if target.atr_req is not None:
                            self.target = sense_dep(target)
                        elif target.brty.endswith('A'):
                            self.target = sense_tta(target)
                        elif target.brty.endswith('B'):
                            self.target = sense_ttb(target)
                        elif target.brty.endswith('F'):
                            self.target = sense_ttf(target)
                        else:
                            info = "unknown technology type in %r"
                            raise UnsupportedTargetError(info % target.brty)
                    except UnsupportedTargetError as error:
                        if len(targets) == 1:
                            raise error
                        else:
                            log.debug(error)
                    except CommunicationError as error:
                        log.debug(error)
                    else:
                        if self.target is not None:
                            log.debug("found {0}".format(self.target))
                            return self.target
                if len(targets) > 0:
                    self.device.mute()  # deactivate the rf field
                if i < options.get('iterations', 1) - 1:
                    elapsed = time.time() - started
                    time.sleep(max(0, options.get('interval', 0.1)-elapsed))

    def listen(self, target, timeout):
        """Listen *timeout* seconds to become activated as *target*.

        .. note:: The :meth:`listen` method is intended for experts
                  with a good understanding of the commands and
                  responses exchanged during target activation (the
                  notion used for commands and responses follows the
                  NFC Forum Digital Specification). If the greater
                  level of control is not needed it is recommended to
                  use the :meth:`connect` method.

        The *target* argument is a :class:`LocalTarget` object that
        provides bitrate, technology type and response data
        attributes. The return value is either a :class:`LocalTarget`
        object with bitrate, technology type and request/response data
        attributes or :const:`None`.

        An **P2P Target** is selected when the ``atr_res`` attribute
        is set. The bitrate and technology type are decided by the
        Initiator and do not need to be specified. The ``sens_res``,
        ``sdd_res`` and ``sel_res`` attributes for Type A technology
        as well as the ``sensf_res`` attribute for Type F technolgy
        must all be set.

        When activated, the bitrate and type are set to the current
        communication values, the ``atr_req`` attribute contains the
        ATR_REQ received from the Initiator and the ``dep_req``
        attribute contains the first DEP_REQ received after
        activation. If the Initiator has changed communication
        parameters, the ``psl_req`` attribute holds the PSL_REQ that
        was received. The ``atr_res`` (and the ``psl_res`` if
        transmitted) are also made available.

        If the local target was activated in passive communication
        mode either the Type A response (``sens_res``, ``sdd_res``,
        ``sel_res``) or Type F response (``sensf_res``) attributes
        will be present.

        With a Nexus 5 on a reader connected via USB the following
        code should be working and produce similar output (the Nexus 5
        prioritizes active communication mode):

        >>> import nfc, nfc.clf
        >>> clf = nfc.ContactlessFrontend("usb")
        >>> atr_res = "d50101fe0102030405060708000000083246666d010110"
        >>> target = nfc.clf.LocalTarget()
        >>> target.sensf_res = bytearray.fromhex("0101FE"+16*"FF")
        >>> target.sens_res = bytearray.fromhex("0101")
        >>> target.sdd_res = bytearray.fromhex("08010203")
        >>> target.sel_res = bytearray.fromhex("40")
        >>> target.atr_res = bytearray.fromhex(atr_res)
        >>> print(clf.listen(target, timeout=2.5))
        424F atr_res=D50101FE0102030405060708000000083246666D010110 ...

        A **Type A Target** is selected when ``atr_res`` is not
        present and the technology type is ``A``. The bitrate should
        be set to 106 kbps, even if a driver supports higher bitrates
        they would need to be set after activation. The ``sens_res``,
        ``sdd_res`` and ``sel_res`` attributes must all be provided.

        >>> target = nfc.clf.Localtarget("106A")
        >>> target.sens_res = bytearray.fromhex("0101"))
        >>> target.sdd_res = bytearray.fromhex("08010203")
        >>> target.sel_res = bytearray.fromhex("00")
        >>> print(clf.listen(target, timeout=2.5))
        106A sdd_res=08010203 sel_res=00 sens_res=0101 tt2_cmd=3000

        A **Type B Target** is selected when ``atr_res`` is not
        present and the technology type is ``B``. Unfortunately none
        of the supported devices supports Type B technology for listen
        and an :exc:`nfc.clf.UnsupportedTargetError` exception will be
        the only result.

        >>> target = nfc.clf.LocalTarget("106B")
        >>> try: clf.listen(target, 2.5)
        ... except nfc.clf.UnsupportedTargetError: print("sorry")
        ...
        sorry

        A **Type F Target** is selected when ``atr_res`` is not
        present and the technology type is ``F``. The bitrate may be
        212 or 424 kbps. The ``sensf_res`` attribute must be provided.

        >>> idm, pmm, sys = "02FE010203040506", "FFFFFFFFFFFFFFFF", "12FC"
        >>> target = nfc.clf.LocalTarget("212F")
        >>> target.sensf_res = bytearray.fromhex("01" + idm + pmm + sys)
        >>> print(clf.listen(target, 2.5))
        212F sensf_req=00FFFF0003 tt3_cmd=0C02FE010203040506 ...

        **Exceptions**

        * :exc:`~exceptions.IOError` (ENODEV) when a local contacless
          communication device has not been opened or communication
          with the local device is no longer possible.

        * :exc:`nfc.clf.UnsupportedTargetError` if the single target
          supplied as input is not supported by the active driver.
          This exception is never raised when :meth:`sense` is called
          with multiple targets, those unsupported are then silently
          ignored.

        """
        def listen_tta(target, timeout):
            return self.device.listen_tta(target, timeout)

        def listen_ttb(target, timeout):
            return self.device.listen_ttb(target, timeout)

        def listen_ttf(target, timeout):
            return self.device.listen_ttf(target, timeout)

        def listen_dep(target, timeout):
            target = self.device.listen_dep(target, timeout)
            if target and target.atr_req:
                try:
                    assert len(target.atr_req) >= 16, "less than 16 byte"
                    assert len(target.atr_req) <= 64, "more than 64 byte"
                    return target
                except AssertionError as error:
                    log.debug("atr_req is %s", str(error))

        assert isinstance(target, LocalTarget), \
            "invalid target argument type: %r" % target

        with self.lock:
            if self.device is None:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            self.target = None  # forget captured target
            self.device.mute()  # deactivate the rf field

            info = "listen %.3f seconds for %s"
            if target.atr_res is not None:
                log.debug(info, timeout, "DEP")
                self.target = listen_dep(target, timeout)
            elif target.brty in ('106A', '212A', '424A'):
                log.debug(info, timeout, target)
                self.target = listen_tta(target, timeout)
            elif target.brty in ('106B', '212B', '424B', '848B'):
                log.debug(info, timeout, target)
                self.target = listen_ttb(target, timeout)
            elif target.brty in ('212F', '424F'):
                log.debug(info, timeout, target)
                self.target = listen_ttf(target, timeout)
            else:
                errmsg = "unsupported bitrate technology type {}"
                raise ValueError(errmsg.format(target.brty))

            return self.target

    def exchange(self, send_data, timeout):
        """Exchange data with an activated target (*send_data* is a command
        frame) or as an activated target (*send_data* is a response
        frame). Returns a target response frame (if data is send to an
        activated target) or a next command frame (if data is send
        from an activated target). Returns None if the communication
        link broke during exchange (if data is sent as a target). The
        timeout is the number of seconds to wait for data to return,
        if the timeout expires an nfc.clf.TimeoutException is
        raised. Other nfc.clf.CommunicationError exceptions may be raised if
        an error is detected during communication.

        """
        with self.lock:
            if self.device is None:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))

            log.debug(">>> %s timeout=%s", print_data(send_data), str(timeout))

            if isinstance(self.target, RemoteTarget):
                exchange = self.device.send_cmd_recv_rsp
            elif isinstance(self.target, LocalTarget):
                exchange = self.device.send_rsp_recv_cmd
            else:
                log.error("no target for data exchange")
                return None

            send_time = time.time()
            rcvd_data = exchange(self.target, send_data, timeout)
            recv_time = time.time() - send_time

            log.debug("<<< %s %.3fs", print_data(rcvd_data), recv_time)
            return rcvd_data

    @property
    def max_send_data_size(self):
        """The maximum number of octets that can be send with the
        :meth:`exchange` method in the established operating mode.

        """
        with self.lock:
            if self.device is None:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
            else:
                return self.device.get_max_send_data_size(self.target)

    @property
    def max_recv_data_size(self):
        """The maximum number of octets that can be received with the
        :meth:`exchange` method in the established operating mode.

        """
        with self.lock:
            if self.device is None:
                raise IOError(errno.ENODEV, os.strerror(errno.ENODEV))
            else:
                return self.device.get_max_recv_data_size(self.target)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def __str__(self):
        if self.device is not None:
            s = "{dev.vendor_name} {dev.product_name} on {dev.path}"
            return s.format(dev=self.device)
        else:
            return self.__repr__()


###############################################################################
#
# Targets
#
###############################################################################
class Target(object):
    def __init__(self, **kwargs):
        for name in kwargs:
            self.__dict__[name] = kwargs[name]

    def __getattr__(self, name):
        return None

    def __eq__(self, other):
        return self.__dict__ == other.__dict__

    def __str__(self):
        attrs = []
        for name in sorted(self.__dict__.keys()):
            if name.startswith('_'):
                continue
            value = self.__dict__[name]
            if isinstance(value, (bytes, bytearray)):
                value = binascii.hexlify(value).decode().upper()
            attrs.append("{0}={1}".format(name, value))
        return "{brty} {attrs}".format(brty=self.brty, attrs=' '.join(attrs))


class RemoteTarget(Target):
    """A RemoteTarget instance provides bitrate and technology type and
    command/response data of a remote card or device that, when input
    to :meth:`sense`, shall be attempted to discover and, when
    returned by :meth:`sense`, has been discovered by the local
    device. Command/response data attributes, whatever name, default
    to None.

    """
    brty_pattern = re.compile(r'(\d+[A-Z])(?:/(\d+[A-Z])|.*)')

    def __init__(self, brty, **kwargs):
        super(RemoteTarget, self).__init__(**kwargs)
        self.brty = brty

    @property
    def brty(self):
        """A string that combines bitrate and technology type, e.g. '106A'."""
        return self._brty_send

    @brty.setter
    def brty(self, value):
        brty_pattern_match = self.brty_pattern.match(value)
        if brty_pattern_match:
            (self._brty_send, self._brty_recv) = brty_pattern_match.groups()
            if not self._brty_recv:
                self._brty_recv = self._brty_send
        else:
            raise ValueError("brty pattern does not match for %r" % value)

    @property
    def brty_send(self):
        return self._brty_send

    @property
    def brty_recv(self):
        return self._brty_recv


class LocalTarget(Target):
    """A LocalTarget instance provides bitrate and technology type and
    command/response data of the local card or device that, when input
    to :meth:`listen`, shall be made available for discovery and, when
    returned by :meth:`listen`, has been discovered by a remote
    device. Command/response data attributes, whatever name, default
    to None.

    """
    def __init__(self, brty='106A', **kwargs):
        super(LocalTarget, self).__init__(**kwargs)
        self.brty = brty

    @property
    def brty(self):
        """A string that combines bitrate and technology type, e.g. '106A'."""
        return self._brty_send \
            if self._brty_send == self._brty_recv \
            else self._brty_send+"/"+self._brty_recv

    @brty.setter
    def brty(self, value):
        self._brty_send = self._brty_recv = value


###############################################################################
#
# Exceptions
#
###############################################################################
class Error(Exception):
    """Base class for exceptions specific to the contacless frontend module.

    - UnsupportedTargetError
    - CommunicationError

      - ProtocolError
      - TransmissionError
      - TimeoutError
      - BrokenLinkError

    """


class UnsupportedTargetError(Error):
    """The :class:`RemoteTarget` input to
    :meth:`ContactlessFrontend.sense` or :class:`LocalTarget` input to
    :meth:`ContactlessFrontend.listen` is not supported by the local
    device.

    """


class CommunicationError(Error):
    """Base class for communication errors.

    """


class ProtocolError(CommunicationError):
    """Raised when an NFC Forum Digital Specification protocol error
    occured.

    """


class TransmissionError(CommunicationError):
    """Raised when an NFC Forum Digital Specification transmission error
    occured.

    """


class TimeoutError(CommunicationError):
    """Raised when an NFC Forum Digital Specification timeout error
    occured.

    """


class BrokenLinkError(CommunicationError):
    """The remote device (Reader/Writer or P2P Device) has deactivated the
    RF field or is no longer within communication distance.

    """
