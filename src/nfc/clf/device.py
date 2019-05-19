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
"""All contactless drivers must implement the interface defined in
:class:`~nfc.clf.device.Device`. Unsupported target discovery or target
emulation methods raise :exc:`~nfc.clf.UnsupportedTargetError`. The
interface is used internally by :class:`~nfc.clf.ContactlessFrontend`
and is not intended as an application programming interface. Device
driver methods are not thread-safe and do not necessarily check input
arguments when they are supposed to be valid. The interface may change
without notice at any time.

"""
from . import transport

import os
import sys
import errno
import importlib

import logging
log = logging.getLogger(__name__)

usb_device_map = {
    (0x054c, 0x0193): "pn531",   # PN531 (Sony VID/PID)
    (0x04cc, 0x0531): "pn531",   # PN531 (Philips VID/PID), SCM SCL3710
    (0x04cc, 0x2533): "pn533",   # NXP PN533 demo board
    (0x04e6, 0x5591): "pn533",   # SCM SCL3711
    (0x04e6, 0x5593): "pn533",   # SCM SCL3712
    (0x054c, 0x02e1): "rcs956",  # Sony RC-S330/360/370
    (0x054c, 0x06c1): "rcs380",  # Sony RC-S380
    (0x054c, 0x06c3): "rcs380",  # Sony RC-S380
    (0x072f, 0x2200): "acr122",  # ACS ACR122U
}

tty_driver_list = ["arygon", "pn532"]


def connect(path):
    """Connect to a local device identified by *path* and load the
    appropriate device driver. The *path* argument is documented at
    :meth:`nfc.clf.ContactlessFrontend.open`. The return value is
    either a :class:`Device` instance or :const:`None`. Note that not
    all drivers can be autodetected, specifically for serial devices
    *path* must usually also specify the driver.

    """
    assert isinstance(path, str) and len(path) > 0

    found = transport.USB.find(path)
    if found is not None:
        for vid, pid, bus, dev in found:
            module = usb_device_map.get((vid, pid))
            if module is None:
                continue

            log.debug("loading {mod} driver for usb:{vid:04x}:{pid:04x}"
                      .format(mod=module, vid=vid, pid=pid))

            if sys.platform.startswith("linux"):
                devnode = "/dev/bus/usb/%03d/%03d" % (int(bus), int(dev))
                if not os.access(devnode, os.R_OK | os.W_OK):
                    log.debug("access denied to " + devnode)
                    if len(path.split(':')) < 3:
                        continue
                    else:
                        raise IOError(errno.EACCES, os.strerror(errno.EACCES))

            driver = importlib.import_module("nfc.clf." + module)
            try:
                device = driver.init(transport.USB(bus, dev))
            except IOError as error:
                log.debug(error)
                if len(path.split(':')) < 3:
                    continue
                else:
                    raise error

            device._path = "usb:{0:03}:{1:03}".format(int(bus), int(dev))
            return device

    found = transport.TTY.find(path)
    if found is not None:
        devices = found[0]
        drivers = [found[1]] if found[1] else tty_driver_list
        globbed = found[2] or drivers is tty_driver_list
        for drv in drivers:
            for dev in devices:
                log.debug("trying {0} on {1}".format(drv, dev))
                driver = importlib.import_module("nfc.clf." + drv)
                tty = None
                try:
                    tty = transport.TTY(dev)
                    device = driver.init(tty)
                    device._path = dev
                    return device
                except IOError as error:
                    log.debug(error)
                    if tty is not None:
                        tty.close()
                    if not globbed:
                        raise

    if path.startswith("udp"):
        path = path.split(':')
        host = str(path[1]) if len(path) > 1 and path[1] else 'localhost'
        port = int(path[2]) if len(path) > 2 and path[2] else 54321
        driver = importlib.import_module("nfc.clf.udp")
        device = driver.init(host, port)
        device._path = "udp:{0}:{1}".format(host, port)
        return device


class Device(object):
    """All device drivers inherit from the :class:`Device` class and must
    implement it's methods.

    """
    def __init__(self, *args, **kwargs):
        fname = "__init__"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def __str__(self):
        strings = (self.vendor_name, self.product_name, self.chipset_name)
        return ' '.join(filter(bool, strings)) + " at " + self.path

    @property
    def vendor_name(self):
        """The device vendor name. An empty string if the vendor name could
        not be determined.

        """
        return self._vendor_name if hasattr(self, "_vendor_name") else ''

    @property
    def product_name(self):
        """The device product name. An empty string if the product name could
        not be determined.

        """
        return self._device_name if hasattr(self, "_device_name") else ''

    @property
    def chipset_name(self):
        """The name of the chipset embedded in the device."""
        return self._chipset_name

    @property
    def path(self):
        return self._path

    def close(self):
        fname = "close"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def mute(self):
        """Mutes all existing communication, most notably the device will no
        longer generate a 13.56 MHz carrier signal when operating as
        Initiator.

        """
        fname = "mute"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def sense_tta(self, target):
        """Discover a Type A Target.

        Activates the 13.56 MHz carrier signal and sends a SENS_REQ
        command at the bitrate set by **target.brty**. If a response
        is received, sends an RID_CMD for a Type 1 Tag or SDD_REQ and
        SEL_REQ for a Type 2/4 Tag and returns the responses.

        Arguments:

          target (nfc.clf.RemoteTarget): Supplies bitrate and optional
            command data for the target discovery. The only sensible
            command to set is **sel_req** populated with a UID to find
            only that specific target.

        Returns:

          nfc.clf.RemoteTarget: Response data received from a remote
            target if found. This includes at least **sens_res** and
            either **rid_res** (for a Type 1 Tag) or **sdd_res** and
            **sel_res** (for a Type 2/4 Tag).

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

        """
        fname = "sense_tta"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def sense_ttb(self, target):
        """Discover a Type B Target.

        Activates the 13.56 MHz carrier signal and sends a SENSB_REQ
        command at the bitrate set by **target.brty**. If a SENSB_RES
        is received, returns a target object with the **sensb_res**
        attribute.

        Note that the firmware of some devices (least all those based
        on PN53x) automatically sends an ATTRIB command with varying
        but always unfortunate communication settings. The drivers
        correct that situation by sending S(DESELECT) and WUPB before
        return.

        Arguments:

          target (nfc.clf.RemoteTarget): Supplies bitrate and the
            optional **sensb_req** for target discovery. Most drivers
            do no not allow a fully customized SENSB_REQ, the only
            parameter that can always be changed is the AFI byte,
            others may be ignored.

        Returns:

          nfc.clf.RemoteTarget: Response data received from a remote
            target if found. The only response data attribute is
            **sensb_res**.

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

        """
        fname = "sense_ttb"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def sense_ttf(self, target):
        """Discover a Type F Target.

        Activates the 13.56 MHz carrier signal and sends a SENSF_REQ
        command at the bitrate set by **target.brty**. If a SENSF_RES
        is received, returns a target object with the **sensf_res**
        attribute.

        Arguments:

          target (nfc.clf.RemoteTarget): Supplies bitrate and the
            optional **sensf_req** for target discovery. The default
            SENSF_REQ invites all targets to respond and requests the
            system code information bytes.

        Returns:

          nfc.clf.RemoteTarget: Response data received from a remote
            target if found. The only response data attribute is
            **sensf_res**.

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

        """
        fname = "sense_ttf"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def sense_dep(self, target):
        """Discover a NFC-DEP Target in active communication mode.

        Activates the 13.56 MHz carrier signal and sends an ATR_REQ
        command at the bitrate set by **target.brty**. If an ATR_RES
        is received, returns a target object with the **atr_res**
        attribute.

        Note that some drivers (like pn531) may modify the transport
        data bytes length reduction value in ATR_REQ and ATR_RES due
        to hardware limitations.

        Arguments:

          target (nfc.clf.RemoteTarget): Supplies bitrate and the
            mandatory **atr_req** for target discovery. The bitrate
            may be one of '106A', '212F', or '424F'.

        Returns:

          nfc.clf.RemoteTarget: Response data received from a remote
            target if found. The only response data attribute is
            **atr_res**. The actually sent and potentially modified
            ATR_REQ is also included as **atr_req** attribute.

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

        """
        fname = "sense_dep"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def listen_tta(self, target, timeout):
        """Listen as Type A Target.

        Waits to receive a SENS_REQ command at the bitrate set by
        **target.brty** and sends the **target.sens_res**
        response. Depending on the SENS_RES bytes, the Initiator then
        sends an RID_CMD (SENS_RES coded for a Type 1 Tag) or SDD_REQ
        and SEL_REQ (SENS_RES coded for a Type 2/4 Tag). Responses are
        then generated from the **rid_res** or **sdd_res** and
        **sel_res** attributes in *target*.

        Note that none of the currently supported hardware can
        actually receive an RID_CMD, thus Type 1 Tag emulation is
        impossible.

        Arguments:

          target (nfc.clf.LocalTarget): Supplies bitrate and mandatory
            response data to reply when being discovered.

          timeout (float): The maximum number of seconds to wait for a
            discovery command.

        Returns:

          nfc.clf.LocalTarget: Command data received from the remote
            Initiator if being discovered and to the extent supported
            by the device. The first command received after discovery
            is returned as one of the **tt1_cmd**, **tt2_cmd** or
            **tt4_cmd** attribute (note that unset attributes are
            always None).

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

          ~exceptions.ValueError: A required target response attribute
            is not present or does not supply the number of bytes
            expected.

        """
        fname = "listen_tta"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def listen_ttb(self, target, timeout):
        """Listen as Type A Target.

        Waits to receive a SENSB_REQ command at the bitrate set by
        **target.brty** and sends the **target.sensb_res**
        response.

        Note that none of the currently supported hardware can
        actually listen as Type B target.

        Arguments:

          target (nfc.clf.LocalTarget): Supplies bitrate and mandatory
            response data to reply when being discovered.

          timeout (float): The maximum number of seconds to wait for a
            discovery command.

        Returns:

          nfc.clf.LocalTarget: Command data received from the remote
            Initiator if being discovered and to the extent supported
            by the device. The first command received after discovery
            is returned as **tt4_cmd** attribute.

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

          ~exceptions.ValueError: A required target response attribute
            is not present or does not supply the number of bytes
            expected.

        """
        fname = "listen_ttb"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def listen_ttf(self, target, timeout):
        """Listen as Type A Target.

        Waits to receive a SENSF_REQ command at the bitrate set by
        **target.brty** and sends the **target.sensf_res**
        response. Then waits for a first command that is not a
        SENSF_REQ and returns this as the **tt3_cmd** attribute.

        Arguments:

          target (nfc.clf.LocalTarget): Supplies bitrate and mandatory
            response data to reply when being discovered.

          timeout (float): The maximum number of seconds to wait for a
            discovery command.

        Returns:

          nfc.clf.LocalTarget: Command data received from the remote
            Initiator if being discovered and to the extent supported
            by the device. The first command received after discovery
            is returned as **tt3_cmd** attribute.

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            or the *target* argument requested an unsupported bitrate
            (or has a wrong technology type identifier).

          ~exceptions.ValueError: A required target response attribute
            is not present or does not supply the number of bytes
            expected.

        """
        fname = "listen_ttf"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def listen_dep(self, target, timeout):
        """Listen as NFC-DEP Target.

        Waits to receive an ATR_REQ (if the local device supports
        active communication mode) or a Type A or F Target activation
        followed by an ATR_REQ in passive communication mode. The
        ATR_REQ is replied with **target.atr_res**. The first DEP_REQ
        command is returned as the **dep_req** attribute along with
        **atr_req** and **atr_res**. The **psl_req** and **psl_res**
        attributes are returned when the has Initiator performed a
        parameter selection. The **sens_res** or **sensf_res**
        attributes are returned when activation was in passive
        communication mode.

        Arguments:

          target (nfc.clf.LocalTarget): Supplies mandatory response
            data to reply when being discovered. All of **sens_res**,
            **sdd_res**, **sel_res**, **sensf_res**, and **atr_res**
            must be provided. The bitrate does not need to be set, an
            NFC-DEP Target always accepts discovery at '106A', '212F
            and '424F'.

          timeout (float): The maximum number of seconds to wait for a
            discovery command.

        Returns:

          nfc.clf.LocalTarget: Command data received from the remote
            Initiator if being discovered and to the extent supported
            by the device. The first command received after discovery
            is returned as **dep_req** attribute.

        Raises:

          nfc.clf.UnsupportedTargetError: The method is not supported
            by the local hardware.

          ~exceptions.ValueError: A required target response attribute
            is not present or does not supply the number of bytes
            expected.

        """
        fname = "listen_dep"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def send_cmd_recv_rsp(self, target, data, timeout):
        """Exchange data with a remote Target

        Sends command *data* to the remote *target* discovered in the
        most recent call to one of the sense_xxx() methods. Note that
        *target* becomes invalid with any call to mute(), sense_xxx()
        or listen_xxx()

        Arguments:

          target (nfc.clf.RemoteTarget): The target returned by the
            last successful call of a sense_xxx() method.

          data (bytearray): The binary data to send to the remote
            device.

          timeout (float): The maximum number of seconds to wait for
            response data from the remote device.

        Returns:

          bytearray: Response data received from the remote device.

        Raises:

          nfc.clf.CommunicationError: When no data was received.

        """
        fname = "send_cmd_recv_rsp"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def send_rsp_recv_cmd(self, target, data, timeout=None):
        """Exchange data with a remote Initiator

        Sends response *data* as the local *target* being discovered
        in the most recent call to one of the listen_xxx() methods.
        Note that *target* becomes invalid with any call to mute(),
        sense_xxx() or listen_xxx()

        Arguments:

          target (nfc.clf.LocalTarget): The target returned by the
            last successful call of a listen_xxx() method.

          data (bytearray): The binary data to send to the remote
            device.

          timeout (float): The maximum number of seconds to wait for
            command data from the remote device.

        Returns:

          bytearray: Command data received from the remote device.

        Raises:

          nfc.clf.CommunicationError: When no data was received.

        """
        fname = "send_rsp_recv_cmd"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def get_max_send_data_size(self, target):
        """Returns the maximum number of data bytes for sending.

        The maximum number of data bytes acceptable for sending with
        either :meth:`send_cmd_recv_rsp` or :meth:`send_rsp_recv_cmd`.
        The value reflects the local device capabilities for sending
        in the mode determined by *target*. It does not relate to any
        protocol capabilities and negotiations.

        Arguments:

          target (nfc.clf.Target): The current local or remote
            communication target.

        Returns:

          int: Maximum number of data bytes supported for sending.

        """
        fname = "get_max_send_data_size"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def get_max_recv_data_size(self, target):
        """Returns the maximum number of data bytes for receiving.

        The maximum number of data bytes acceptable for receiving with
        either :meth:`send_cmd_recv_rsp` or :meth:`send_rsp_recv_cmd`.
        The value reflects the local device capabilities for receiving
        in the mode determined by *target*. It does not relate to any
        protocol capabilities and negotiations.

        Arguments:

          target (nfc.clf.Target): The current local or remote
            communication target.

        Returns:

          int: Maximum number of data bytes supported for receiving.

        """
        fname = "get_max_recv_data_size"
        cname = self.__class__.__module__ + '.' + self.__class__.__name__
        raise NotImplementedError("%s.%s() is required" % (cname, fname))

    def turn_on_led_and_buzzer(self):
        """If a device has an LED and/or a buzzer, this method can be
        implemented to turn those indicators to the ON state.

        """
        pass

    def turn_off_led_and_buzzer(self):
        """If a device has an LED and/or a buzzer, this method can be
        implemented to turn those indicators to the OFF state.

        """
        pass

    @staticmethod
    def add_crc_a(data):
        # Calculate CRC-A for bytearray *data* and return *data*
        # extended with the two CRC bytes.
        crc = calculate_crc(data, len(data), 0x6363)
        return data + bytearray([crc & 0xff, crc >> 8])

    @staticmethod
    def check_crc_a(data):
        # Calculate CRC-A for the leading *len(data)-2* bytes of
        # bytearray *data* and return whether the result matches the
        # trailing 2 bytes of *data*.
        crc = calculate_crc(data, len(data)-2, 0x6363)
        return (data[-2], data[-1]) == (crc & 0xff, crc >> 8)

    @staticmethod
    def add_crc_b(data):
        # Calculate CRC-B for bytearray *data* and return *data*
        # extended with the two CRC bytes.
        crc = ~calculate_crc(data, len(data), 0xFFFF) & 0xFFFF
        return data + bytearray([crc & 0xff, crc >> 8])

    @staticmethod
    def check_crc_b(data):
        # Calculate CRC-B for the leading *len(data)-2* bytes of
        # bytearray *data* and return whether the result matches the
        # trailing 2 bytes of *data*.
        crc = ~calculate_crc(data, len(data)-2, 0xFFFF) & 0xFFFF
        return (data[-2], data[-1]) == (crc & 0xff, crc >> 8)


def calculate_crc(data, size, reg):
    for octet in data[:size]:
        for pos in range(8):
            bit = (reg ^ ((octet >> pos) & 1)) & 1
            reg = reg >> 1
            if bit:
                reg = reg ^ 0x8408
    return reg
