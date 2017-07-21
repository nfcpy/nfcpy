.. -*- mode: rst; fill-column: 80 -*-

***************
Getting started
***************

Installation
============

.. _pip: https://pip.pypa.io/en/stable/
.. _libusb: http://libusb.info/
.. _WinUSB: https://msdn.microsoft.com/en-us/library/ff540196.aspx
.. _Zadig: http://zadig.akeo.ie/
.. _ndeflib: http://ndeflib.readthedocs.io/en/stable/

**Install libusb**

The `libusb`_ library provides generic access to USB devices. Linux
distributions usually have this installed, otherwise it should be
available through the standard package manager (beware not to choose
the old version 0.x).

Windows users will have a little work to (i) install the Microsoft
`WinUSB`_ driver and (ii) place a copy of the libusb library into the
system folder. Microsoft provides Instructions to install `WinUSB`_
but a much simpler approach is to use the `Zadig`_ Windows application
(download and run zadig, select your device and choose the WinUSB
driver to install). The libusb library for Windows can be downloaded
from `libusb`_ (Downloads -> Latest Windows Binaries) as a 7z
archive. Just unpack and copy ``MS64\dll\libusb-1.0.dll`` to
``C:\Windows\System32`` and ``MS32\dll\libusb-1.0.dll`` to the
``C:\Windows\SysWOW64`` directory.

**Install Python and nfcpy**

Python is usually installed on Linux, otherwise can be downloaded at
https://www.python.org/downloads/. Windows users may grab an installer
at https://www.python.org/downloads/windows/. Choose the latest 2.x
version, *nfcpy* is not yet ready for Python 3.

With Python installed use `pip`_ to install the latest stable version
of nfcpy. This will also install the required libusb1 and pyserial
modules.

.. code-block:: shell

   $ pip install -U nfcpy

Windows users may have to use ``C:\Python27\Scripts\pip.exe``.

**Verify installation**

Check if all is correctly installed and *nfcpy* finds your contactless
reader (Windows users may have to use``C:\Python27\python.exe``).

.. code-block:: shell

   $ python -m nfc

If all goes well the output should tell that your your reader was
found, below is an example of how it may look with an SCL3711:

.. code-block:: none

   This is the latest version of nfcpy run in Python 2.7.12
   on Linux-4.4.0-47-generic-x86_64-with-Ubuntu-16.04-xenial
   I'm now searching your system for contactless devices
   ** found SCM Micro SCL3711-NFC&RW PN533v2.7 at usb:002:024
   I'm not trying serial devices because you haven't told me
   -- add the option '--search-tty' to have me looking
   -- but beware that this may break existing connections

Common problems on Linux (access rights or other drivers claiming the
device) should be reported with a possible solution:

.. code-block:: none

   This is the latest version of nfcpy run in Python 2.7.12
   on Linux-4.4.0-47-generic-x86_64-with-Ubuntu-16.04-xenial
   I'm now searching your system for contactless devices
   ** found usb:04e6:5591 at usb:002:025 but access is denied
   -- the device is owned by 'root' but you are 'stephen'
   -- also members of the 'root' group would be permitted
   -- you could use 'sudo' but this is not recommended
   -- it's better to add the device to the 'plugdev' group
      sudo sh -c 'echo SUBSYSTEM==\"usb\", ACTION==\"add\", ATTRS{idVendor}==\"04e6\", ATTRS{idProduct}==\"5591\", GROUP=\"plugdev\" >> /etc/udev/rules.d/nfcdev.rules'
      sudo udevadm control -R # then re-attach device
   I'm not trying serial devices because you haven't told me
   -- add the option '--search-tty' to have me looking
   -- but beware that this may break other serial devs
   Sorry, but I couldn't find any contactless device


Open a local device
===================

Any data exchange with a remote NFC device needs a contactless frontend attached
and opened for communication. Most commercial devices (also called NFC Reader)
are physically attached through USB and either provide a native USB interface or
a virtual serial port.

The :class:`nfc.ContactlessFrontend` manages all communication with a local
device. The :class:`~nfc.clf.ContactlessFrontend.open` method tries to find and
open a device and returns True for success. The string argument determines the
device with a sequence of components separated by colon. The first component
determines where the device is attached (usb, tty, or udp) and what the further
components may be. This is best explained by example.

Suppose a FeliCa S330 Reader is attached to a Linux computer on USB bus number 3
and got device number 9 (note that device numbers always increment when a device
is connected):

.. code-block:: shell

   $ lsusb
   ...
   Bus 003 Device 009: ID 054c:02e1 Sony Corp. FeliCa S330 [PaSoRi]
   ...

.. testsetup:: clf-usb

   nfc_ContactlessFrontend_open = nfc.ContactlessFrontend.open
   nfc.ContactlessFrontend.open = mock.Mock('nfc.ContactlessFrontend.open')
   nfc.ContactlessFrontend.open.return_value = True

.. doctest:: clf-usb

   >>> import nfc
   >>> clf = nfc.ContactlessFrontend()
   >>> assert clf.open('usb:003:009') is True    # open device 9 on bus 3
   >>> assert clf.open('usb:054c:02e1') is True  # open first PaSoRi 330
   >>> assert clf.open('usb:003') is True        # open first Reader on bus 3
   >>> assert clf.open('usb:054c') is True       # open first Sony Reader
   >>> assert clf.open('usb') is True            # open first USB Reader
   >>> clf.close()  # previous open calls implicitly closed the device

.. testcleanup:: clf-usb

   nfc.ContactlessFrontend.open = nfc_ContactlessFrontend_open

Some devices, especially for embedded projects, have a UART interface that may
be connected either directly or through a USB UART adapter. Below is an example
of a Raspberry Pi 3 which has two UART ports (ttyAMA0, ttyS0) and one reader is
connected with a USB UART adapter (ttyUSB0). On a Raspberry Pi 3 the UART linked
from /dev/serial1 is available on the GPIO header (the other one is used for
Bluetooth connectivity). On a Raspberry Pi 2 it is always ttyAMA0.

.. code-block:: shell

   pi@raspberrypi ~ $ ls -l /dev/tty[ASU]* /dev/serial?
   lrwxrwxrwx 1 root root          5 Dez 21 18:11 /dev/serial0 -> ttyS0
   lrwxrwxrwx 1 root root          7 Dez 21 18:11 /dev/serial1 -> ttyAMA0
   crw-rw---- 1 root dialout 204, 64 Dez 21 18:11 /dev/ttyAMA0
   crw-rw---- 1 root dialout   4, 64 Dez 21 18:11 /dev/ttyS0
   crw-rw---- 1 root dialout 188,  0 Feb 24 12:17 /dev/ttyUSB0

.. testsetup:: clf-tty

   nfc_ContactlessFrontend_open = nfc.ContactlessFrontend.open
   nfc.ContactlessFrontend.open = mock.Mock('nfc.ContactlessFrontend.open')
   nfc.ContactlessFrontend.open.return_value = True

.. doctest:: clf-tty

   >>> import nfc
   >>> clf = nfc.ContactlessFrontend()
   >>> assert clf.open('tty:USB0:arygon') is True  # open /dev/ttyUSB0 with arygon driver
   >>> assert clf.open('tty:USB0:pn532') is True   # open /dev/ttyUSB0 with pn532 driver
   >>> assert clf.open('tty:AMA0') is True         # try different drivers on /dev/ttyAMA0
   >>> assert clf.open('tty') is True              # try all serial ports and drivers
   >>> clf.close()  # previous open calls implicitly closed the device

.. testcleanup:: clf-tty

   nfc.ContactlessFrontend.open = nfc_ContactlessFrontend_open


A special kind of device bus that does not require any physical hardware is
provided for testing and application prototyping. It works by sending NFC
communication frames across a UDP/IP connection and can be used to connect two
processes running an *nfcpy* application either locally or remote.

In the following example the device path is supplied as an init argument. This
would raise an :exc:`exceptions.IOError` with :data:`errno.ENODEV` if it fails
to open. The example also demonstrates the use of a :keyword:`with` statement
for automatic close when leaving the context.

.. doctest:: clf-udp
      
   >>> import nfc
   >>> with nfc.ContactlessFrontend('udp') as clf:
   ...     print(clf)
   ... 
   Linux IP-Stack on udp:localhost:54321


Read and write tags
===================

.. |clf.sense| replace:: :meth:`clf.sense() <nfc.clf.ContactlessFrontend.sense>`
.. |clf.connect| replace:: :meth:`clf.connect() <nfc.clf.ContactlessFrontend.connect>`
.. |tag.ndef| replace:: :attr:`tag.ndef <nfc.tag.Tag.ndef>`
.. |tag.ndef.octets| replace:: :attr:`tag.ndef.octets <nfc.tag.Tag.NDEF.octets>`
.. |tag.ndef.records| replace:: :attr:`tag.ndef.records <nfc.tag.Tag.NDEF.records>`
.. |tag.ndef.has_changed| replace:: :attr:`tag.ndef.has_changed <nfc.tag.Tag.NDEF.has_changed>`

NFC Tag Devices are tiny electronics devices with a comparatively large (some
square centimeters) antenna that serves as both an inductive power receiver and
for communication. The energy is provided by the NFC Reader Device for as long
as it wishes to communicate with the Tag.

Most Tags are embedded in plastics or paper and can store data in persistent
memory. NFC Tags as defined by the NFC Forum have standardized memory format and
command set to store NFC Data Exchange Format (NDEF) records. Most commercial
NFC Tags also provide vendor-specific commands for special applications, some of
those can be used with *nfcpy*. A rather new class of NFC Interface Tags is
targeted towards providing NFC communication for embedded devices where the
information exchange is through NFC with the microcontroller of the embedded
device.

.. tip::

   It is quite easy to make an NFC field detector. Just a few turns of copper
   wire around three fingers and the ends soldered to an LED will do the job.
   Here's a `video <https://www.youtube.com/watch?v=dTv4U5fotM0>`_.

NFC Tags are simple slave devices that wait unconditionally for any reader
command to respond. This makes it easy to interact with them from within a
Python interpreter session using the local contactless frontend.

.. testsetup:: tags-open-clf

   nfc_ContactlessFrontend_open = nfc.ContactlessFrontend.open
   nfc.ContactlessFrontend.open = mock.Mock('nfc.ContactlessFrontend.open')
   nfc.ContactlessFrontend.open.return_value = True

.. doctest:: tags-open-clf

   >>> import nfc
   >>> clf = nfc.ContactlessFrontend('usb')

.. testcleanup:: tags-open-clf

   nfc.ContactlessFrontend.open = nfc_ContactlessFrontend_open

The |clf.sense| method can now be used to search for a proximity target with
arguments set for the desired communication technologies. The example shows the
result of a Type F card response for which the :meth:`nfc.tag.activate` function
then returns a :class:`~nfc.tag.tt3.Type3Tag` instance.

.. testsetup:: memory-tag

   HEX = lambda s: bytearray.fromhex(s)
   clf = nfc.ContactlessFrontend('udp')
   clf.sense = mock.Mock('nfc.ContactlessFrontend.sense')
   sensf_res = bytearray.fromhex('0101010701260CCA020F0D23042F7783FF12FC')
   clf.sense.return_value = nfc.clf.RemoteTarget('212F', sensf_res=sensf_res)
   clf.exchange = mock.Mock('nfc.ContactlessFrontend.exchange')
   clf.exchange.side_effect = [
       HEX('1d 07 01010701260CCA02 0000 01 100b0a01 89000000 00000100 000e00be'),
       HEX('1d 07 01010701260CCA02 0000 01 d1010a55 036e6663 70792e6f 72670000'),
       HEX('1d 07 01010701260CCA02 0000 01 100b0a01 89000000 00000100 000e00be'),
       HEX('0c 09 01010701260CCA02 0000'),
       HEX('0c 09 01010701260CCA02 0000'),
       HEX('0c 09 01010701260CCA02 0000'),
       HEX('1d 07 01010701260CCA02 0000 01 100b0a01 89000000 00000100 002700d7'),
       HEX('3d 07 01010701260CCA02 0000 03 d1022253 7091010a 55036e66 6370792e'
                                          '6f726751 01105402 656e6e66 63707920'
                                          '70726f6a 65637400 00000000 00000000')
   ]

.. doctest:: memory-tag

   >>> from nfc.clf import RemoteTarget
   >>> target = clf.sense(RemoteTarget('106A'), RemoteTarget('106B'), RemoteTarget('212F'))
   >>> print(target)
   212F sensf_res=0101010701260CCA020F0D23042F7783FF12FC
   >>> tag = nfc.tag.activate(clf, target)
   >>> print(tag)
   Type3Tag 'FeliCa Standard (RC-S960)' ID=01010701260CCA02 PMM=0F0D23042F7783FF SYS=12FC

The same :class:`~nfc.tag.tt3.Type3Tag` instance can also be acquired with the
|clf.connect| method. This is the generally preferred way to discover and
activate contactless targets of any supported type. When configured with the
*rdwr* dictionary argument the |clf.connect| method will use Reader/Writer mode
to discover NFC Tags. When a Tag is found and activated, the ``on-connect``
callback function returning :const:`False` means that the tag presence loop
shall not be run but the :class:`nfc.tag.Tag` object returned immediately. A
more useful callback function could do something with the *tag* and return
:const:`True` for requesting a presence loop that makes |clf.connect| return
only after the tag is gone.

.. doctest:: memory-tag

   >>> tag = clf.connect(rdwr={'on-connect': lambda tag: False})
   >>> print(tag)
   Type3Tag 'FeliCa Standard (RC-S960)' ID=01010701260CCA02 PMM=0F0D23042F7783FF SYS=12FC

An NFC Forum Tag can store NFC Data Exchange Format (NDEF) Records in a
specifically formatted memory region. NDEF data is found automatically and
wrapped into an :class:`~nfc.tag.Tag.NDEF` object accessible through the
|tag.ndef| attribute. When NDEF data is not present the attribute is simply
:const:`None`.

.. doctest:: memory-tag

   >>> assert tag.ndef is not None
   >>> for record in tag.ndef.records:
   ...     print(record)
   ... 
   NDEF Uri Record ID '' Resource 'http://nfcpy.org'

The |tag.ndef.records| attribute contains a list of NDEF Records decoded from
|tag.ndef.octets| with the `ndeflib`_ package. Each record has common and
type-specific methods and attributes for content access.

.. doctest:: memory-tag

   >>> record = tag.ndef.records[0]
   >>> print(record.type)
   urn:nfc:wkt:U
   >>> print(record.uri)
   http://nfcpy.org

A list of NDEF Records assigned to |tag.ndef.records| gets encoded and then
written to the Tag (internally the bytes are assigned to |tag.ndef.octets| to
trigger the update).

.. doctest:: memory-tag

   >>> import ndef
   >>> uri, title = 'http://nfcpy.org', 'nfcpy project'
   >>> tag.ndef.records = [ndef.SmartposterRecord(uri, title)]

When NDEF data bytes are written to a Memory Tag then the |tag.ndef| object
matches the stored data. In case of an Interface Tag this may not be true
because the write commands may be handled differently by the device. The only
way to find out is read back the data and compare. This is the logic behind
|tag.ndef.has_changed|, which should be :const:`False` for a Memory Tag.

.. doctest:: memory-tag

   >>> assert tag.ndef.has_changed is False

An NFC Interface Tag may be used to realize a device that presents dynamically
changing NDEF data depending on internal state, for example a sensor device
returning the current temperature.

.. testsetup:: interface-tag

   HEX = lambda s: bytearray.fromhex(s)
   clf = nfc.ContactlessFrontend('udp')
   clf.sense = mock.Mock('nfc.ContactlessFrontend.sense')
   sensf_res = bytearray.fromhex('0103FEFFFFFFFFFFFF00E1000000FFFF0012FC')
   clf.sense.return_value = nfc.clf.RemoteTarget('212F', sensf_res=sensf_res)
   clf.exchange = mock.Mock('nfc.ContactlessFrontend.exchange')
   clf.exchange.side_effect = [
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 100c0c00 04000000 00000000 000e003a'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 d1010a54 02656e2b 32312e33 20430000'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 100c0c00 04000000 00000000 000e003a'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 d1010a54 02656e2b 32312e30 20430000'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 100c0c00 04000000 00000000 000e003a'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 d1010a54 02656e2b 32302e35 20430000'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 100c0c00 04000000 00000000 000e003a'),
       HEX('1d 07 03FEFFFFFFFFFFFF 0000 01 d1010a54 02656e2b 32302e31 20430000'),
   ]
   import time
   time.sleep = mock.Mock('time.sleep')

.. doctest:: interface-tag

   >>> tag = clf.connect(rdwr={'on-connect': lambda tag: False})
   >>> print(tag)
   Type3Tag 'FeliCa Link (RC-S730) Plug Mode' ID=03FEFFFFFFFFFFFF PMM=00E1000000FFFF00 SYS=12FC
   >>> assert tag.ndef is not None and tag.ndef.length > 0
   >>> assert tag.ndef.records[0].type == 'urn:nfc:wkt:T'
   >>> print('Temperature 0: {}'.format(tag.ndef.records[0].text))
   Temperature 0: +21.3 C
   >>> for count in range(1, 4):
   ...     while not tag.ndef.has_changed: time.sleep(1)
   ...     print('Temperature {}: {}'.format(count, tag.ndef.records[0].text))
   ... 
   Temperature 1: +21.0 C
   Temperature 2: +20.5 C
   Temperature 3: +20.1 C

Finally the contactless frontend should be closed.

.. testsetup:: tags-close-clf

   clf = nfc.ContactlessFrontend('udp')

.. doctest:: tags-close-clf

   >>> clf.close()

Documentation of all available Tag classes as well as NDEF class methods and
attributes can be found in the :mod:`nfc.tag` module reference. For NDEF Record
class types, methods and attributes consult the `ndeflib`_ documentation.


Emulate a card
==============

It is possible to emulate a card (NFC Tag) with *nfcpy* but unfortunately this
only works with some NFC devices and is limited to Type 3 Tag emulation. The
RC-S380 fully supports Type 3 Tag emulation. Devices based on PN532, PN533, or
RC-S956 chipset can also be used but an internal frame size limit of 64 byte
only allows read/write operations with up to 3 data blocks.

Below is an example of an NDEF formatted Type 3 Tag. The first 16 byte (first
data block) contain the attribute data by which the reader will learn the NDEF
version, the number of data blocks that can be read or written in a single
command, the total capacity and the write permission state. Bytes 11 to 13
contain the current NDEF message length, initialized to zero. The example is
made to specifically open only an RC-S380 contactless frontend (otherwise the
number of blocks that may be read or written should not be more than 3).

.. code-block:: python

   import nfc
   import struct

   ndef_data_area = bytearray(64 * 16)
   ndef_data_area[0] = 0x10  # NDEF mapping version '1.0'
   ndef_data_area[1] = 12    # Number of blocks that may be read at once
   ndef_data_area[2] = 8     # Number of blocks that may be written at once
   ndef_data_area[4] = 63    # Number of blocks available for NDEF data
   ndef_data_area[10] = 1    # NDEF read and write operations are allowed
   ndef_data_area[14:16] = struct.pack('>H', sum(ndef_data_area[0:14]))  # Checksum

   def ndef_read(block_number, rb, re):
       if block_number < len(ndef_data_area) / 16:
           first, last = block_number*16, (block_number+1)*16
           block_data = ndef_data_area[first:last]
           return block_data

   def ndef_write(block_number, block_data, wb, we):
       global ndef_data_area
       if block_number < len(ndef_data_area) / 16:
           first, last = block_number*16, (block_number+1)*16
           ndef_data_area[first:last] = block_data
           return True

   def on_startup(target):
       idm, pmm, sys = '03FEFFE011223344', '01E0000000FFFF00', '12FC'
       target.sensf_res = bytearray.fromhex('01' + idm + pmm + sys)
       target.brty = "212F"
       return target

   def on_connect(tag):
       print("tag activated")
       tag.add_service(0x0009, ndef_read, ndef_write)
       tag.add_service(0x000B, ndef_read, lambda: False)
       return True

   with nfc.ContactlessFrontend('usb:054c:06c1') as clf:
       while clf.connect(card={'on-startup': on_startup, 'on-connect': on_connect}):
           print("tag released")


This is a fully functional NFC Forum Type 3 Tag. With a separate reader or
Android apps such as `NXP Tag Info`_ and `NXP Tag Writer`_, NDEF data can now be
written into the **ndef_data_area** and read back until the loop is terminated
with :kbd:`Control-C`.

.. _NXP Tag Info:
   https://play.google.com/store/apps/details?id=com.nxp.taginfolite

.. _NXP Tag Writer:
   https://play.google.com/store/apps/details?id=com.nxp.nfc.tagwriter


Work with a peer
================

The best part of NFC comes when the limitations of a single master
controlling a humble servant are overcome. This is achieved by the NFC
Forum Logical Link Control Protocol (LLCP), which allows multiplexed
communications between two NFC Forum Devices with either peer able to
send protocol data units at any time and no restriction to a single
application run in one direction.

An LLCP link between two NFC devices is requested with the **llcp**
argument to |clf.connect|.

.. doctest::
   :options: +SKIP

   >>> import nfc
   >>> clf = ContactlessFrontend('usb')
   >>> clf.connect(llcp={}) # now touch a phone
   True

When the first example got LLCP running there is actually just
symmetry packets exchanged back and forth until the link is
broken. We have to use callback functions to add some useful stuff.

.. doctest::
   :options: +SKIP

   >>> def on_connect(llc):
   ...     print llc; return True
   ... 
   >>> clf.connect(llcp={'on-connect': connected})
   LLC: Local(MIU=128, LTO=100ms) Remote(MIU=1024, LTO=500ms)
   True

The on_connect function receives a single argument **llc**, which is
the :class:`~nfc.llcp.llc.LogicalLinkController` instance coordinates
aal data exchange with the remote peer. With this we can add client
applications but they must be run in a separate execution context to
have on_connect return fast. Only after on_connect returns, the
**llc** can start running the symmetry loop (the LLCP heartbeat) with
the remote peer and generally receive and dispatch protocol and
service data units.

When using the interactive interpreter it is less convinient to
program in the callback functions so we will start a thread in the
callback to execute the *llc.run** loop and return with False. This
tells |clf.connect| to return immediately with the **llc** instance).

.. doctest::
   :options: +SKIP

   >>> import threading
   >>> def on_connect(llc):
   ...     threading.Thread(target=llc.run).start(); return False
   ... 
   >>> llc = clf.connect(llcp={'on-connect': on_connect})
   >>> print llc
   LLC: Local(MIU=128, LTO=100ms) Remote(MIU=1024, LTO=500ms)

Application code is not supposed to work directly with the **llc**
object but use it to create :class:`~nfc.llcp.Socket` objects for the
actual communication. Two types of regular sockets can be created with
either :const:`nfc.llcp.LOGICAL_DATA_LINK` for a connection-less
socket or :const:`nfc.llcp.DATA_LINK_CONNECTION` for a connection-mode
socket. A connection-less socket does not guarantee that application
data is delivered to the remote application (although *nfcpy* makes
sure that it's been delivered to the remote device). A connection-mode
socket cares about reliability, unless the other implementation is
buggy data you send is guaranteed to make it to the receiving
application - error-free and in order.

What can be done with an Android phone as the peer device is for
example to send to its default SNEP Server. SNEP is the NFC Forum
Simple NDEF Exchange Protocol and a default SNEP Server is built into
Android under the name of Android Beam. SNEP messages are exchanged
over an LLCP data link connection so we create a connection mode
socket, connect to the server with the service name known from the
`NFC Forum Assigned Numbers Register`_ and then send a SNEP PUT
request with a web link to open.

.. doctest::
   :options: +SKIP

   >>> import ndef
   >>> socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
   >>> socket.connect('urn:nfc:sn:snep')
   >>> records = [ndef.UriRecord("http://nfcpy.org")]
   >>> message = b''.join(ndef.message_encoder(records))
   >>> socket.send("\x10\x02\x00\x00\x00" + chr(len(message)) + message)
   >>> socket.recv()
   '\x10\x81\x00\x00\x00\x00'
   >>> socket.close()

The phone should now have opened the http://nfcpy.org web page.

The code can be simplified by using the :class:`~nfc.snep.SnepClient`
from the :mod:`nfc.snep` package.

.. doctest::
   :options: +SKIP

   >>> import nfc.snep
   >>> snep = nfc.snep.SnepClient(llc)
   >>> snep.put_records([ndef.UriRecord("http://nfcpy.org")])
   True

The :meth:`~nfc.snep.SnepClient.put` method is smart enough to
temporarily connect to ``urn:nfc.sn:snep`` for sending. There are also
methods to open and close the connection explicitely and maybe use a
different service name.

.. note:: The :ref:`llcp-tutorial` tutorial has more information on
          LLCP in general and how its used with *nfcpy*. The
          :mod:`nfc.llcp` package documentation contains describes all
          the API classes and methods that are available.

.. _NFC Forum Assigned Numbers Register:
   http://members.nfc-forum.org/specs/nfc_forum_assigned_numbers_register
