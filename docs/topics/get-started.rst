***************
Getting started
***************

Installation
============

.. _Bazaar: http://bazaar.canonical.com/en/
.. _Launchpad: https://launchpad.net/
.. _nfcpy trunk: https://code.launchpad.net/~stephen-tiedemann/nfcpy/trunk
.. _pip: https://pip.pypa.io/en/stable/
.. _libusb: http://libusb.info/
.. _WinUSB: https://msdn.microsoft.com/en-us/library/ff540196.aspx
.. _Zadig: http://zadig.akeo.ie/

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
modules.::

  $ pip install -U nfcpy

Windows users may have to use ``C:\Python27\Scripts\pip.exe``.

**Verify installation**

Check if all is correctly installed and *nfcpy* finds your contactless
reader (Windows users may have to use``C:\Python27\python.exe``). ::

  $ python -m nfc

If all goes well the output should tell that your your reader was
found, below is an example of how it may look with an SCL3711:::

  This is the latest version of nfcpy run in Python 2.7.12
  on Linux-4.4.0-47-generic-x86_64-with-Ubuntu-16.04-xenial
  I'm now searching your system for contactless devices
  ** found SCM Micro SCL3711-NFC&RW PN533v2.7 at usb:002:024
  I'm not trying serial devices because you haven't told me
  -- add the option '--search-tty' to have me looking
  -- but beware that this may break existing connections

Common problems on Linux (access rights or other drivers claiming the
device) should be reported with a possible solution::

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


Open a reader
=============

.. |clf.connect| replace:: :meth:`clf.connect()
                           <nfc.clf.ContactlessFrontend.connect>`


The main interface to start programming with *nfcpy* is provided by
:class:`nfc.ContactlessFrontend`. When initialized with a *path*
argument it tries to locate and open a contacless reader connected at
that location, which may be for example the first available reader on
USB. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> print(clf)
  Sony RC-S360/SH on usb:002:005

For more control of where a reader may befound specifiy further
details of the path string, for example **usb:002:005** to open the
same reader as above, or **usb:002** to open the first available
reader on USB bus number 2 (same numbers as shown by **lsusb**). The
other way to specify a USB reader is by vendor and product ID, like
**usb:054c:02e1** will open the same reader as before if there's only
one of them plugged in. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb:054c')
  >>> print(clf)
  Sony RC-S360/SH on usb:002:005

If you don't have an NFC reader at hand or just want to test your
application logic a driver that carries NFC frames across a UDP/IP
link might come handy. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('udp')
  >>> print(clf)
  Linux IP-Stack on udp:localhost:54321

Just for completeness, you can also omit the path argument and later
open a reader using |clf.connect|. This returns just False when no
reader was found instead of raising an exception.


Read and write tags
===================

With a reader opened the next step to get an NFC communication running
is to use the |clf.connect| method. We'll start with connecting to a
tag (a contactless card), which should not be a Mifare Classic.
Supported are NFC Forum Type 1, 2, 3 and 4 Tags.

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> clf.connect(rdwr={}) # now touch a tag and remove it
  True

With the call to |clf.connect| the tag got discovered, activated and
it's NDEF data read and then, for as long as it has not been moved
away, the tag presence was continously verified. The return value
tells that there was an activation and termination was as expected and
not for any exceptional case like a Ctrl-C keyboard interrupt.

The **rdwr** argument is a dictionary that may carry further options
to control |clf.connect|. From a set of callback functions we may
choose ``on-connect`` to be alerted when the tag is activated.

  >>> def connected(tag): print(tag); return False
  ...
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> tag = clf.connect(rdwr={'on-connect': connected}) # now touch a tag
  Type3Tag IDm=01010501b00ac30b PMm=03014b024f4993ff SYS=12fc

This simple callback function print some basic information about the
tag, here it is an NFC Forum Type 3 Tag with system code 12FCh. This
time the |clf.connect| call returned immediately after the touch with
an :class:`nfc.tag.tt3.Type3Tag` object. This is because the callback
did return False to request that the presence loop not be run. With
the tag object returned we can check if there is an NDEF Message
stored on the tag.

  >>> print(tag.ndef.message.pretty() if tag.ndef else "Sorry, no NDEF")
  record 1
    type   = 'urn:nfc:wkt:Sp'
    name   = ''
    data   = '\xd1\x01\nU\x03nfcpy.org'

The logic is simple. If the **tag.ndef** attribute not None then the
**tag.ndef.message** attribute will be a :class:`nfc.ndef.Message`
object we can easily print with :meth:`~nfc.ndef.Message.pretty`. This
prints the list of records in the message, which happens to be just
one.

  >>> record_1 = tag.ndef.message[0]
  >>> print(record_1.pretty())
  type = 'urn:nfc:wkt:Sp'
  name = ''
  data = '\xd1\x01\nU\x03nfcpy.org'

The type attribute tells that this :class:`nfc.ndef.Record` is an NFC
Forum Well-Known Smartposter type record. The **nfc.ndef** package has
a record class for this.

  >>> import nfc.ndef
  >>> smartposter = nfc.ndef.SmartPosterRecord(record_1)
  >>> print(smartposter.pretty())
  resource = http://nfcpy.org
  action   = default

So far we have only read from the tag, now it's time to write. For an
NDEF message this is pretty easy and shown by adding a smartposter
title.

  >>> smartposter.title = "Python module for near field communication"
  >>> tag.ndef.message = nfc.ndef.Message(sp)
  >>> print(nfc.ndef.SmartPosterRecord(tag.ndef.message[0]).pretty())
  resource  = http://nfcpy.org
  title[en] = Python module for near field communication
  action    = default
  
The new message was immediately written to the tag with the assignment
to **tag.ndef.message**. The next line then caused the NDEF message to
be read back from the tag and converts it into a SmartPoster object
for pretty print.

   >>> clf.close()
   
.. note:: The :mod:`nfc.ndef` package has a lot more than could be
   covered in this short introduction, feel free to read the API
   documentation as well as the :ref:`ndef-tutorial` tutorial to learn
   how *nfcpy* maps the concepts of the NDEF specification. And the
   :mod:`nfc.tag` package provides more information on the methods
   that are available for formatting, protecting, authenticating and
   exchanging raw commands with tags.


Emulate a card
==============

It is possible to emulate a card (NFC Tag) with *nfcpy* but
unfortunately it only works with some NFC devices and is limited to
Type 3 Tag emulation. The RC-S380 fully supports Type 3 Tag
emulation. Devices based on PN532, PN533, or RC-S956 chipset can also
be used but an internal frame size limit of 64 byte only allows
read/write operations with up to 3 data blocks.

Below is an example of an NDEF formatted Type 3 Tag. The first 16 byte
(first data block) contain the attribute data by which the reader will
learn the NDEF version, the number of data blocks that can be read or
written in a single command, the total capacity and the write
permission state. Bytes 11 to 13 contain the current NDEF message
length, initialized to zero. The example is made to specifically open
only an RC-S380 contactless frontend (otherwise the number of blocks
that may be read or written should not be more than 3).

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


This is a fully functional NFC Forum Type 3 Tag. With a separate
reader or Android apps such as `NXP Tag Info`_ and `NXP Tag Writer`_,
NDEF data can now be written into the **ndef_data_area** and read back
until the loop is terminated with the *Ctrl-C* keyboard interrupt.

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

  >>> import nfc
  >>> clf = ContactlessFrontend('usb')
  >>> clf.connect(llcp={}) # now touch a phone
  True

When the first example got LLCP running there is actually just
symmetry packets exchanged back and forth until the link is
broken. We have to use callback functions to add some useful stuff.

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

  >>> socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
  >>> socket.connect('urn:nfc:sn:snep')
  >>> msg = nfc.ndef.Message(nfc.ndef.UriRecord("http://nfcpy.org"))
  >>> socket.send("\x10\x02\x00\x00\x00" + chr(len(str(msg))) + str(msg))
  >>> socket.recv()
  '\x10\x81\x00\x00\x00\x00'
  >>> socket.close()

The phone should now have opened the http://nfcpy.org web page.

The code can be simplified by using the :class:`~nfc.snep.SnepClient`
from the :mod:`nfc.snep` package.

  >>> import nfc.snep
  >>> snep = nfc.snep.SnepClient(llc)
  >>> snep.put(nfc.ndef.Message(nfc.ndef.UriRecord("http://nfcpy.org")))
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
