***************
Getting started
***************

Installation
============

.. _Bazaar: http://bazaar.canonical.com/en/

.. _Launchpad: https://launchpad.net/

.. _nfcpy trunk: https://code.launchpad.net/~stephen-tiedemann/nfcpy/trunk

**1. Get the code**

To get the latest development version: ::

  $ sudo apt-get install bzr
  $ cd <somedir>
  $ bzr branch lp:nfcpy trunk

This will download a branch of the `nfcpy trunk`_ repository from
Canonical's `Launchpad`_ source code hosting platform into the local
directory ``<somedir>/trunk``.

For Windows install, the easiest is to download the Bazaar standalone
installer from http://wiki.bazaar.canonical.com/WindowsDownloads and
choose the *Typical Installation* that includes the *Bazaar Explorer
GUI Application*. Start *Bazaar Explorer*, go to *Get project source
from elsewhere* and create a local **branch** of ``lp:nfcpy`` into
``C:/src/nfcpy`` or some other directory of choice.

A release version can be branched from the appropriate series, for
example the latest 0.9.x release. ::

  $ bzr branch lp:nfcpy/0.9

Tarballs of released versions are available for download at
https://launchpad.net/nfcpy.

**2. Install Python**

Python is usually installed on Linux, otherwise can be downloaded at
https://www.python.org/downloads/. Windows users may grab an installer
at https://www.python.org/downloads/windows/. Choose the latest 2.x
version, *nfcpy* is not yet ready for Python 3.

**3. Install libusb**

The final piece needed is the USB library *libusb* and Python
bindings. Once more this is dead easy for Linux where *libusb* is
already available and the only step required is: ::

  $ sudo apt-get install python-usb

To install libusb for Windows read the *Driver Installation* at
http://www.libusb.org/wiki/windows_backend and use *Zadig.exe* to
install *libusb-win32* for the contactless reader device (connect the
reader and cancel the standard Windows install dialog, the device will
be selectable in *Zadig*). The Python USB library can be downloaded as
a zip file from http://sourceforge.net/projects/pyusb/ and installed
with ``python.exe setup.py install`` from within the unzipped pyusb
source code directory (add the full path to *python.exe* if it's not
part of the search path).

**4. Run example**

A couple of example programs come with *nfcpy*. To see if the
installation succeeded and the reader is working head over to the
*nfcpy* directory and run the tagtool example: ::

  $ python examples/tagtool.py show

Touch a compatible tag (NFC Forum Type 1-4) and the NDEF data should
be printed. See :doc:`../examples/tagtool` for other options.

.. note:: Things may not immediately work with contactless USB readers
   on Linux. The first problem is that the readers are by default only
   accessible by the root user and will not be found when nfcpy is run
   from an unpriviledged user account. A second problem can be that a
   kernel driver of the Linux NFC subsystem has been activated for the
   device and this prevents nfcpy from accessing it. And the same
   problem exists if the pcscd daemon is installed.

   Since nfcpy version 0.10 the example programs are able to report
   the issues and hint the necessary actions. However, this will only
   be the case when program is called with a fully qualified --device
   argument. Thus a typical call sequence might be: ::

     $ examples/tagtool.py --device usb
     [main] no contactless reader found on usb
     [main] no contactless reader available
     $ lsusb
     Bus 003 Device 007: ID 054c:02e1 Sony Corp. FeliCa S330 [PaSoRi]
     $ examples/tagtool.py --device usb:054c:02e1
     [main] access denied for device with path usb:054c:02e1
     [main] first match for path usb:054c:02e1 is usb:003:014
     [main] usb:003:014 is owned by root but you are stephen
     [main] members of the root group may use usb:003:014
     [main] you may want to add a udev rule to access this device
     [main] sudo sh -c 'echo SUBSYSTEM==\"usb\", ACTION==\"add\", ATTRS{idVendor}==\"054c\", ATTRS{idProduct}==\"02e1\", GROUP=\"plugdev\" >> /etc/udev/rules.d/nfcdev.rules'

   The last line shown above provides a command line to copy into the
   terminal which will add a udev rule to allow members of the
   'plugdev' group to access the reader. The device must then be
   briefly unplugged to get the rule effective.


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
  >>> clf.connect(rdwr={'on-connect': connected}) # now touch a tag
  Type3Tag IDm=01010501b00ac30b PMm=03014b024f4993ff SYS=12fc
  <nfc.tag.tt3.Type3Tag object at 0x7f9e8302bfd0>

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

It is possible to let *nfcpy* emulate a tag (card). This is simply
requested with a **card** argument to |clf.connect|.

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> clf.connect(card={})
  None

Seems not so simple returned immediately with a None result. The
reason is just that there exists no sensible default behavior that
could be applied when working as a tag, there needs to be more
information about what kind of tag we want to emulate (apologies for
the bad coding style but this gives fewer lines to copy).

  >>> sensf_res = bytearray.fromhex('01 03FEFFE011223344 01E0000000FFFF00 12FC')
  >>> def on_startup(target):
  ...     target.brty = "212F"; target.sensf_res = sensf_res; return target
  ...
  >>> clf.connect(card={'on-startup': on_startup}) # touch a reader
  True

.. note:: A :class:`~nfc.tag.TagEmulation` class still only exists for
          Type 3 Tags although since version 0.10 it is possible to
          run *nfcpy* in target mode for Type 2 and Type 4A Tgas with
          selected devces. It is also now possible to use PN532, PN533
          and RC-S956 basesd devices in addition to RC-S380 for Type 3
          Tag emulation, but except for RC-S380 the command and
          response frames can only be up to 64 byte.
   
A nice tool to read the tag we've just created is the excellent `NXP
Tag Info`_ app available in the Android app store. It should report
that our tag is a *FeliCa Plug RC-S926* (because sensf_res[9:11] is
``01E0``) and show the 8 byte *IDm*, 8 byte *PMm* and 2 byte *System
Code* in the TECH view. The `NXP Tag Info`_ app should also report
that there is no NDEF partition on the tag, so this is gonna be fixed
next.

  >>> attr = nfc.tag.tt3.NdefAttributeData()
  >>> attr.version, attr.nbr, attr.nbw = '1.0', 12, 8
  >>> attr.capacity, attr.writeable = 1024, True
  >>> ndef_data_area = str(attr) + bytearray(attr.capacity)

  >>> def ndef_read(block_number, rb, re):
  ...     if block_number < len(ndef_data_area) / 16:
  ...         first, last = block_number*16, (block_number+1)*16
  ...         block_data = ndef_data_area[first:last]
  ...         return block_data
  ...
  >>> def ndef_write(block_number, block_data, wb, we):
  ...     global ndef_data_area
  ...     if block_number < len(ndef_data_area) / 16:
  ...         first, last = block_number*16, (block_number+1)*16
  ...         ndef_data_area[first:last] = block_data
  ...         return True
  ...
  >>> def on_connect(tag):
  ...     tag.add_service(0x0009, ndef_read, ndef_write)
  ...     tag.add_service(0x000B, ndef_read, lambda: False)
  ...     return True
  ...
  >>> card_options = {'on_startup': on_startup, 'on-connect': on_connect}
  >>> while clf.connect(card=card_options): pass

This is now a fully functional NFC Forum Type 3 Tag. With something
like the `NXP Tag Writer`_, NDEF data can now be stored into the
**ndef_data_area** and read back. The loop can be terminated with a
keyboard interrupt *Ctrl-C*.

   >>> clf.close()

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
