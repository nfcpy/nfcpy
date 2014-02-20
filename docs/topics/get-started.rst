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
  $ bzr branch lp:nfcpy

This will download a branch of the `nfcpy trunk`_ repository from
Canonical's `Launchpad`_ source code hosting platform into the local
directory ``<somedir>/trunk``.

For a Windows install the easiest is to download the Bazaar standalone
installer from http://wiki.bazaar.canonical.com/WindowsDownloads and
choose the *Typical Installation* that includes the *Bazaar Explorer
GUI Application*. Start *Bazaar Explorer*, go to *Get project source
from elsewhere* and create a local **branch** of ``lp:nfcpy`` into
``C:/src/nfcpy`` or some other directory of choice.

A release versions can be branched from the appropriate series, for
example to grab the latest 0.0.x release.::

  $ bzr branch lp:nfcpy/0.9

Tarballs of released versions are available for download at
https://launchpad.net/nfcpy.

**2. Install Python**

Python is already installed on every Desktop Linux. Windows installers
can be found at http://www.python.org/download/windows/. Make sure to
choose a 2.x version, usually the latest, as *nfcpy* is not yet ported
to Python 3.

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

.. note:: Things may not immediately work on Linux for two reasons:
   The reader might be claimed by the Linux NFC subsystem available
   since Linux 3.1 and root privileges may be required to access the
   device. To prevent a reader being used by the NFC kernel driver add
   a blacklist entry in ``'/etc/modprobe.d/'``, for example the following
   line works for the PN533 based SCL3711: ::

     $ echo "blacklist pn533" | sudo tee -a /etc/modprobe.d/blacklist-nfc.conf

   Root permissions are usually needed for the USB readers and ``sudo
   python`` is an easy fix, however not quite convinient and
   potentially dangerous. A better solution is to add a udev rule and
   make the reader accessible to a normal user, like the following
   rules would allow members of the *plugdev* group to access an
   SCL-3711 or RC-S380 if stored in
   ``'/etc/udev/rules.d/nfcdev.rules'``. ::

     SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="04e6", \
       ATTRS{idProduct}=="5591", GROUP="plugdev" # SCM SCL-3711
     SUBSYSTEM=="usb", ACTION=="add", ATTRS{idVendor}=="054c", \
       ATTRS{idProduct}=="06c1", GROUP="plugdev" # Sony RC-S380


Open a reader
=============

The main entrance to nfcpy is the :class:`nfc.ContactlessFrontend`
class. When initialized with a *path* argument it tries to locate and
open a contacless reader connected at that location, which may be for
example the first available reader on USB. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> print(clf)
  Sony RC-S360/SH on usb:002:005

For more control of where a reader may befound specifiy further
details of the path string, for example `usb:002:005` to open the same
reader as above, or `usb:002` to open the first available reader on
USB bus number 2 (same numbers as shown by the `lsusb` command). The
other way to specify a USB reader is by vendor and product ID, again
by way of example `usb:054c:02e1` will most likely open the same
reader as before if there's only one plugged in. ::

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
  Linux UDP/IP on udp:localhost:54321

Just to say for completeness, you can also omit the path argument and
later open a reader using :meth:`ContactlessFrontend.open`. The
difference is that :meth:`~ContactlessFrontend.open` returns either
:const:`True` or :const:`False` depending on whether a reader was
found whereas ``ContactlessFrontend('...')`` raises :exc:`IOError`
if a reader was not found.

Read/write tags
===============

With a reader opened the next step to get an NFC communication running
is to use the :meth:`nfc.clf.ContactlessFrontend.connect` method.
We'll start with connecting to a tag (a contactless card), hopefully
you have one and it's not a Mifare Classic. Currently supported are
only NFC Forum Type 1, 2, 3 and 4 Tags. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> clf.connect(rdwr={}) # now touch a tag and remove it
  True

Although this doesn't look very exciting a lot has happened in the
background. The tag was discovered and activated and it's data content
read. Thereafter :meth:`nfc.clf.ContactlessFrontend.connect` continued
to check the presence of the tag until you removed it. The return
value :const:`True` tells us that it terminated normally and not
due to a :exc:`KeyboardInterrupt` (in which case we've seen
:const:`False`). You can try this by either not touching or not
removing the tag and press `Ctrl-C` while in ``connect()``.

Obviously, as we've set the *rdwr* options as a dictionary, there must
be something we can put into the dictionary to give us a bit more
control. The most important option we can set is a callback funtion
that will let us know when a tag got connected. It's famously called
'on-connect' and can be used like so: ::

  >>> import nfc
  >>> def connected(tag): print tag
  ...
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> clf.connect(rdwr={'on-connect': connected}) # now touch a tag
  Type3Tag IDm=01010501b00ac30b PMm=03014b024f4993ff SYS=12fc
  <nfc.tag.tt3.Type3Tag object at 0x7f9e8302bfd0>

As expected our simple callback function does print some basic
information about the tag, we see that it was an NFC Forum Type 3 Tag
which has the system code 12FCh, a Manufacture ID and Manufacture
Parameters. You should have noted that the connect() was not blocking
until the tag was removed and that we've got an instance of class
:class:`nfc.tag.tt3.Type3Tag` returned. Both is because the callback
function did return :const:`None` (treated as :const:`False`
internally) and the connect() logic assumed that the caller want's to
handle the tag presence check by itself or explicitely does not want
to have that loop running. If we slightly modify the example you'll
notice that again you have to remove the tag before connect() returns
and the return value now is :const:`True` (unless you press
``Control-C`` of course). ::

  >>> import nfc
  >>> def connected(tag): print tag; return True
  ...
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> clf.connect(rdwr={'on-connect': connected}) # now touch a tag
  Type3Tag IDm=01010501b00ac30b PMm=03014b024f4993ff SYS=12fc
  True

.. note:: The generally recommended way for application logic on top
   of nfcpy is to use callback functions and not manually deal with
   the objects returned by connect(). But in the interactive Python
   interpreter it is sometimes just more convinient to do so. Tags are
   also quite friendly, they'll just wait indefinite time for you to
   send them a command, this is much different for LLCP and CARD mode
   where timing becomes critical. But more on that later.

Now that we've seen how to connect a tag, how do we get some data from
it? If using the same tag as before, we've already learned by the
system code 12FCh (which is specific for Type 3 Tags) that this tag
should be capable to hold an NDEF message (NDEF is the NFC Forum Data
Exchange Format and can be read and written with every NFC Forum
compliant Tag). As *nfcpy* is supposed to make things easy, here is
the small addition we need to get the NDEF message printed. ::

  >>> import nfc
  >>> with nfc.ContactlessFrontend('usb') as clf:
  ...     tag = clf.connect(rdwr={'on-connect': None}) # now touch a tag
  ...     print tag.ndef.message.pretty() if tag.ndef else "Sorry, no NDEF"
  ...
  record 1
    type   = 'urn:nfc:wkt:Sp'
    name   = ''
    data   = '\xd1\x01\nU\x03nfcpy.org'

If the tag's attribute :attr:`~nfc.tag.ndef` is set we can simply read
the ndef :attr:`~nfc.tag.ndef.message` attribute to get a fully parsed
:class:`nfc.ndef.Message` object, which in turn has a method to pretty
print itself. It looks like this is a Smartposter message and probably
links to the *nfcpy* website.

.. note:: We used two additional features to make our life easier and
   shorten typing. We've set the 'on-connect' callback to simply
   :const:`None` instead of providing an actual function object that
   returns :const:`None` (or :const:`False` which would have the same
   effect). And we used :class:`ContactlessFrontend` as a context
   manager, which means the *clf* it will be closed as soon as we
   leave the **with** clause.

Let's see if the Smartposter message is really referring to
``nfcpy.org``. For that we'll need to know that NDEF parsers and
generators are in the submodule ``nfc.ndef``. And because it's easier
to observe results step-by-step we'll not use the context manager
mechanism but go plain. Just don't forget that you have either close
the *clf* at the end of the example or leave the interpreter before
trying the next example ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> tag = clf.connect(rdwr={'on-connect': None}) # now touch a tag
  >>> if tag.ndef and tag.ndef.message.type == 'urn:nfc:wkt:Sp':
  ...     sp = nfc.ndef.SmartPosterRecord(tag.ndef.message[0])
  ...     print sp.pretty()
  ...
  resource = http://nfcpy.org
  action   = default

There are a few things to note. First, we went one step further in
attribute the hierarchy and discovered the message type. An
:class:`nfc.ndef.Message` is a sequence of :class:`nfc.ndef.Record`
objects, each having a *type*, a *name* and a *data* member. The
*type* and *name* of the first record are simply mapped to the *type*
and *name* of the message itself as that usually sets the processing
context for the remaining records. Second, we grab the first record by
index 0 without any check for an index error. Of course may that be
safe due to the initial check on message type (which turns to the
first record type) and we'd expect something else to be there if the
message is empty. But it's also safe because the `tag.ndef.message`
will **always** hold a valid :class:`~nfc.ndef.Message`, just that it
be a message with one empty record (*type*, *name* and *data* will all
be empty strings) if the NDEF tag does not contain actual NDEF data or
the data is corrupted.

Now as the final piece of this section let us improve the Smartposter
a little bit. Usually a Smartposter should have a URI that links to
the resource and a title to help humans understand what the link
points to. We omit all the safety check, so please be sure to touch
the same tag as before and not switch to a Mifare Classic. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> tag = clf.connect(rdwr={'on-connect': None}) # now touch the tag
  >>> sp = nfc.ndef.SmartPosterRecord('http://nfcpy.org')
  >>> sp.title = "Python module for near field communication"
  >>> tag.ndef.message = nfc.ndef.Message(sp)
  >>> print nfc.ndef.SmartPosterRecord(tag.ndef.message[0]).pretty()
  resource  = http://nfcpy.org
  title[en] = Python module for near field communication
  action    = default

It happend, you've destroyed your overly expensive contactless
tag. Sorry I was joking, except for the "overly expensive" part (they
should really become cheaper). But the tag, if nothing crashed, has
now slightly different content and it all happend in the sixth line
were the new message got assigned to the ``tag.ndef.message``
attribute. In that line it was immediately written to the tag and the
internal copy (the old data) invalidated. The last line then caused
the message to be read back from the tag and finally printed.

.. note:: The :mod:`nfc.ndef` module has a lot more functionality than
   could be covered in this short introduction, feel free to read the
   API documentation as well as the :ref:`ndef-tutorial` tutorial to
   learn how *nfcpy* maps to the concepts of the NDEF specification.

Pretend a card
==============

How do we get *nfcpy* to be a card? Supply ``card`` options to
:meth:`nfc.ContactlessFrontend.connect`. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> print clf.connect(card={})
  None

Guess you've noticed that something was going wrong. Unlike when
reading a card (or tag) the ``clf.connect()`` call returns immediately
and the result we're getting is :const:`None`. This is because there
exists no sensible default behavior that can be applied when working
as a tag, we need to be explicit about the technology we want to use
(for a tag reader it just makes sense to look for all technologies and
tag types). So we choose a technology and supply that as the 'targets'
option. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> nfcf_idm = bytearray.fromhex('03FEFFE011223344')
  >>> nfcf_pmm = bytearray.fromhex('01E0000000FFFF00')
  >>> nfcf_sys = bytearray.fromhex('12FC')
  >>> target = nfc.clf.TTF(br=212, idm=nfcf_idm, pmm=nfcf_pmm, sys=nfcf_sys)
  >>> clf.connect(card={'targets': [target]}) # touch a reader
  True

.. note:: It is time to talk about the limitations. As of writing,
   *nfcpy* supports tag emulation only for NFC Forum Type 3 Tag and
   requires a Sony RC-S380 contactless frontend. The only alternative
   to an RC-S380 is to use the UDP driver that simulates NFC
   communication over UDP/IP. To use the UDP driver initialize
   ContactlessFrontend with the string ``udp`` and use
   ``examples/tagtool.py --device udp`` as card reader.

You can read the tag we've created for example with the excellent `NXP
Tag Info`_ app available for free in the Android app store. It will
tell you that this is a *FeliCa Plug RC-S926* tag (because we said
that with the first two bytes of the *IDm*) and if you switch over to
the TECH view there'll be the *IDm*, *PMm* and *System Code* we've
set.

.. note:: Depending on your Android device it will be more or less
   difficult to get a stable reading, it seems to depend much on the
   phone's NFC chip and driver. Generally the Google Nexus 4 and 10
   work pretty well and the same should be true for the Samsung S4 as
   those are having the same chip. Other phones can be a little bitchy.

The `NXP Tag Info`_ app tells us that there's no NDEF partition on it,
so let's fix that. It's unfortunately now going to be a bit more code
and you probably want to copy it, so the following is not showing the
interpreter prompt. ::

  import nfc
  clf = nfc.ContactlessFrontend('usb')
  nfcf_idm = bytearray.fromhex('03FEFFE011223344')
  nfcf_pmm = bytearray.fromhex('01E0000000FFFF00')
  nfcf_sys = bytearray.fromhex('12FC')
  target = nfc.clf.TTF(br=212, idm=nfcf_idm, pmm=nfcf_pmm, sys=nfcf_sys)

  attr = nfc.tag.tt3.NdefAttributeData()
  attr.version, attr.nbr, attr.nbw = '1.0', 12, 8
  attr.capacity, attr.writeable = 1024, True
  ndef_data_area = str(attr) + bytearray(attr.capacity)

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

  def connected(tag, cmd):
      tag.add_service(0x0009, ndef_read, ndef_write)
      tag.add_service(0x000B, ndef_read, lambda: False)
      return True
  
  while clf.connect(card={'targets': [target], 'on-connect': connected}): pass

We've now got a fully functional NFC Forum Type 3 Tag. If, for
example, you have the `NXP Tag Writer`_ app installed, start to write
something to the card, touch again to read it back, and so
on. Finally, press ``Ctrl-C`` to stop the card working.

.. note:: Other card commands can be realized by running the basic
   *receive command* and *send response* loop as part of the
   application logic, for example as part of the ``on-connect``
   callback function with a :const:`False` value returned at the
   end. The loop requires a bit of exception checking and must handle
   unknown command, check out :meth:`nfc.ContactlessFrontend.connect`
   in ``nfc/clf.py`` for something to start with.

.. _NXP Tag Info:
   https://play.google.com/store/apps/details?id=com.nxp.taginfolite

.. _NXP Tag Writer:
   https://play.google.com/store/apps/details?id=com.nxp.nfc.tagwriter


Work with a peer
================

The best part of NFC comes when the limitations of a single master
controlling a poor servant are overcome. This is achieved by the NFC
Forum Logical Link Control Protocol (LLCP), which allows multiplexed
communications between two NFC Forum Devices with either peer able to
send protocol data units at any time and no restriction to a single
application run in one direction.

An LLCP link between two NFC devices is established again by calling
:meth:`ContactlessFrontend.connect` with a set of options, this time
they go with the argument ``llcp``.

.. note:: The example code in this section assumes that you have an
   Android phone to use as peer device. If that is not the case you
   can either use readers that are supported by *nfcpy* and start
   ``examples/snep-test-server.py --loop`` before diving into the
   examples or use the UDP driver to work without a hardware. You'll
   then start ``examples/snep-test-server.py --loop --device udp``
   first and initalize :meth:`~ContactlessFrontend` with the path
   string ``'udp'`` instead of ``'usb'``.

Here's the shortest code fragment we can use to get an LLCP link
running. ::

  >>> import nfc
  >>> clf = ContactlessFrontend('usb')
  >>> clf.connect(llcp={}) # now touch your phone
  True
  >>> clf.close()

Depending on your reader and the phone you may have had to explicitely
move both out of proximity to see :const:`True` printed after connect
or it may just have happened. That is simply because the device
connect phase may have seen unstable communication and ``connect``
returns after one activation/deactivation.

.. note:: In the contactless world it can not be really distinguished
   whether deactivation was intentional deactivation or because of
   broken communication. A broken communication is just the normal
   case when a user removes the device.

Remember that :meth:`~ContactlessFrontend.connect` returns
:const:`True` (or something that evaluates :const:`True` in a boolean
expression) when returning normally and the pattern is clear: We just
need to call :meth:`~ContactlessFrontend.connect` in an endless loop
until a :exc:`KeyboardInterrupt` exception is raised (with ``Ctrl-C``
or send by an external program) ::

  >>> import nfc
  >>> clf = ContactlessFrontend('usb')
  >>> while clf.connect(llcp={}): pass
  ...
  >>> clf.close()

Now we've got LLCP running but there's still not much we can do with
it. But same as for the other modes we can add a callback function for
the ``on-connect`` event. This function will receive as it's single
argument the :class:`~nfc.llcp.llc.LogicalLinkController` instance
that controls the LLCP link. ::

  >>> import nfc
  >>> def connected(llc):
  ...     print llc
  ...     return True
  ...
  >>> clf = ContactlessFrontend('usb')
  >>> clf.connect(llcp={'on-connect': connected})
  LLC: Local(MIU=128, LTO=100ms) Remote(MIU=1024, LTO=500ms)
  True
  >>> clf.close()

The callback function is the place where we to start LLCP client and
server applications but it is important to treat it like an interrupt,
that means application code must be started in a separate thread and
the callback return immediately. The reason is that in order to keep
the LLCP link alive and receive or dispatch LLC protocol data units
(PDUs) the :class:`~nfc.llcp.llc.LogicalLinkController` must run a
service loop and :meth:`~ContactlessFrontend.connect` is using the
calling thread's context for that. When using the interactive
interpreter this is less convinient as we'd have to change the
callback code when going further with the tutorial, so remember that
if the callback returns :const:`False` or :const:`None` then
:meth:`~ContactlessFrontend.connect` will not do the housekeeping
stuff but return immediately and give us the callback parameters. ::

  >>> import nfc, threading
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> connected = lambda llc: threading.Thread(target=llc.run).start()
  >>> llc = clf.connect(llcp={'on-connect': connected})
  >>> print llc
  LLC: Local(MIU=128, LTO=100ms) Remote(MIU=1024, LTO=500ms)
  >>> clf.close()

Application code is not supposed to work directly with the *llc*
object but it's one of the parameters we need to create a
:class:`nfc.llcp.Socket` for the actual communication. The other
parameter we need to supply is the socket type, either
:const:`nfc.llcp.LOGICAL_DATA_LINK` for a connection-less socket or
:const:`nfc.llcp.DATA_LINK_CONNECTION` for a connection-mode socket. A
connection-less socket does not guarantee that application data is
delivered to the remote application (although *nfcpy* makes sure that
it's been delivered to the remote device). A connection-mode socket
cares about reliability, unless the other implementation is buggy data
you send is guaranteed to make it to the receiving application -
error-free and in order.

So what can we do next with the Android phone? It happens that every
modern NFC phone on the market has a so called SNEP Default Server
running that we can play with. The acronym SNEP stands for the NFC
Forum Simple NDEF Exchange Protocol and the SNEP Default Server is a
service that must be available on every NFC Forum certified
device. Though many phones are not yet certified, a SNEP default
server is built into stock Android as part of the Android Beam
feature. Because SNEP messages are exchanged over an LLCP data link
connection we'll first have to create a connection-mode socket, then
determine the address of the SNEP server, connect to the server and
finally send some data. ::

  >>> import nfc, threading
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> connected = lambda llc: threading.Thread(target=llc.run).start()
  >>> llc = clf.connect(llcp={'on-connect': connected})
  >>> socket = nfc.llcp.Socket(llc, nfc.llcp.DATA_LINK_CONNECTION)
  >>> addr = socket.resolve('urn:nfc:sn:snep')
  >>> addr
  4
  >>> socket.connect(addr)
  >>> msg = nfc.ndef.Message(nfc.ndef.SmartPosterRecord("http://nfcpy.org"))
  >>> str(msg)
  '\xd1\x02\x0eSp\xd1\x01\nU\x03nfcpy.org'
  >>> hex(len(str(msg)))
  '0x13'
  >>> socket.send("\x10\x02\x00\x00\x00\x13" + str(msg))
  >>> socket.recv()
  '\x10\x81\x00\x00\x00\x00'
  >>> socket.close()
  >>> clf.close()

If your phone has an Internet connection you should now see that the
Internet browser has opened the http://nfcpy.org web page. In Android terminology we've *beamed*.

.. _NFC Forum Assigned Numbers Register:
   http://www.nfc-forum.org/specs/nfc_forum_assigned_numbers_register

Just for the purpose of demonstration the example did resolve the SNEP
default server's service name into an address value first. But both
the service name ``urn:nfc:sn:snep`` and the address 4 are well-known
values defined in the `NFC Forum Assigned Numbers Register`_ and so
we've could have directly connect to address 4. And because it is also
possible to use a service name as an address we've could have gone
without the reolve step at all. So all of the following calls would have brought us the same effect. ::

  >>> socket.connect( socket.resolve('urn:nfc:sn:snep') )
  >>> socket.connect( 'urn:nfc:sn:snep' )
  >>> socket.connect( 4 )

As it is a primary goal of *nfcpy* to make life as simple as possible,
there is no need to mess around with binary strings. The
:class:`nfc.snep.SnepClient` does all the things needed, just import
:mod:`nfc.snep` to have it available. ::

  >>> import nfc, nfc.snep, threading
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> connected = lambda llc: threading.Thread(target=llc.run).start()
  >>> llc = clf.connect(llcp={'on-connect': connected})
  >>> link = nfc.ndef.UriRecord("http://nfcpy.org")
  >>> snep = nfc.snep.SnepClient(llc)
  >>> snep.put(nfc.ndef.Message(link))
  True
  >>> clf.close()

The :mod:`nfc.llcp` module documentation contains more information on
LLCP and the :class:`nfc.llcp.Socket` API.

