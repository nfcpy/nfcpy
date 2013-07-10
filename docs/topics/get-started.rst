Getting started
===============

.. note::

   Working with contactless reader hardware may require root
   permissions on Linux systems, it is usually necessary for readers
   that connect via USB. The simplest way is to run python via sudo
   but then the password must be input quite frequently. A more
   persistent method is to adjust device node permissions, this will
   at least keep it for the login session::

      $ lsusb
      Bus 003 Device 009: ID 04e6:5591 SCM Microsystems, Inc.
      $ sudo chmod 666 /dev/bus/usb/003/009

   The most persistant method is to install a udev rules file into
   /etc/udev/rules.d/. An example can be found at
   https://code.google.com/p/libnfc/source/browse/trunk/contrib/udev/42-pn53x.rules

Open a reader
-------------

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
---------------

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

Emulate a tag
-------------

This section has yet to be written.

Work with a peer
----------------

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
argument the :class:`~nfc.llcp:llc:LogicalLinkController` instance
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
  >>> clf = nfc.ContactlessFrontend('usb)
  >>> connected = lambda llc: threading.Thread(target=llc.run()).start()
  >>> llc = clf.connect(llcp={'on-connect': connected})
  >>> print llc
  LLC: Local(MIU=128, LTO=100ms) Remote(MIU=1024, LTO=500ms)
  >>> clf.close()

Application code is not supposed to work directly with the *llc*
object but it's one of the parameters we need to create a
:class:`nfc.llcp.Socket` for the actual communication. The other
argument we need to supply is the socket type, either
:const:`nfc.llcp.LOGICAL_DATA_LINK` for a connection-less socket or
:const:`nfc.llcp.DATA_LINK_CONNECTION` for a connection-mode socket. A
connection-less socket does not guarantee that application data is
delivered to the remote application (although *nfcpy* guarantees that
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
server is built into stock Android and part of the Android Beam
feature. As SNEP messages are exchanged over an LLCP data link
connection we'll first create a connection-mode socket, then determine
the address of the SNEP server, connect to the server and send some
data. ::

  >>> import nfc, threading
  >>> clf = nfc.ContactlessFrontend('usb)
  >>> connected = lambda llc: threading.Thread(target=llc.run()).start()
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

Just for the purpose of demonstration I've shown how to resolve the
SNEP default server's service name into an address value. Both the
service name ``urn:nfc:sn:snep`` and the address 4 are well-known
values defined in the `NFC Forum Assigned Numbers Register`_ so we
could have directly connect to 4. It is also possible to use a service
name as an address so below calls all have the same effect. ::

  >>> socket.connect( socket.resolve('urn:nfc:sn:snep') )
  >>> socket.connect( 'urn:nfc:sn:snep' )
  >>> socket.connect( 4 )

As it is a primary goal of *nfcpy* to make life as simple as possible
there is no need to mess around with binary strings. The
:class:`nfc.snep.SnepClient` does all the things needed, just import
:mod:`nfc.snep` to have it available. ::

  >>> import nfc, nfc.snep, threading
  >>> clf = nfc.ContactlessFrontend('usb)
  >>> connected = lambda llc: threading.Thread(target=llc.run()).start()
  >>> llc = clf.connect(llcp={'on-connect': connected})
  >>> snep = nfc.snep.SnepClient(llc)
  >>> uri = "http://nfcpy.org"
  >>> snep.put(nfc.ndef.Message(nfc.ndef.SmartPosterRecord(uri)))
  >>> clf.close()

The :mod:`nfc.llcp` module documentation contains more information on
LLCP and the :class:`nfc.llcp.Socket` API.

