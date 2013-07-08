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

Read/Write Tags
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

Emulate Tags
------------

This section has yet to be written.

Peer 2 Peer
-----------

This section has yet to be written. Meantime, you may read the :mod:`nfc.llcp` API documentation which has some lightweight examples too.
