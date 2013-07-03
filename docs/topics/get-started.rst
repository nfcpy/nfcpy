===============
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
=============

The main entrance to nfcpy is the :class:`nfc.ContactlessFrontend`
class. When initialized without argument it tries to locate and open a
contacless reader connected at USB or TTY. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend()
  >>> print(clf)
  Sony RC-S360/SH on usb:002:005

For more control of where a reader may befound specifiy a path string,
for example `usb:002:005` would open the same reader as above whereas
`usb:002` would open the first available reader on usb bus 2 (same
numbers as shown by the `lsusb` command). The other way to specify a
USB reader is by vendor and product ID, again by way of example
`usb:054c:02e1` will most likely open the same reader as before if
there's only one plugged in. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend(path='usb:054c')
  >>> print(clf)
  Sony RC-S360/SH on usb:002:005

Similar stuff exists for serially connected readers and, best of all,
if you don't have an NFC reader at hand or just want to test your
application logic there's also a driver that carries NFC frames
across a UDP/IP link. ::

  >>> import nfc
  >>> clf = nfc.ContactlessFrontend(path='udp')
  >>> print(clf)
  Linux UDP/IP on udp:localhost:54321

