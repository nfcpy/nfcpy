====================
Contactless Frontend
====================

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

Finding readers
===============

>>> import nfc
>>> clf = nfc.ContactlessFrontend()
>>> repr(clf)
'<nfc.clf.ContactlessFrontend object at 0xb780068c>'
>>> str(clf)
'Sony RC-S360/SH on usb:002:005'
>>> clf.close()
>>> str(clf)
'<nfc.clf.ContactlessFrontend object at 0xb780068c>'

:class:`~nfc.ContactlessFrontend` can be used in a :keyword:`with` statement.

>>> import nfc
>>> with nfc.ContactlessFrontend() as clf:
>>>     str(clf)
'Sony RC-S360/SH on usb:002:005'
>>> str(clf)
'<nfc.clf.ContactlessFrontend object at 0xb780068c>'

