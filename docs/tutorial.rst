Tutorial
========

.. note::

   Examples may require root privileges to access the NFC readers connected via USB (and not emulating a serial connection). This can best be done by running "sudo python" or to adjust permissions of the device node.  ::

      $ lsusb
      Bus 003 Device 009: ID 04e6:5591 SCM Microsystems, Inc.
      $ sudo chmod 666 /dev/bus/usb/003/009


Connect to a reader
-------------------

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

