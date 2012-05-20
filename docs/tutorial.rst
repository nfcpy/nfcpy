********
Tutorial
********

.. note::

   Examples code may require root privileges if accessing NFC readers
   connected via USB This can be done by running python as superuser
   or by adjusting device node permissions.  ::

      $ lsusb
      Bus 003 Device 009: ID 04e6:5591 SCM Microsystems, Inc.
      $ sudo chmod 666 /dev/bus/usb/003/009

Connect to a reader
===================

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

Tag Type Classes
================

Tag type objects are returned by the
:meth:`nfc.ContactlessFrontend.poll()` method when a contactless tag
is present in the reader's field. The following example shows how to
read and write NDEF binary data ::

    clf = nfc.ContactlessFrontend()
    tag = clf.poll()
    if isinstance(tag, nfc.TAG):
        if tag.ndef:
            ndef_data = tag.ndef.message
            print ndef_data.encode("hex")
            tag.ndef.message = ndef_data


Working with NDEF
=================

The NFC Data Exchange Format (NDEF) is a binary message format used to
exchange application-defined payloads between NFC Forum Devices or to
store and retrieve payloads from an NFC Forum Tag. A payload is
described by a type, a length and an optional identifer encoded in an
NDEF Record structure. An NDEF Message is a sequence of NDEF records
with a begin marker in the first and an end marker in the last record.

The :class:`nfc.ndef.Record` and :class:`nfc.ndef.Message` types can
be used to decode and encode NDEF Records and Messages.

>>> import nfc.ndef
>>> message = nfc.ndef.Message(b'\xD1\x01\x0ET\x02enHello World')
>>> len(message)
1
>>> message[0]
nfc.ndef.Record('urn:nfc:wkt:T', '', '\x02enHello World')

>>> import nfc.ndef
>>> record = nfc.ndef.UriRecord("http://nfcpy.org")
>>> record.type, record.name, record.data
'urn:nfc:wkt:U'
>>> record.data
'\x03nfcpy.org'
