Tutorial
========

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

