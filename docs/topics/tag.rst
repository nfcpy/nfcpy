=====================
Contactless Tag Types
=====================

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


