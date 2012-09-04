=============
helloworld.py
=============

Everything needs a "hello world", so does nfcpy. The *helloworld*
example demonstrates how to use nfcpy to discover a tag, write NDEF
data to the tag, wait until the tag was removed and touched again to
finally read NDEF data from the tag.

.. warning::

   The helloworld example overwrites data on the tag without asking
   for permission. Be careful.

Source code
-----------

.. literalinclude:: ../../examples/helloworld.py
   :lines: 24-
   :linenos:

Discussion
----------

Line 11

  The first available NFC reader is opened and stored in `clf`. This
  line would raise a :exc:`LookupError` exception if no reader is found, and
  should in real applications be enclosed in a try-except clause.

Line 13-17

  Here we wait for a tag to be touched, using the
  :meth:`nfc.ContactlessFrontend.poll` method in an endless loop. This
  loop will only discover tags and no peer-to-peer targets because
  protocol_data is not provided.

Line 19-22

  This creates three different :class:`nfc.ndef.TextRecords`, which are
  then used to initialize an :class:`nfc.ndef.Message` with a list of
  records. An alternative way would have been to append the records::

    message = nfc.ndef.Message()
    message.append(nfc.ndef.TextRecord(text="Hello World", language="en"))
    ...

Line 24

  This is where the data gets written to the tag. The message is first
  converted into a string of octets using Python's :func:`str`
  function, and then by assigning the the result to the
  :attr:`nfc.NDEF.message` object exposed by the tag's ndef attribute
  it is immediately written to the tag.

Line 26-28

  Here we just check if the tag is still in proximity using the
  :meth:`nfc.TAG.is_present` method in a loop.

Line 30-34

  Same as before, we're waiting for a tag to be touched.

Line 36

  An :class:`nfc.ndef.Message` can be initialized with a string (or
  bytearray) of raw NDEF message data. The message data is then parsed
  into the sequence of :class:`nfc.ndef.Records` that are found within
  the NDEF message.

Line 37-40

  The :class:`nfc.ndef.Message` type supports :func:`list` operations,
  so we can sequentially loop over the records. Every record that has
  a record type "urn:nfc:wkt:T" gets passed into an
  :class:`nfc.ndef.TextRecord` and we can finally print the language
  and text.
