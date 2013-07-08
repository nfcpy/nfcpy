=============
helloworld.py
=============

Everything needs a "hello world", so does nfcpy. The *helloworld*
example demonstrates how to use nfcpy to discover a tag, write NDEF
data to the tag, wait until the tag was removed and touched again to
finally read NDEF data from the tag.

.. warning::

   The helloworld example overwrites data on the tag without
   asking. Be sure what you do.

Source code
-----------

.. literalinclude:: ../../examples/helloworld.py
   :lines: 23-
   :linenos:

Discussion
----------

Line 13-15

  We create three :class:`nfc.ndef.TextRecord` objects to have "Hello
  World" in different languages.

Line 17

  The example is implemented as a class just because we want to easily
  share share state (via the ``sent_data`` attribute) between
  ``main()`` method and ``send_data()``.

Line 18

  The ``send_hello()`` method will be called when the first tag has
  been activated. This is because we set as callback in our first call
  to :meth:`nfc.ContactlessFrontend.connect`.

Line 19

  A tag may or may not have an NDEF partition. If it has, the
  ``tag.ndef`` attribute will hold an NDEF object, otherwise it will
  ``None``.

Line 20

  This creates an :class:`nfc.ndef.Message` with the three text
  records and writes the message to the tag.

Line 21

  Let the ``main()`` method now that we've written the hello world
  message. This will terminate the loop in line 37.

Line 25

  We want the :meth:`nfc.ContactlessFrontend.connect` method to only
  return when the tag is moved out of range. This is achieved by
  returning ``True``.

Line 27

  The ``read_hello()`` method will be called when the second tag has
  been activated. This is because we set as callback in our second
  call to :meth:`nfc.ContactlessFrontend.connect`.

Line 29-32

  The ``tag.ndef.message`` attribute is guaranteed to be an
  :class:`nfc.ndef.Message` type (with one empty record if the tag
  doesn't actually contain NDEF data). The :class:`nfc.ndef.Message`
  type supports sequence operations, so we can simply iterate over the
  records. For every record that has the record type ``urn:nfc:wkt:T``
  we'll construct a :class:`nfc.ndef.TextRecord` and print the
  content.

Line 36

  The first available NFC reader (connected on USB) is opened and
  assigned to *clf*. This line would raise an :exc:`IOError` exception
  (with errno set to :const:`errno.ENODEV`) if no reader is found and
  should in real applications be enclosed in a try-except clause.

Line 38

  Our synchronization flag. This will be set to ``True`` in
  ``send_hello()`` when the NDEF message was written.

Line 42

  This is where the magic happens. By calling
  :meth:`nfc.ContactlessFrontend.connect` with the *rdwr* keyword
  argument we'll have a tag discovery loop activated and receive a
  callback to the function set with 'on-callback'. As we set the
  callback to ``send_hello()`` the ``sent_hello`` attribute will
  become ``True`` if the NDEF message was written.

Line 45

  We use :meth:`nfc.ContactlessFrontend.connect` again but this time
  with the callback set to ``read_hello()``. In absence
  of human errors we should be able to read the "hello world" NDEF
  message back from the tag.

