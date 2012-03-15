Interface
=========

Contactless Frontend
--------------------

.. class:: nfc.ContactlessFrontend

   ..method:: poll()

.. autoclass:: nfc.ContactlessFrontend
   :members:


Tag Type Classes
----------------
Tag type objects are returned by :meth:`~nfc.ContactlessFrontend.poll()` when a contactless tag is present in the reader's field. The following example shows how to read and write NDEF data::

    clf = nfc.ContactlessFrontend()
    tag = clf.poll()
    if isinstance(tag, nfc.TAG):
        if tag.ndef:
            ndef_data = tag.ndef.message
            print ndef_data.encode("hex")
            tag.ndef.message = ndef_data

.. autoclass:: nfc.TAG
   :members:

.. autoclass:: nfc.NDEF
   :members:

.. autoclass:: nfc.Type1Tag()
   :members:

   Base: :class:`nfc.TAG`

.. autoclass:: nfc.Type2Tag()
   :members:

   Base: :class:`nfc.TAG`

.. autoclass:: nfc.Type3Tag()
   :members:

   Base: :class:`nfc.TAG`

.. autoclass:: nfc.Type4Tag()
   :members:

   Base: :class:`nfc.TAG`

Data Exchange
-------------

.. autoclass:: nfc.DEP()
   :members: general_bytes, role

.. autoclass:: nfc.DEPInitiator()
   :members: exchange

.. autoclass:: nfc.DEPTarget()
   :members: wait_command, send_response

