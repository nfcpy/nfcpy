Interface
=========

Contactless Frontend
--------------------

.. autoclass:: nfc.ContactlessFrontend
   :members:


Tag Type Classes
----------------
Tag type objects are returned by :meth:`~nfc.ContactlessFrontend.poll()` when a contactless tag is present in the reader's field.

.. autoclass:: nfc.TAG
   :members:

.. class:: nfc.Type1Tag

   Not yet implemented

.. autoclass:: nfc.Type2Tag()
   :members:

   Base: :class:`nfc.TAG`

.. autoclass:: nfc.Type3Tag()
   :members:

   Base: :class:`nfc.TAG`

.. class:: nfc.Type4Tag

   Not yet implemented

.. class:: nfc.MifareClassic

   Not yet implemented

.. autoclass:: nfc.tag.NDEF
   :members:

Data Exchange
-------------

.. autoclass:: nfc.DEP()
   :members: general_bytes, role

.. autoclass:: nfc.DEPInitiator()
   :members: exchange

.. autoclass:: nfc.DEPTarget()
   :members: wait_command, send_response

