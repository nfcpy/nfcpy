Interface
=========

.. autoclass:: nfc.ContactlessFrontend
   :members: poll, listen, close

.. autoclass:: nfc.DEPInitiator
   :members: exchange

.. autoclass:: nfc.DEPTarget
   :members: wait_command, send_response

Tag Types
---------

.. py:class:: nfc.Type1Tag

   Not yet implemented

.. autoclass:: nfc.Type2Tag
   :members: read, write, is_present, ndef

.. autoclass:: nfc.Type3Tag
   :members: read, write, is_present, ndef

.. py:class:: nfc.Type4Tag

   Not yet implemented

.. py:class:: nfc.MifareClassic

   Not yet implemented
