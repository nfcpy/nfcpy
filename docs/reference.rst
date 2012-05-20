****************
Module Reference
****************

:mod:`nfc`
===============

.. autoclass:: nfc.ContactlessFrontend
   :members:

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

.. autoclass:: nfc.DEP()
   :members: general_bytes, role

.. autoclass:: nfc.DEPInitiator()
   :members: exchange

   Base: :class:`nfc.DEP`

.. autoclass:: nfc.DEPTarget()
   :members: wait_command, send_response

   Base: :class:`nfc.DEP`

:mod:`nfc.ndef`
===============

.. automodule:: nfc.ndef

.. autoclass:: nfc.ndef.Record
   :members:

.. autoclass:: nfc.ndef.TextRecord
   :members:

   Base: :class:`nfc.ndef.Record`

.. autoclass:: nfc.ndef.UriRecord
   :members:

   Base: :class:`nfc.ndef.Record`

.. autoclass:: nfc.ndef.Message
   :members:

:mod:`nfc.snep`
===============
This module implements a Server and Client for the Simple NDEF Exchange Protocol (SNEP) defined by the NFC Forum.

.. note::
   This module is not yet documented.

:mod:`nfc.npp`
===============
This module implements a Server and Client for the NDEF Push Protocol (NPP) defined by Google.

.. note::
   This module is not yet documented.

