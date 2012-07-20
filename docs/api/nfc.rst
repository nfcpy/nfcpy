==============
``nfc`` module
==============

.. automodule:: nfc

Contactless Frontend
====================

.. autoclass:: nfc.ContactlessFrontend
   :members:

Tag Base Class
==============

.. autoclass:: TAG
   :members:

.. autoclass:: NDEF
   :members:

Type 1 Tag
==========

.. autoclass:: Type1Tag()
   :members:

   Base: :class:`nfc.TAG`

Type 2 Tag
==========

.. autoclass:: Type2Tag()
   :members:

   Base: :class:`nfc.TAG`

Type 3 Tag
==========

.. autoclass:: Type3Tag()
   :members:

   Base: :class:`nfc.TAG`

Type 4 Tag
==========

.. autoclass:: Type4Tag()
   :members:

   Base: :class:`nfc.TAG`

Data Exchange Protocol
======================

Base Class
----------

.. autoclass:: nfc.DEP()
   :members: general_bytes, role

Initiator
---------

.. autoclass:: nfc.DEPInitiator()
   :members: exchange

   Base: :class:`nfc.DEP`

Target
------

.. autoclass:: nfc.DEPTarget()
   :members: wait_command, send_response

   Base: :class:`nfc.DEP`

