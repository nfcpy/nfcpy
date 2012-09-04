===================
``nfc.ndef`` module
===================

.. automodule:: nfc.ndef

Message
=======
.. autoclass:: Message
   :members:

Record
======
.. autoclass:: Record
   :members:

.. autoclass:: nfc.ndef.record.RecordList
   :show-inheritance:
   :members:

TextRecord
==========
.. autoclass:: TextRecord
   :show-inheritance:
   :members:

UriRecord
=========
.. autoclass:: UriRecord
   :show-inheritance:
   :members:

SmartPosterRecord
=================
.. autoclass:: SmartPosterRecord
   :show-inheritance:
   :members:

Connection Handover
===================

HandoverRequestMessage
----------------------
.. autoclass:: HandoverRequestMessage
   :members:

HandoverSelectMessage
---------------------
.. autoclass:: HandoverSelectMessage
   :members:

HandoverCarrierRecord
---------------------
.. autoclass:: HandoverCarrierRecord
   :show-inheritance:
   :members:

Data Structures
---------------
.. autoclass:: nfc.ndef.handover.Version()
   :members:

.. autoclass:: nfc.ndef.handover.Carrier()
   :members:

.. autoclass:: nfc.ndef.handover.HandoverError()
   :members:

BluetoothConfigRecord
---------------------
.. autoclass:: BluetoothConfigRecord()
   :show-inheritance:
   :members:

WifiConfigRecord
----------------
.. autoclass:: WifiConfigRecord()
   :show-inheritance:
   :members:

WifiPasswordRecord
------------------
.. autoclass:: WifiPasswordRecord()
   :show-inheritance:
   :members:

