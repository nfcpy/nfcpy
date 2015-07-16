nfc.clf
=======

.. contents::
   :local:

.. automodule:: nfc.clf

Contactless Frontend
--------------------

.. note:: The contactless frontend defined in this module is also
          available as :class:`nfc.ContactlessFrontend`.

.. autoclass:: ContactlessFrontend
   :members:

Technology Types
----------------

.. autoclass:: RemoteTarget
   :members:
   
.. autoclass:: LocalTarget
   :members:

Exceptions
----------

.. autoexception:: Error
   :show-inheritance:

.. autoexception:: UnsupportedTargetError
   :show-inheritance:

.. autoexception:: CommunicationError
   :show-inheritance:

.. autoexception:: ProtocolError
   :show-inheritance:

.. autoexception:: TransmissionError
   :show-inheritance:

.. autoexception:: TimeoutError
   :show-inheritance:

.. autoexception:: BrokenLinkError
   :show-inheritance:

Driver Interface
----------------

.. automodule:: nfc.clf.device
   :members:

Device Drivers
--------------

rcs380
~~~~~~

.. automodule:: nfc.clf.rcs380

pn531
~~~~~

.. automodule:: nfc.clf.pn531

pn532
~~~~~

.. automodule:: nfc.clf.pn532

pn533
~~~~~

.. automodule:: nfc.clf.pn533

rcs956
~~~~~~

.. automodule:: nfc.clf.rcs956

acr122
~~~~~~

.. automodule:: nfc.clf.acr122

udp
~~~

.. automodule:: nfc.clf.udp

