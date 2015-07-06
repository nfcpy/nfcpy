nfc.clf
=======

.. contents::
   :local:

.. automodule:: nfc.clf

Contactless Frontend
--------------------

The contactless frontend class is also imported as
:class:`nfc.ContactlessFrontend`, thus is available after ``import
nfc`` as used by the examples in this section.

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

Device Drivers
--------------

This section documents the contactless devices that are supported by
nfcpy. The device drivers are used by :class:`ContactlessFrontend` to
provide the preferred interface for application code.

.. note:: Device driver methods are not thread-safe and do not check
   input arguments that are verified by the ContaclessFrontend. The
   documentation of device driver classes and methods is not for
   applications but merely to note the various functionality
   support. Direct access to device drivers is not intended.

pn531
~~~~~

.. automodule:: nfc.clf.pn531
   :show-inheritance:
   :members:

pn532
~~~~~

.. automodule:: nfc.clf.pn532
   :show-inheritance:
   :members:

pn533
~~~~~

.. automodule:: nfc.clf.pn533
   :show-inheritance:
   :members:

rcs956
~~~~~~

.. automodule:: nfc.clf.rcs956
   :show-inheritance:
   :members:

acr122
~~~~~~

.. automodule:: nfc.clf.acr122
   :show-inheritance:
   :members:

Driver Base Classes
-------------------

device
~~~~~~

.. automodule:: nfc.clf.device
   :show-inheritance:
   :members:

pn53x
~~~~~

.. automodule:: nfc.clf.pn53x
   :show-inheritance:
   :members:

