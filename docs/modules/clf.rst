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

.. autoclass:: TechnologyType
   :members:

.. autoclass:: TTA
   :show-inheritance:
   :members:

.. autoclass:: TTB
   :show-inheritance:
   :members:

.. autoclass:: TTF
   :show-inheritance:
   :members:

.. autoclass:: DEP
   :show-inheritance:
   :members:

Exceptions
----------

.. autoexception:: DigitalError
   :show-inheritance:

.. autoexception:: ProtocolError
   :show-inheritance:

.. autoexception:: TransmissionError
   :show-inheritance:

.. autoexception:: TimeoutError
   :show-inheritance:

Device Drivers
--------------

This section documents the device drivers that are supported by
nfcpy. The device drivers are used by :class:`ContactlessFrontend` to
provide the preferred interface for application code. Device driver
methods are not thread-safe and do not check arguments.

.. automodule:: nfc.clf.device
   :members:

PN53x family
~~~~~~~~~~~~

.. automodule:: nfc.clf.pn53x
   :show-inheritance:
   :members:

NXP PN531
~~~~~~~~~

.. automodule:: nfc.clf.pn531
   :show-inheritance:
   :members:

NXP PN532
~~~~~~~~~

.. automodule:: nfc.clf.pn532
   :show-inheritance:
   :members:

NXP PN533
~~~~~~~~~

.. automodule:: nfc.clf.pn533
   :show-inheritance:
   :members:

Sony RC-S956
~~~~~~~~~~~~

.. automodule:: nfc.clf.rcs956
   :show-inheritance:
   :members:

