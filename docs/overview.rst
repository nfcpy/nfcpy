********
Overview
********

Requirements
============

* `Python`_ version 2.6 or newer (but not Python 3)
* Python `usb1`_ module to access USB devices through `libusb`_
* Python `serial`_ module to access serial (incl. FTDI) devices
* Python `docopt`_ module for some of the example programs

.. _Python: https://www.python.org
.. _usb1: https://github.com/vpelletier/python-libusb1
.. _libusb: http://libusb.info
.. _serial: http://pythonhosted.org/pyserial/
.. _docopt: https://github.com/docopt/docopt

Supported Devices
=================

The contactless devices known to be working with *nfcpy* are listed
below with the device path column showing the full *path* argument for
the :meth:`nfc.clf.ContactlessFrontend.open` method or the
``--device`` option that most example programs support. The testbed
column shows the devices that are regularly tested with *nfcpy*.

============ ========= ========= =============== ======= ========
Manufacturer Product   NFC Chip  Device Path     Testbed Notes
============ ========= ========= =============== ======= ========
Sony         RC-S330   RC-S956   usb:054c:02e1   Yes     [#hw1]_
Sony         RC-S360   RC-S956   usb:054c:02e1   Yes     [#hw1]_
Sony         RC-S370   RC-S956   usb:054c:02e1   No      [#hw1]_
Sony         RC-S380/S Port100   usb:054c:06c1   Yes     [#hw2]_
Sony         RC-S380/P Port100   usb:054c:06c3   No      [#hw2]_
Sony         Board     PN531v4.2 usb:054c:0193   Yes     [#hw3]_
Philips/NXP  Board     PN531v4.2 usb:04cc:0531   Yes     [#hw3]_
Identive     SCL3710   PN531     usb:04cc:0531   No      [#hw4]_
ACS          ACR122U   PN532v1.4 usb:072f:2200   Yes     [#hw5]_
ACS          ACR122U   PN532v1.6 usb:072f:2200   Yes     [#hw5]_
Stollmann    Reader    PN532v1.4 tty:USB0:pn532  Yes     [#hw6]_
Adafruit     Board     PN532v1.6 tty:AMA0:pn532  Yes     [#hw7]_
Identive     SCL3711   PN533v2.7 usb:04e6:5591   Yes     [#hw8]_
Identive     SCL3712   PN533     usb:04e6:5593   No      [#hw9]_
SensorID     StickID   PN533v2.7 usb:04cc:2533   Yes     [#hw10]_
Arygon       ADRA      PN531v4.2 tty:USB0:arygon Yes
============ ========= ========= =============== ======= ========

.. [#hw1] The Sony RC-S330, RC-S360, and RC-S370 are in fact identical
   devicess, the difference is only in size and thus antenna.
   
.. [#hw2] The only known difference between RC-S380/S and RC-S380/P is
   that the RC-380/S has the CE and FCC certification marks for sales
   in Europe and US.

.. [#hw3] This is a reference board that was once designed by Philips
   and Sony and has a hardware switch to select either the Philips or
   Sony USB Vendor/Product ID. The chip can only handle Type A and
   Type F technology.

.. [#hw4] This device is supported as a standard PN531. It has been
   reported to work as expected but is not part of regular testing.
      
.. [#hw5] While the ACR122U internally uses a PN532 contactless chip
   the functionality provided by a PN532 can not be fully used due to
   an additional controller that implements a USB-CCID interface (for
   PC/SC) towards the host. It is possible using PCSC_Escape commands
   to unleash some functionality but this this is not equivalent to
   directly accessing a PN532. **It is not recommended to buy this
   device for use with nfcpy.**
      
.. [#hw6] The path shown is for Ubuntu Linux in case the reader is the
   first UART/USB bridge found by the OS. Also on Windows OS the
   path is slightly different (``com:COM1:pn532``).

.. [#hw7] This is sold by Adafruit as "PN532 NFC/RFID Controller
   Breakout Board" and can directly be connected to a serial port of,
   for example, a Raspberry Pi (the device path shown is for the
   Raspberry Pi's UART, when using a USB/UART bridge it would be
   ``usb:USB0:pn532``). Note that the serial link speed is only 115200
   baud when connected at /dev/ttyAMA0 while with a USB/UART bridge it
   may be up to 921600 baud (on Linux the driver tries to figure this
   out).

.. [#hw8] The SCL3711 has a relatively small antenna that winds
   around the circuitry and may be the reason for less superior
   performance when operating as a target in passive communication
   mode (where the external field must be modulated).

.. [#hw9] The SCL3712 has been reported to work but is not available
   for regular testing.

.. [#hw10] The SensorID USB stick is a native PN533. It has no EEPROM
   attached and thus uses the default NXP Vendor/Product IDs from the
   ROM code. Absence of an EEPROM also means that the firmware uses
   default RF settings.

Functional Support
------------------   

The following table summarizes the functional support level of the
supported devices. Identical devices are aggregated under one of the
product names. Only testbed devices are covered. In the table an ``x``
means that the function is supported by hardware and software while an
``o`` means that the hardware would support but but the software not
yet implemented. More information about individual driver / hardware
restrictions can be found in the :mod:`nfc.clf` documentation.

================  === === === === ===  === === === === === === === ===
..                Tag Read/Write       Tag Emulation       Peer2Peer  
----------------  -------------------  ------------------- -----------
..                1   2   3   4A  4B   1   2   3   4A  4B  I   T   ac 
================  === === === === ===  === === === === === === === ===
RC-S380           x   x   x   x   x    ..  o   x   o   ..  x   x   .. 
RC-S956           ..  x   x   x   x    ..  o   ..  o   ..  x   x   .. 
PN533             x   x   x   x   x    ..  o   x   o   ..  x   x   x  
PN532             x   x   x   x   x    ..  o   x   o   ..  x   x   x  
PN531             ..  x   x   x   ..   ..  o   ..  o   ..  x   x   x  
ACR122U           ..  x   x   x   x    ..  ..  ..  ..  ..  x   ..  .. 
================  === === === === ===  === === === === === === === ===

General Notes
-------------   

* Testbed devices are verified to work with the latest stable nfcpy
  release. Test platforms are Ubuntu Linux (usually the latest
  version), Raspbian (with Raspberry Pi 2 Model B), and Windows
  (currently a Windows 7 virtual machine). No tests are done for MAC
  OS X because of lack of hardware.

* All device architectures with a PN532 or PN533 suffer from a
  firmware bug concerning Type 1 Tags with dynamic memory layout
  (e.g. the Topaz 512). With *nfcpy* version 0.10 this restriction
  could be removed by directly adressing the Contactless Interface
  Unit (CIU) within the chip.

* The ACR122U is not supported as P2P Target because the listen time
  can not be set to less than 5 seconds. It can not be overstated that
  the ACR122U is not a good choice for *nfcpy*.


Implementation Status
=====================

====================================  =========================
Specification                         Status
====================================  =========================
TS NFC Digital Protocol 1.1           implemented
TS NFC Activity 1.1                   implemented
TS Type 1 Tag Operation 1.2           implemented
TS Type 2 Tag Operation 1.2           implemented
TS Type 3 Tag Operation 1.2           implemented
TS Type 4 Tag Operation 3.0           implemented
TS NFC Data Exchange Format 1.0       except chunking
TS NFC Record Type Definition 1.0     implemented
TS Text Record Type 1.0               implemented
TS URI Record Type 1.0                implemented
TS Smart Poster Record Type 1.0       implemented
TS Signature Record Type              not implemented
TS Logical Link Control Protocol 1.3  implemented
TS Simple NDEF Exchange Protocol 1.0  implemented
TS Connection Handover 1.2            implemented
TS Personal Health Communication 1.0  implemented
AD Bluetooth Secure Simple Pairing    implemented
====================================  =========================

References
==========

* NFC Forum Specifications:
  http://nfc-forum.org/our-work/specifications-and-application-documents/
