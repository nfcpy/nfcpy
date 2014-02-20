********
Overview
********

Requirements
============

* Python 2.6 or newer but not Python 3.x
* pyUSB and libusb (for native USB readers)
* pySerial (for serial readers on COM or USB)

Supported Hardware
==================

* Sony RC-S330/360/370/380
* SCM SCL-3710/11/12
* ACS ACR122U (version 2.xx)
* Arygon APPBUS
* Stollmann NFC Reader

Notes:

* All readers are tested to work with Ubuntu Linux. Less frequently
  some are tested to work on Windows (usually the SCL3711 and
  RC-S3xx). User feedback indicates that the readers seem to work on
  Mac. Readers with serial communication protocol have not yet been
  tested on Windows.

* The Sony RC-S380 is the only reader for which *nfcpy* currently
  supports tag emulation, more specifically Type 3 Tag emulation.

* The NXP PN53x can not properly handle Type 1 Tags with dynamic
  memory layout (Topaz 512) due to a firmware bug that does not allow
  READ-8 and WRITE-8 commands to be executed.

* The NXP PN531 chip does not support any Type 1 Tag command and is
  also not able to exchange Type 4 Tag commands if the ReadBinary and
  UpdateBinary commands exceed the length of a standard host
  controller frame (which may happen if the card sets ISO-DEP MIU
  as 256).

* The ACR122U is disabled as P2P Listener because the listen time can
  not be set less than 5 seconds. Also, because the reader has an MCU
  that controls a PN532 to implement the USB CCID protocol, it is
  generally less usable for NFC P2P communication due to the MCU
  interfering with settings made directly to the PN532.

Implementation Status
=====================

====================================  =========================
Specification                         Status
====================================  =========================
TS NFC Digital Protocol 1.0           except Type B
TS NFC Activity 1.0                   except Type B
TS Type 1 Tag Operation 1.1           implemented
TS Type 2 Tag Operation 1.1           implemented
TS Type 3 Tag Operation 1.1           implemented
TS Type 4 Tag Operation 1.0           implemented
TS Type 4 Tag Operation 2.0           implemented
TS NFC Data Exchange Format 1.0       except chunking
TS NFC Record Type Definition 1.0     implemented
TS Text Record Type 1.0               implemented
TS URI Record Type 1.0                implemented
TS Smart Poster Record Type 1.0       implemented
TS Signature Record Type 1.0          not implemented
TS Logical Link Control Protocol 1.1  implemented
TS Simple NDEF Exchange Protocol 1.0  implemented
TS Connection Handover 1.2            implemented
TS Personal Health Communication 1.0  implemented
AD Bluetooth Secure Simple Pairing    implemented
====================================  =========================

References
==========

* NFC Forum Specifications: http://www.nfc-forum.org/specs/
