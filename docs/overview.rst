Overview
========

Requirements
------------

* Python 2.6 or newer but not Python 3.x
* pyUSB and libusb (for native USB readers)
* pySerial (for serial readers on COM or USB)

Installation
------------

A tarball or install package is not yet available. Installation means
to branch the repository at https://code.launchpad.net/nfcpy into a
local directory and import the nfc module or execute commands from
that directory (or add the directory to PYTHONPATH).

Installation on (Ubuntu) Linux is as easy as: ::

  $ sudo apt-get install bzr # to download from repository
  $ sudo apt-get install python-usb # for USB readers
  $ sudo apt-get install python-serial # for TTY readers
  $ cd <some-dir>
  $ bzr branch lp:nfcpy # creates a copy in ./trunk/
  $ examples/tagtool.py show # then touch a tag

Supported Hardware
------------------

These readers are supported on Linux, Windows and Mac:

* Sony RC-S330/360/380
* SCM SCL3710/11/12
* ACS ACR122U (with limitations on listen period setting)

These readers are supported on Linux (and probably Mac):

* Arygon ACS122U
* Arygon APPB US
* Stollmann NFC Reader

Notes:

* The NXP PN53x can not properly handle Type 1 Tags with dynamic
  memory layout (Topaz 512) due to a firmware bug that not allow
  READ-8 and WRITE-8 commands to be executed.
* The NXP PN531 chip does not support any Type 1 Tag command and is
  also not able to exchange Type 4 Tag commands if the ReadBinary and
  UpdateBinary commands exceed the length of a standard host
  controller frame (which may happen if the card sets ISO-DEP MIU
  as 256).

Implementation Status
---------------------

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
----------
* NFC Forum Specifications: http://www.nfc-forum.org/specs/

.. [RTD] NFC Record Type Definition (RTD) Technical Specification,
         Version 1.0, NFC Forum

.. [NDEF] NFC Data Exchange Format (NDEF)Technical Specification,
          Version 1.0, NFC Forum
