Overview
========

Requirements
------------
* Python 2.6 or newer but not Python 3.x
* pyUSB and libusb (for native USB readers)
* pySerial (for serial readers on COM or USB)

Hardware
--------
These readers are supported on Linux, Windows and Mac:

* Sony RC-S330/360/370
* SCM SCL3711
* ACS ACR122U (with limitations on listen period setting)

These readers are supported on Linux (and probably Mac):

* Arygon ACS122U
* Arygon APPB US
* Stollmann NFC Reader

Implementation Status
---------------------
==================  ==================================  =========================
Owner               Specification                       Status
==================  ==================================  =========================
NFC Forum Inc.      NFC Digital Protocol 1.0            except NFC-B and Type4B
NFC Forum Inc.      NFC Activity 1.0                    except NFC-B and Type4B
NFC Forum Inc.      Type 1 Tag Operation 1.1            except dynamic memory
NFC Forum Inc.      Type 2 Tag Operation 1.1            fully supported
NFC Forum Inc.      Type 3 Tag Operation 1.1            fully supported
NFC Forum Inc.      Type 4 Tag Operation 1.0            fully supported
NFC Forum Inc.      Type 4 Tag Operation 2.0            fully supported
NFC Forum Inc.      NFC Data Exchange Format 1.0        except record chunking
NFC Forum Inc.      NFC Record Type Definition 1.0      fully supported
NFC Forum Inc.      NFC Text Record Type 1.0            fully supported
NFC Forum Inc.      NFC URI Record Type 1.0             fully supported
NFC Forum Inc.      NFC Signature Record Type 1.0       not implemented
NFC Forum Inc.      NFC Smart Poster Record Type 1.0    fully supported
NFC Forum Inc.      Logical Link Control Protocol 1.1   fully supported
NFC Forum Inc.      Simple NDEF Exchange Protocol 1.0   fully supported
NFC Forum Inc.      Connection Handover 1.2             version 1.1 record format
Google Inc.         NDEF Push Protocol                  fully supported
Bluetooth SIG       Simple Secure Pairing               out-of-band data format
Wi-Fi Alliance      Wi-Fi Simple Config                 out-of-band data format
NXP Semiconductors  AN130511 Mifare Std NDEF mapping    on wishlist
==================  ==================================  =========================

References
----------
* NFC Forum Specifications: http://www.nfc-forum.org/specs/

.. [RTD] NFC Record Type Definition (RTD) Technical Specification,
         Version 1.0, NFC Forum

.. [NDEF] NFC Data Exchange Format (NDEF)Technical Specification,
          Version 1.0, NFC Forum
