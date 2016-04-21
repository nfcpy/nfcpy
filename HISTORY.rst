Changelog for nfcpy
===================

0.11.0 (2016-04-21)
-------------------

* The main new feature of release 0.11 is the support for encrypted
  LLCP connections from the NFC Forum LLCP 1.3 Specification. The
  feature is available for Linux systems with OpenSSL crypto library
  (probably all). Encryption is automatically used if the supported by
  the peer device.

* The Python USB library has changed from PyUSB to the python-libusb
  module (pip install python-libusb). This allows to wait for a USB
  response packet and still being able to cancel with keyboard
  interrupt (which PyUSB was unfortunately blocking).

* Starting with this release the nfcpy library part (the nfc module
  but not the examples) will be uploaded to the Python Package Index
  for simple installation with 'pip install nfcpy'.
  
* The Type 2 Tag sector_select command could finally be tested with an
  NTAG I2C Tag and is now working as intended.

0.10.2 (2015-10-02)
-------------------

* Fixes an initialization issue when PN532 is connected to serial port
  on Raspberry Pi.

0.10.1 (2015-09-28)
-------------------

* Issue warning when nfc/clf/pn53x.py is atttempted to be used as a
  driver (since version 0.10 pn53x contains only an abstract base
  class, drivers are in pn531.py/pn532.py/pn533.py).

* Fixed an issue with PN532 deactivation - the chip needs additional
  time after change of serial baudrate before the next command may be
  send.

0.10.0 (2015-07-27)
-------------------

* Complete update of the tag read/write implementation to support
  features of specific tag products, such as password protection for
  Sony FeliCa Lite-S and NXP NTAG.

* Type 4B Tags (ISO Tags) are now supported. This completes support
  for all NFC Forum Tag Types.

* All contactless driver implementation is updated for generally more
  stability and an improved low-level API. The contactless frontend
  interface class and all ddrivers are now in one sub-package and emit
  debug messages with the logger "nfc.clf".

* The TTA/TTB/TTF/DEP communication types are replaced by RemoteTarget
  and LocalTarget types with enclosed communication parameters that
  allow more control of the discovery process. This change is only
  relevant for application code that has set specifc poll targets or
  implemented card emulation code, otherwise it won't be noticed.

* The contactless frontend connect() method understands some more
  options for callbacks and peer to peer communication settings.

* Serial (tty) readers can be automatically discovered by probing
  ports and drivers. On Linux, the maximum serial baudrate is checked
  and configured up to 921.6 kbaud (with a PN532). Note that automatic
  port and driver discovery may disturb other serial devices and
  should only be used if that is not a concern.
  
* New example tools use use the low-level driver API for very specific
  tasks like pure remote target discovery (with the option to do this
  repeatedly), listen to become discovered, and to simply observe when
  an external RF field is switched on and off (requires a PN531/2/3).

* The tagtool.py and beam.py tools can inspect frequently encountered
  permission problems and output targeted recommendations for solving
  them.

* Among other updates the documentation now gives more info about
  device capabilities on both the overview page as well as in the
  drivers section.

0.9.2 (2015-02-03)
------------------

* Fixes bug lp:1274973 "acr122 driver throws exception on frame length check"

0.9.1 (2014-02-13)
------------------

* Fixes bug lp:1279271 "error reading type 1 tag with more than 120 bytes"

0.9.0 (2014-01-31)
------------------

* First versioned release

