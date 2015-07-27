Changelog for nfcpy
===================

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

