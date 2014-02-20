##########################################
Python module for near field communication
##########################################

Release v\ |version|

The **nfcpy** module implements NFC Forum specifications for wireless
short-range data exchange with NFC devices and tags. It is written in
Python and aims to provide an easy-to-use yet powerful framework for
Python applications. The software is licensed under the 
`EUPL <http://ec.europa.eu/idabc/eupl>`_.

To send a web link to a smartphone:

  >>> import nfc, nfc.snep, threading
  >>> connected = lambda llc: threading.Thread(target=llc.run).start()
  >>> uri = nfc.ndef.Message(nfc.ndef.UriRecord("http://nfcpy.org"))
  >>> clf = nfc.ContactlessFrontend('usb')
  >>> llc = clf.connect(llcp={'on-connect': connected})
  >>> nfc.snep.SnepClient(llc).put(uri)
  True
  >>> clf.close()

.. toctree::
   :maxdepth: 2

   overview
   topics/get-started
   topics/ndef
   topics/llcp
   topics/snep
   examples/index
   testing/index
   modules/index

