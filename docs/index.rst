##########################################
Python module for near field communication
##########################################

.. _versions: https://readthedocs.org/projects/nfcpy/versions

.. epigraph:: This documentation covers the '\ |release|\ ' version of
   **nfcpy**. There are also other `versions`_.

.. _Python: https://www.python.org
.. _EUPL: http://ec.europa.eu/idabc/eupl
.. _GitHub: https://github.com/nfcpy/nfcpy
.. _NFC Forum: http://nfc-forum.org/
.. _PyPI: https://pypi.python.org/pypi/nfcpy

The **nfcpy** module implements `NFC Forum`_ specifications for
wireless short-range data exchange with NFC devices and tags. It is
written in `Python`_ and aims to provide an easy-to-use yet powerful
framework for applications integrating NFC. The source code is
licensed under the `EUPL`_ and hosted at `GitHub`_. The latest release
version can be installed from `PyPI`_ with ``pip install -U nfcpy``.

To send a web link to a smartphone::

  import nfc
  import ndef
  from threading import Thread

  def beam(llc):
      snep_client = nfc.snep.SnepClient(llc)
      snep_client.put_records([ndef.UriRecord('http://nfcpy.org')])

  def connected(llc):
      Thread(target=beam, args=(llc,)).start()
      return True

  with nfc.ContactlessFrontend('usb') as clf:
      clf.connect(llcp={'on-connect': connected})

There are also a number of :doc:`examples/index` that can be used from
the command line: ::

  $ examples/beam.py send link http://nfcpy.org
  
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

