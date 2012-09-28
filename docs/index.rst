===================
nfcpy documentation
===================

The *nfcpy* module implements NFC Forum specifications for wireless short-range data exchange with NFC devices and tags. It is written in Python and aims to provide an easy-to-use, yet powerful API for Python applications.

.. note::

   The documentation is work in progress and still incomplete. Bear with
   me that this changes.

.. toctree::
   :hidden:
   :glob:

   overview
   topics/*
   examples/*

:doc:`overview`
   Hardware and software requirements, implementation status and references.

Tutorials
=========

:doc:`topics/clf`
    Find and use NFC contactless readers.

:doc:`topics/tag`
    Supported tag types and how to use them.

:doc:`topics/ndef`
    How to parse or generate NDEF records and messages.

:doc:`topics/test-tags`
    Recipes to generate tags for testing tag readers.

Examples
========

:doc:`examples/helloworld`
   A straightforward example of NDEF read and write.

:doc:`examples/tagtool`
   Read or write or format tags for NDEF use.

:doc:`examples/ndeftool`
   Generate or inspect or reorganize NDEF data.

:doc:`examples/handover-test`
   A test tool for dynamic connection handover.

Reference
=========

.. toctree::

    api/nfc
    api/ndef
    api/llcp
    api/snep
    api/handover

Indices
=======

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

