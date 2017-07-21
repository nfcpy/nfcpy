# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import errno
import nfc.llcp.err


def test_llcp_error_class():
    err = nfc.llcp.Error(errno.EPIPE)
    assert isinstance(err, nfc.llcp.Error)
    assert isinstance(err, IOError)
    assert err.errno == errno.EPIPE
    assert str(err) == "nfc.llcp.Error: [EPIPE] Broken pipe"


def test_connect_refused():
    err = nfc.llcp.ConnectRefused(reason=1)
    assert isinstance(err, nfc.llcp.ConnectRefused)
    assert isinstance(err, nfc.llcp.Error)
    assert err.errno == errno.ECONNREFUSED
    assert err.reason == 1
    assert str(err) == ("nfc.llcp.ConnectRefused: [ECONNREFUSED] "
                        "Connection refused with reason 1")
