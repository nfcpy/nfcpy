# -*- coding: utf-8 -*-
from __future__ import absolute_import, division

import pytest

import nfc.llcp.socket
import nfc.llcp.llc


def HEX(s):
    return bytearray.fromhex(s)


@pytest.fixture()
def llc(mocker):
    mocker.patch('nfc.llcp.llc.LogicalLinkController', autospec=True)
    return nfc.llcp.llc.LogicalLinkController()


@pytest.fixture(params=[
    nfc.llcp.llc.RAW_ACCESS_POINT,
    nfc.llcp.LOGICAL_DATA_LINK,
    nfc.llcp.DATA_LINK_CONNECTION,
])
def sock_type(request):
    return request.param


@pytest.fixture()
def sock(llc, sock_type):
    sock = nfc.llcp.socket.Socket(llc, sock_type)
    llc.socket.assert_called_once_with(sock_type)
    assert sock.llc is llc
    return sock


def test_resolve(sock):
    sock.llc.resolve.return_value = 'result'
    assert sock.resolve('urn:nfc:sn:svc') == 'result'
    sock.llc.resolve.assert_called_with('urn:nfc:sn:svc')
    assert sock.resolve(name='urn:nfc:sn:svc') == 'result'
    sock.llc.resolve.assert_called_with('urn:nfc:sn:svc')


def test_setsockopt(sock):
    sock.llc.getsockopt.return_value = 'result'
    sock.setsockopt('option', 'value')
    sock.llc.setsockopt.assert_called_with(sock._tco, 'option', 'value')
    sock.setsockopt(option='option', value='value')
    sock.llc.setsockopt.assert_called_with(sock._tco, 'option', 'value')


def test_getsockopt(sock):
    sock.llc.getsockopt.return_value = 'result'
    assert sock.getsockopt('option') == 'result'
    sock.llc.getsockopt.assert_called_with(sock._tco, 'option')
    assert sock.getsockopt(option='option') == 'result'
    sock.llc.getsockopt.assert_called_with(sock._tco, 'option')


def test_bind(sock):
    sock.llc.bind.return_value = 'result'
    assert sock.bind('address') == 'result'
    sock.llc.bind.assert_called_with(sock._tco, 'address')
    assert sock.bind(address='address') == 'result'
    sock.llc.bind.assert_called_with(sock._tco, 'address')


def test_connect(sock):
    sock.llc.connect.return_value = 'result'
    assert sock.connect('address') == 'result'
    sock.llc.connect.assert_called_with(sock._tco, 'address')
    assert sock.connect(address='address') == 'result'
    sock.llc.connect.assert_called_with(sock._tco, 'address')


def test_listen(sock):
    sock.llc.listen.return_value = 'result'
    assert sock.listen('backlog') == 'result'
    sock.llc.listen.assert_called_with(sock._tco, 'backlog')
    assert sock.listen(backlog='backlog') == 'result'
    sock.llc.listen.assert_called_with(sock._tco, 'backlog')


def test_accept(sock):
    sock.llc.accept.return_value = 'tco'
    assert isinstance(sock.accept(), nfc.llcp.socket.Socket)
    sock.llc.accept.assert_called_with(sock._tco)


def test_send(sock):
    sock.llc.send.return_value = 'result'
    assert sock.send('data') == 'result'
    sock.llc.send.assert_called_with(sock._tco, 'data', 0)
    assert sock.send('data', 'flags') == 'result'
    sock.llc.send.assert_called_with(sock._tco, 'data', 'flags')
    assert sock.send(data='data', flags='flags') == 'result'
    sock.llc.send.assert_called_with(sock._tco, 'data', 'flags')


def test_sendto(sock):
    sock.llc.sendto.return_value = 'result'
    assert sock.sendto('data', 'addr') == 'result'
    sock.llc.sendto.assert_called_with(sock._tco, 'data', 'addr', 0)
    assert sock.sendto('data', 'addr', 'flags') == 'result'
    sock.llc.sendto.assert_called_with(sock._tco, 'data', 'addr', 'flags')
    assert sock.sendto(data='data', addr='addr', flags='flags') == 'result'
    sock.llc.sendto.assert_called_with(sock._tco, 'data', 'addr', 'flags')


def test_recv(sock):
    sock.llc.recv.return_value = 'data'
    assert sock.recv() == 'data'
    sock.llc.recv.assert_called_with(sock._tco)


def test_recvfrom(sock):
    sock.llc.recvfrom.return_value = ('data', 'addr')
    assert sock.recvfrom() == ('data', 'addr')
    sock.llc.recvfrom.assert_called_with(sock._tco)


def test_poll(sock):
    sock.llc.poll.return_value = 'result'
    assert sock.poll('event') == 'result'
    sock.llc.poll.assert_called_with(sock._tco, 'event', None)
    assert sock.poll('event', 'timeout') == 'result'
    sock.llc.poll.assert_called_with(sock._tco, 'event', 'timeout')
    assert sock.poll(event='event', timeout='timeout') == 'result'
    sock.llc.poll.assert_called_with(sock._tco, 'event', 'timeout')


def test_getsockname(sock):
    sock.llc.getsockname.return_value = 'sockname'
    assert sock.getsockname() == 'sockname'
    sock.llc.getsockname.assert_called_with(sock._tco)


def test_getpeername(sock):
    sock.llc.getpeername.return_value = 'peername'
    assert sock.getpeername() == 'peername'
    sock.llc.getpeername.assert_called_with(sock._tco)


def test_close(sock):
    sock.llc.close.return_value = 'closed'
    assert sock.close() == 'closed'
    sock.llc.close.assert_called_with(sock._tco)
