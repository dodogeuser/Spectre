import asyncio
import hashlib
import time
from types import SimpleNamespace
import pytest
from app.active.client import ActiveClient,exchange,tls_exchange,service_exchange
from app.active.policy import RunOptions,destination
from app.security.url_policy import NetworkPolicyError
from app.services.http_client import ResponseLimitError


class Limiter:
    def __init__(self):self.calls=[]
    def reserve(self,*args):self.calls.append(args);return 0
    def defer(self,*args):self.calls.append(args)


@pytest.mark.parametrize('addresses',[['127.0.0.1'],['10.0.0.1'],['169.254.169.254'],['::1'],['93.184.216.34','192.168.1.1'],[]])
def test_dns_rebinding_all_answers_checked(addresses):
    calls=[]
    client=ActiveClient('example.com',[443],lambda:None,Limiter(),resolver=lambda *a:addresses,http_transport=lambda *a:calls.append(a))
    with pytest.raises(NetworkPolicyError):asyncio.run(client.call(RunOptions(module='http',confirmed=True)))
    assert calls==[]


@pytest.mark.parametrize('kind',['large_body','large_header','compressed','stream_overflow'])
def test_real_exchange_bounds_without_network(monkeypatch,kind):
    class Response:
        status=200
        def getheaders(self):return [('Content-Type','text/html'),('X-Ignored','x'*17000)] if kind=='large_header' else [('Content-Type','text/html')]
        def getheader(self,key,default=None):return {'Content-Length':'65537' if kind=='large_body' else None,'Content-Encoding':'gzip' if kind=='compressed' else 'identity'}.get(key,default)
        def read1(self,size):return b'x'*size
    class Connection:
        sock=None
        def __init__(self,*a):pass
        def request(self,*a,**kw):assert 'Cookie' not in kw['headers'] and 'Authorization' not in kw['headers']
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr('app.active.client.PinnedHTTPConnection',Connection)
    with pytest.raises(ResponseLimitError):exchange(destination('http://example.com/','example.com',[80]),'93.184.216.34','GET',{},time.monotonic()+20,lambda:None)


def test_pinned_tcp_refusal_is_specific_negative(monkeypatch):
    seen=[]
    def refuse(address,timeout):seen.append(address);raise ConnectionRefusedError()
    monkeypatch.setattr('app.active.client.socket.create_connection',refuse)
    result=service_exchange(destination('http://example.com/','example.com',[80]),'93.184.216.34',time.monotonic()+20,lambda:None)
    assert seen==[('93.184.216.34',80)] and result['reachability']=='not_reachable'


def test_tls_failure_never_retries_unverified(monkeypatch):
    import ssl
    calls=[]
    class Raw:
        def close(self):calls.append('closed')
    class Context:
        def wrap_socket(self,raw,server_hostname):calls.append(server_hostname);raise ssl.SSLCertVerificationError('fixture invalid certificate')
    monkeypatch.setattr('app.active.client.socket.create_connection',lambda *a:Raw())
    monkeypatch.setattr('app.active.client.ssl.create_default_context',lambda:Context())
    with pytest.raises(ssl.SSLCertVerificationError):tls_exchange(destination('https://example.com/','example.com',[443]),'93.184.216.34',time.monotonic()+20,lambda:None)
    assert calls==['example.com','closed']


def test_redirect_bound_rate_limit_and_fresh_guard():
    calls=[];guards=[];limiter=Limiter()
    def redirect(dest,address,method,headers,deadline,guard):
        calls.append(dest.url);return {'url':dest.url,'headers':{'location':'/next'},'http_status':302}
    client=ActiveClient('example.com',[443],lambda:guards.append(True),limiter,resolver=lambda *a:['93.184.216.34'],http_transport=redirect)
    result=asyncio.run(client.call(RunOptions(module='http',confirmed=True)))['http']
    assert len(calls)==3 and result['availability']=='partial' and len(guards)>=9
    assert all(args[1]==2 for args in limiter.calls)


def test_malformed_transport_is_not_a_confirmed_observation():
    client=ActiveClient('example.com',[443],lambda:None,Limiter(),resolver=lambda *a:['93.184.216.34'],http_transport=lambda *a:{})
    with pytest.raises(KeyError):asyncio.run(client.call(RunOptions(module='http',confirmed=True)))
