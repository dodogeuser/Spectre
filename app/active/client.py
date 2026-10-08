"""Pinned, bounded active transport. Every network step requires a fresh guard."""
import asyncio
import hashlib
import http.client
import re
import socket
import ssl
import time
from datetime import datetime,timezone
from urllib.parse import urljoin,urlsplit,urlunsplit

from app.active.policy import destination
from app.security.url_policy import public_address,resolve_public,NetworkPolicyError
from app.services.http_client import bounded_call,ResponseLimitError
from app.services.reporting import clean_text
from app.version import VERSION as APP_VERSION

SELECTED=frozenset({'content-type','location','server','allow','strict-transport-security','content-security-policy','x-content-type-options','x-frame-options','referrer-policy','permissions-policy','access-control-allow-origin','access-control-allow-credentials','access-control-allow-methods','retry-after'})


def safe_url(url):
    p=urlsplit(url)
    return urlunsplit((p.scheme,p.netloc,p.path,'',''))


class PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self,dest,address,timeout):
        super().__init__(dest.host,dest.port,timeout=timeout);self.address=address
    def connect(self):self.sock=socket.create_connection((self.address,self.port),self.timeout)


def exchange(dest,address,method,headers,deadline,guard):
    guard();start=time.monotonic()
    timeout=min(5,max(.001,deadline-start))
    from app.services.http_client import PinnedHTTPSConnection
    conn=PinnedHTTPSConnection(dest,address,timeout) if dest.scheme=='https' else PinnedHTTPConnection(dest,address,timeout)
    try:
        guard()
        conn.request(method,dest.path,headers={'User-Agent':f'SPECTRE/{APP_VERSION} authorized verification','Accept':'text/html,text/plain,application/json','Accept-Encoding':'identity',**headers})
        response=conn.getresponse()
        raw_headers=response.getheaders()
        if sum(len(k)+len(v) for k,v in raw_headers)>16384:raise ResponseLimitError('Aggregate header limit')
        selected={key.lower():clean_text(value) for key,value in raw_headers if key.lower() in SELECTED}
        if any(len(value)>4096 for value in selected.values()):raise ResponseLimitError('Header limit')
        body=bytearray()
        if method=='GET' and response.status not in {301,302,303,307,308}:
            if response.getheader('Content-Encoding','identity').lower()!='identity':raise ResponseLimitError('Compressed body blocked')
            length=response.getheader('Content-Length')
            if length is not None and (not length.isdigit() or int(length)>65536):raise ResponseLimitError('Body limit')
            while True:
                guard();remaining=deadline-time.monotonic()
                if remaining<=0:raise TimeoutError('Total timeout')
                if conn.sock:conn.sock.settimeout(min(5,remaining))
                chunk=response.read1(min(8192,65537-len(body)))
                if not chunk:break
                body.extend(chunk)
                if len(body)>65536:raise ResponseLimitError('Body limit')
        content=bytes(body).decode('utf-8',errors='replace')
        # Record only bounded observations/hash, never arbitrary HTML or credentials.
        listing=bool(re.search(r'<title>\s*Index of /',content,re.I) and re.search(r'<a\s[^>]*href=',content,re.I))
        preview=clean_text(content[:512]) if dest.path.split('?')[0] in {'/robots.txt','/.well-known/security.txt'} and selected.get('content-type','').startswith('text/plain') else None
        return {'url':safe_url(dest.url),'http_status':response.status,'headers':selected,'resolved_ip':address,'elapsed_ms':round((time.monotonic()-start)*1000,3),'body_bytes':len(body),'body_sha256':hashlib.sha256(body).hexdigest(),'directory_listing_signature':listing,'text_preview':preview}
    finally:conn.close()


def tls_exchange(dest,address,deadline,guard):
    guard();start=time.monotonic()
    raw=socket.create_connection((address,443),min(5,max(.001,deadline-start)))
    try:
        guard()
        with ssl.create_default_context().wrap_socket(raw,server_hostname=dest.host) as sock:
            cert=sock.getpeercert();der=sock.getpeercert(binary_form=True)
            def name(values):return [{key:clean_text(value)[:256]} for entry in values for key,value in entry][:30]
            end=datetime.fromtimestamp(ssl.cert_time_to_seconds(cert['notAfter']),timezone.utc)
            return {'host':dest.host,'port':443,'resolved_ip':address,'fingerprint_sha256':hashlib.sha256(der).hexdigest(),'subject':name(cert.get('subject',())),'issuer':name(cert.get('issuer',())),'sans':[clean_text(v)[:256] for k,v in cert.get('subjectAltName',()) if k=='DNS'][:100],'not_before':cert['notBefore'],'not_after':cert['notAfter'],'expired_at_capture':end<datetime.now(timezone.utc),'protocol':sock.version(),'cipher':list(sock.cipher()),'certificate_verified':True,'elapsed_ms':round((time.monotonic()-start)*1000,3)}
    finally:raw.close()


def service_exchange(dest,address,deadline,guard):
    guard();start=time.monotonic()
    try:
        with socket.create_connection((address,dest.port),min(3,max(.001,deadline-start))):pass
        state='reachable';reason='TCP connection accepted; application service not inferred'
    except ConnectionRefusedError:
        state='not_reachable';reason='TCP connection refused at capture; not proof of permanent absence'
    return {'host':dest.host,'port':dest.port,'resolved_ip':address,'reachability':state,'service_identification':'not established','reason':reason,'elapsed_ms':round((time.monotonic()-start)*1000,3)}


class ActiveClient:
    def __init__(self,host,ports,guard,limiter,*,resolver=resolve_public,http_transport=exchange,tls_transport=tls_exchange,service_transport=service_exchange):
        self.host,self.ports,self.guard,self.limiter=host,ports,guard,limiter
        self.resolver,self.http_transport,self.tls_transport,self.service_transport=resolver,http_transport,tls_transport,service_transport

    async def call(self,options):
        from app.active.policy import request_url
        deadline=time.monotonic()+20
        async def checked(url,function,*args):
            self.guard();dest=destination(url,self.host,self.ports)
            addresses=await bounded_call(self.resolver,dest.host,dest.port,deadline=deadline)
            if not addresses:raise NetworkPolicyError('No addresses')
            addresses=tuple(public_address(a) for a in addresses)
            delay=self.limiter.reserve(self.host,2,deadline)
            await asyncio.sleep(delay);self.guard()
            result=await bounded_call(function,dest,addresses[0],*args,deadline,self.guard,deadline=deadline)
            self.guard();return result
        if options.module=='tls':return {'tls':await checked('https://'+self.host+'/',self.tls_transport)}
        if options.module=='service':
            rows=[]
            for port in sorted(set(options.ports)):
                try:rows.append(await checked(('https' if port==443 else 'http')+'://'+self.host+'/',self.service_transport))
                except (TimeoutError,OSError,NetworkPolicyError,ResponseLimitError):
                    if not rows:raise
                    return {'services':rows,'availability':'partial','unavailable_port':port,'limitation':'Remaining selected port could not be verified; failure is not proof of absence.'}
            return {'services':rows,'availability':'observed'}
        current=request_url(self.host,options);history=[]
        for index in range(3):
            result=await checked(current,self.http_transport,options.method,options.headers)
            if result['http_status'] in {429,503}:self.limiter.defer(self.host,60)
            if result['http_status'] not in {301,302,303,307,308}:break
            location=result['headers'].get('location','');next_url=urljoin(current,location)
            history.append({'url':safe_url(current),'status':result['http_status'],'location':safe_url(next_url)})
            try:
                next_dest=destination(next_url,self.host,self.ports)
                if urlsplit(current).scheme=='https' and next_dest.scheme!='https':raise NetworkPolicyError('HTTPS downgrade')
                if not location or index==2:raise NetworkPolicyError('Redirect bound')
            except NetworkPolicyError:
                result['scope_boundary']='Redirect not followed: destination or redirect limit outside authorized policy';break
            current=next_url
        result['redirects']=history
        if result['headers'].get('location'):result['headers']['location']=safe_url(result['headers']['location'])
        result['method']=options.method
        result['availability']='partial' if result.get('scope_boundary') else 'rate_limited' if result['http_status']==429 else 'negative_http_response' if result['http_status'] in {404,410} else 'unavailable' if result['http_status']>=500 else 'observed'
        return {'http':result}
