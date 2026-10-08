"""Pure deterministic projection of active measurements; no network or authorization grants."""
from urllib.parse import urlsplit
from app.security.url_policy import public_address


def plan(item,run):
    from app.services.correlation import canonical
    raw,p=item.raw_json,item.parsed_json
    if not isinstance(raw,dict) or raw.get('mode')!='active' or p.get('mode')!='active' or p.get('measurements')!=raw.get('measurements') or raw.get('target_id')!=run.target_id or raw.get('authorization_id')!=run.target_snapshot.get('active_authorization_id') or item.source_type!='active_'+raw.get('module','') or run.collector!=item.source_type:
        raise ValueError('Invalid active evidence provenance')
    host=run.target_snapshot['normalized_value'] if run.target_snapshot['type']=='domain' else urlsplit(run.target_snapshot['normalized_value']).hostname
    nodes,edges=set(),set()
    def node(kind,value):
        n=(kind,canonical(kind,value));nodes.add(n);return n
    def connection(value,port,service=True):
        address=public_address(value)
        root=node('domain',host);ip=node('ip',address)
        edges.add((root,ip,'active_connects_to'))
        if service:
            endpoint=node('service',f'tcp://{host}:{port}')
            edges.add((ip,endpoint,'exposes_service'));return endpoint
    measurements=p['measurements']
    if 'http' in measurements:
        h=measurements['http'];u=urlsplit(h['url'])
        if u.hostname!=host:raise ValueError('Active HTTP host mismatch')
        connection(h['resolved_ip'],443 if u.scheme=='https' else 80)
    if 'tls' in measurements:
        t=measurements['tls']
        if t['host']!=host or t['port']!=443 or t['certificate_verified'] is not True:raise ValueError('Active TLS host mismatch')
        endpoint=connection(t['resolved_ip'],443);certificate=node('certificate',t['fingerprint_sha256'])
        edges.add((endpoint,certificate,'presents_certificate'))
    for service in measurements.get('services',[]):
        if service['host']!=host or service['port'] not in {80,443}:raise ValueError('Invalid active service scope')
        connection(service['resolved_ip'],service['port'],service['reachability']=='reachable')
    return nodes,edges
