from fastapi.testclient import TestClient
from app.main import create_app
from app.config import Settings
from tests.integration.test_accounts_cases import system,login


def test_login_rate_limit_before_database_lookup(system):
    client,factory=system
    for _ in range(10):
        assert client.post('/api/auth/login',json={'username':'owner','password':'invalid-fixture'},headers={'X-Spectre-Login':'1'}).status_code==401
    assert client.post('/api/auth/login',json={'username':'owner','password':'test-password-only'},headers={'X-Spectre-Login':'1'}).status_code==429


def test_secure_cookie_opt_in(system):
    _,factory=system
    with TestClient(create_app(Settings(_env_file=None,secure_cookies=True),factory),base_url='https://testserver') as client:
        response=client.post('/api/auth/login',json={'username':'owner','password':'test-password-only'},headers={'X-Spectre-Login':'1'})
        assert response.status_code==200
        cookie=response.headers['set-cookie'].lower()
        assert 'secure' in cookie and 'httponly' in cookie and 'samesite=strict' in cookie


def test_report_csp_not_weakened_by_default_headers(system):
    client,_=system;headers=login(client,'owner')
    case=client.post('/api/cases',json={'title':'Release fixture'},headers=headers).json()['id']
    response=client.post(f'/api/cases/{case}/reports/export',json={'format':'html'},headers=headers)
    assert response.status_code==200
    assert 'sandbox' in response.headers['content-security-policy']
    assert response.headers['cache-control']=='no-store'
