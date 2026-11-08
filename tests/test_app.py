import io

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from server.app import create_app


@pytest.fixture
def client(tmp_path):
    users = tmp_path / 'users.txt'
    users.write_text('sohee\nalex\n')
    with TestClient(create_app(tmp_path / 'data', users, tmp_path / 'config.toml')) as c:
        yield c


def login(client):
    assert client.post('/api/login', json={'username': 'sohee'}, headers={'X-Kiss-Request': '1'}).status_code == 200
    client.headers['X-Kiss-Request'] = '1'


XML = b'''<nmaprun start="1700000000"><host><status state="up"/><address addr="10.20.0.10" addrtype="ipv4"/><hostnames><hostname name="dc01.corp.local"/></hostnames><ports>
<port protocol="tcp" portid="135"><state state="open"/><service name="msrpc" method="probed" conf="10"/></port>
<port protocol="tcp" portid="49664"><state state="open"/><service name="unknown" method="table"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds" method="probed"/></port>
</ports></host><runstats><finished time="1700000010" exit="success"/></runstats></nmaprun>'''


def test_auth_and_request_guard(client):
    assert client.get('/api/state').status_code == 401
    assert client.post('/api/login', json={'username': 'sohee'}).status_code == 403
    assert client.post('/api/login', json={'username': 'stranger'}, headers={'X-Kiss-Request': '1'}).status_code == 403
    login(client)
    assert client.get('/api/state').status_code == 200
    client.post('/api/logout')
    assert client.get('/api/state').status_code == 401


def test_scope_is_atomic_and_import_preserves_evidence(client):
    login(client)
    assert client.post('/api/scope', json={'kind': 'network', 'discover': False, 'text': '10.20.0.0/24 Corporate\ninvalid'}).status_code == 422
    assert client.get('/api/state').json()['networks'] == []
    assert client.post('/api/scope', json={'kind': 'network', 'discover': False, 'text': '10.20.0.0/24 Corporate'}).status_code == 200
    assert client.post('/api/import', content=XML).status_code == 200
    state = client.get('/api/state').json()
    host = state['hosts'][0]
    assert host['network_id'] == state['networks'][0]['id']
    assert host['hostname'] == 'dc01.corp.local'
    assert [p['port'] for p in host['ports'] if p['group'] == 'Microsoft RPC'] == [135]
    assert next(p for p in host['ports'] if p['port'] == 49664)['group'] == 'Other / unidentified'
    assert client.post('/api/import', content=XML).json()['duplicate'] is True
    assert len(client.get('/api/state').json()['hosts']) == 1
    assert client.get(f"/api/scans/{state['scans'][0]['id']}").content == XML


def test_findings_validate_scope_and_detect_conflicts(client):
    login(client)
    client.post('/api/import', content=XML)
    host = client.get('/api/state').json()['hosts'][0]
    finding = {'title': 'SMB configuration', 'description': '**Evidence**', 'steps': '1. Inspect', 'remediation': 'Restrict access', 'finders': ['sohee'], 'scope': [{'host_id': host['id'], 'ports': ['445/tcp']}]}
    result = client.post('/api/findings', json=finding)
    assert result.status_code == 200
    saved = result.json()
    assert client.put(f"/api/findings/{saved['id']}", json={**finding, 'revision': 1}).status_code == 200
    assert client.put(f"/api/findings/{saved['id']}", json={**finding, 'revision': 1}).status_code == 409
    finding['scope'][0]['ports'] = ['999/tcp']
    assert client.post('/api/findings', json=finding).status_code == 422


def test_images_are_validated_and_authenticated(client):
    login(client)
    assert client.post('/api/attachments', content=b'<svg onload="alert(1)"/>').status_code == 415
    image = io.BytesIO()
    Image.new('RGB', (5, 5), 'blue').save(image, 'PNG')
    result = client.post('/api/attachments', content=image.getvalue())
    assert result.status_code == 200
    path = result.json()['path']
    assert client.get(path).headers['content-type'] == 'image/png'
    client.post('/api/logout')
    assert client.get(path).status_code == 401


def test_import_rejects_entities_and_incomplete_xml(client):
    login(client)
    assert client.post('/api/import', content=b'<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><nmaprun>&x;</nmaprun>').status_code == 422
    assert client.post('/api/import', content=b'<nmaprun>').status_code == 422


def test_credential_endpoints_require_a_session(client):
    payload = {'kind': 'domain', 'domain': 'corp.local', 'username': 'alice', 'secret': 'test-only'}
    assert client.post('/api/credentials', json=payload, headers={'X-Kiss-Request': '1'}).status_code == 401
    login(client)
    saved = client.post('/api/credentials', json=payload)
    assert saved.status_code == 200
    client.post('/api/logout')
    assert client.put(f"/api/credentials/{saved.json()['id']}", json={**payload, 'revision': 1}).status_code == 401


def test_config_password_gates_login(tmp_path):
    users = tmp_path / 'users.txt'
    users.write_text('sohee\n')
    config = tmp_path / 'config.toml'
    config.write_text('password = "open-sesame"\n')
    headers = {'X-Kiss-Request': '1'}
    with TestClient(create_app(tmp_path / 'data', users, config)) as client:
        assert client.get('/api/login').json()['password_required'] is True
        assert client.post('/api/login', json={'username': 'sohee'}, headers=headers).status_code == 403
        assert client.post('/api/login', json={'username': 'sohee', 'password': 'wrong'}, headers=headers).status_code == 403
        assert client.post('/api/login', json={'username': 'sohee', 'password': 'open-sesame'}, headers=headers).status_code == 200
        assert client.get('/api/state').status_code == 200


def test_login_password_optional_when_unset(client):
    assert client.get('/api/login').json()['password_required'] is False
    assert client.post('/api/login', json={'username': 'sohee'}, headers={'X-Kiss-Request': '1'}).status_code == 200
