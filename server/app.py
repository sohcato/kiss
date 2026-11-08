import asyncio
import hashlib
import fcntl
import io
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import time
import warnings
import tempfile
import tomllib
import zipfile
import zlib
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timezone
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from starlette.background import BackgroundTask
from server.backup import build_backup, inspect_backup, restore_records, RESTORE_UPLOAD_LIMIT
from server.automation import install_automation
from fastapi.staticfiles import StaticFiles
from PIL import Image, UnidentifiedImageError
from pydantic import BaseModel, Field

from scripts.nmap_xml import parse_scan
from scripts.evidence import scan_text
from scripts.nmap_runner import discovery_command, run_discovery, run_zone_transfer, validate_dns, run_port_scan

ROOT = Path(__file__).resolve().parent.parent
LIMIT = 20 * 1024 * 1024


class Login(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(default='', max_length=256)


class DnsSettings(BaseModel):
    dns_server: str = Field(default='', max_length=64)
    dns_zone: str = Field(default='', max_length=253)


class Batch(DnsSettings):
    kind: str
    text: str = Field(min_length=1, max_length=100000)
    network_id: str | None = None
    discover: bool = True


class HostRename(BaseModel):
    hostname: str = Field(max_length=253)
    revision: int


class HostEdit(BaseModel):
    owner: str | None = None
    revision: int
    notes: str = Field(max_length=500000)
    status: str


class ScopeItem(BaseModel):
    host_id: str
    ports: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    revision: int = 0
    title: str = Field(min_length=1, max_length=250)
    description: str = Field(default='', max_length=500000)
    steps: str = Field(default='', max_length=500000)
    remediation: str = Field(default='', max_length=500000)
    finders: list[str]
    scope: list[ScopeItem]
    status: str = 'Draft'


class Credential(BaseModel):
    revision: int = 0
    kind: str
    username: str = Field(default='', max_length=250)
    secret: str = Field(default='', max_length=100000)
    secret_type: str = 'Password'
    domain: str = Field(default='', max_length=250)
    host_id: str | None = None
    system: str = Field(default='', max_length=500)
    service: str = Field(default='', max_length=250)
    notes: str = Field(default='', max_length=500000)
    status: str = 'Valid'
    finder: str = Field(default='', max_length=64)


def create_app(data_dir=None, users_file=None, config_file=None):
    data_dir = Path(data_dir or os.environ.get('KISS_DATA_DIR', ROOT / 'data'))
    users_file = Path(users_file or os.environ.get('KISS_USERS_FILE', ROOT / 'users.txt'))
    config_file = Path(config_file or os.environ.get('KISS_CONFIG_FILE', ROOT / 'config.toml'))
    config = tomllib.loads(config_file.read_text()) if config_file.exists() else {}
    admin_username = config.get('admin_username', '')
    if not isinstance(admin_username, str) or (admin_username and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', admin_username)):
        raise ValueError('config.toml admin_username must be a username of up to 64 letters, digits, dots, underscores or hyphens.')
    login_password = config.get('password', '')
    if not isinstance(login_password, str) or len(login_password) > 256:
        raise ValueError('config.toml password must be a string of at most 256 characters. Leave it empty to disable the shared sign-in password.')
    data_dir.mkdir(parents=True, exist_ok=True)
    jobs = set()
    discovery_slot = asyncio.Semaphore(1)
    port_scan_slot = asyncio.Semaphore(1)
    port_tasks = {}
    restoring = False
    active_requests = 0

    @asynccontextmanager
    async def lifespan(app):
        with db() as conn:
            for run in records(conn, 'automation'):
                if run.get('status') in {'Queued', 'Running'}:
                    run.update(status='Interrupted', error='Server restarted. Start a new collection.')
                    put(conn, 'automation', run)
            for network in records(conn, 'networks'):
                if network.get('discovery', {}).get('status') in {'Queued', 'Running'}:
                    activity(conn, network['discovery'].get('actor', 'System'), 'discovery interrupted', 'network', network['id'], network['name'], 'Server restarted. Retry discovery.')
                    network['discovery'] = {'status': 'Interrupted', 'message': 'Server restarted. Retry discovery.'}
                    put(conn, 'networks', network)
            for host in records(conn, 'hosts'):
                if host.get('port_scan', {}).get('status') in {'Queued', 'Running'}:
                    activity(conn, host['port_scan'].get('actor', 'System'), 'port scan interrupted', 'host', host['id'], host['hostname'] or host['address'], 'Server restarted. Run the scan again.')
                    host['port_scan'] = {'status': 'Interrupted', 'message': 'Server restarted. Run the scan again.'}
                    put(conn, 'hosts', host)
        yield
        for task in jobs:
            task.cancel()
        await asyncio.gather(*jobs, return_exceptions=True)

    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)

    @contextmanager
    def db():
        connection = sqlite3.connect(data_dir / 'kiss.sqlite3', timeout=15)
        connection.row_factory = sqlite3.Row
        connection.execute('PRAGMA foreign_keys=ON')
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    with db() as conn:
        conn.executescript('''
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS records (kind TEXT, id TEXT PRIMARY KEY, body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, expires REAL);
        CREATE TABLE IF NOT EXISTS blobs (id TEXT PRIMARY KEY, kind TEXT, mime TEXT, data BLOB);
        ''')

    def users():
        lines = users_file.read_text().splitlines() if users_file.exists() else []
        names = {line.strip() for line in lines if line.strip() and not line.lstrip().startswith('#')}
        if admin_username:
            names.add(admin_username)
        return sorted(names)

    def records(conn, kind):
        return [json.loads(r['body']) for r in conn.execute('SELECT body FROM records WHERE kind=? ORDER BY rowid', (kind,))]

    def get(conn, kind, id):
        row = conn.execute('SELECT body FROM records WHERE kind=? AND id=?', (kind, id)).fetchone()
        if row is None:
            raise HTTPException(404, 'Record not found.')
        return json.loads(row['body'])

    def put(conn, kind, value):
        conn.execute('INSERT INTO records VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET body=excluded.body', (kind, value['id'], json.dumps(value)))

    def activity(conn, actor, action, kind, target_id=None, label='', detail=''):
        put(conn, 'activity', {'id': secrets.token_hex(12), 'at': time.time(), 'actor': actor,
                              'action': action, 'kind': kind, 'target_id': target_id,
                              'label': label, 'detail': detail})

    def auth(request: Request):
        token = hashlib.sha256(request.cookies.get('kiss_session', '').encode()).hexdigest()
        with db() as conn:
            row = conn.execute('SELECT * FROM sessions WHERE token=? AND expires>?', (token, time.time())).fetchone()
        if not row or row['username'] not in users():
            raise HTTPException(401, 'Sign in with an authorized username.')
        return row['username']

    @app.middleware('http')
    async def guard(request, call_next):
        nonlocal active_requests
        if restoring and request.url.path.startswith('/api/'):
            return JSONResponse({'detail': 'Workspace restore in progress. Try again shortly.'}, status_code=503)
        if request.method not in {'GET', 'HEAD', 'OPTIONS'} and request.url.path.startswith('/api/'):
            if request.headers.get('X-Kiss-Request') != '1':
                return JSONResponse({'detail': 'Missing request header.'}, status_code=403)
        active_requests += 1
        try:
            response = await call_next(request)
        finally:
            active_requests -= 1
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'same-origin'
        response.headers['X-Frame-Options'] = 'DENY'
        if request.url.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store'
        return response

    async def body(request, limit=LIMIT):
        data = bytearray()
        async for chunk in request.stream():
            data.extend(chunk)
            if len(data) > limit:
                raise HTTPException(413, f'Upload is too large (maximum {limit // 1024 // 1024} MB).')
        return bytes(data)

    install_automation(app, db, records, get, put, auth, activity, jobs, body)

    @app.get('/api/login')
    def login_options():
        return {'password_required': bool(login_password)}

    @app.post('/api/login')
    def login(payload: Login, response: Response):
        username = payload.username.strip()
        if username not in users():
            raise HTTPException(403, 'Username is not on the server allowlist.')
        if login_password and not secrets.compare_digest(payload.password, login_password):
            raise HTTPException(403, 'Incorrect team password.')
        token = secrets.token_urlsafe(32)
        with db() as conn:
            conn.execute('DELETE FROM sessions WHERE expires<?', (time.time(),))
            conn.execute('INSERT INTO sessions VALUES (?, ?, ?)', (hashlib.sha256(token.encode()).hexdigest(), username, time.time() + 86400))
        response.set_cookie('kiss_session', token, httponly=True, samesite='strict', secure=os.environ.get('KISS_SECURE_COOKIE') == '1', max_age=86400)
        return {'username': username}

    @app.post('/api/logout')
    def logout(request: Request, response: Response):
        with db() as conn:
            conn.execute('DELETE FROM sessions WHERE token=?', (hashlib.sha256(request.cookies.get('kiss_session', '').encode()).hexdigest(),))
        response.delete_cookie('kiss_session')
        return {'ok': True}

    @app.get('/api/state')
    def state(username=Depends(auth)):
        with db() as conn:
            recent = [json.loads(row['body']) for row in conn.execute("SELECT body FROM records WHERE kind='activity' ORDER BY rowid DESC LIMIT 200")]
            return {'is_admin': bool(admin_username) and username == admin_username, 'admin_username': admin_username, 'activity': recent, 'username': username, 'users': users(), **{kind: records(conn, kind) for kind in ['networks', 'hosts', 'findings', 'scans', 'credentials']}}

    def manage_user(name, actor, remove=False):
        if not admin_username or actor != admin_username:
            raise HTTPException(403, 'Only the configured admin can manage users.')
        name = name.strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', name):
            raise HTTPException(422, 'Use 1–64 letters, digits, dots, underscores or hyphens, starting with a letter or digit.')
        if remove and name == admin_username:
            raise HTTPException(409, 'Change the admin in config.toml before removing this user.')
        try:
            # Serialize file updates across server workers and replace atomically.
            with users_file.with_suffix(users_file.suffix + '.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                names = users()
                if (name in names) != remove:
                    raise HTTPException(409 if not remove else 404, 'Username already authorized.' if not remove else 'Username not found.')
                lines = users_file.read_text().splitlines() if users_file.exists() else []
                lines = [line for line in lines if line.strip() != name] if remove else [*lines, name]
                temporary = None
                try:
                    with tempfile.NamedTemporaryFile(mode='w', dir=users_file.parent, delete=False) as handle:
                        temporary = Path(handle.name)
                        handle.write('\n'.join(lines) + '\n')
                        handle.flush()
                        os.fsync(handle.fileno())
                    temporary.replace(users_file)
                finally:
                    if temporary and temporary.exists():
                        temporary.unlink()
                with db() as conn:
                    if remove:
                        conn.execute('DELETE FROM sessions WHERE username=?', (name,))
                    activity(conn, actor, 'removed user' if remove else 'authorized user', 'user', label=name)
        except OSError as exc:
            raise HTTPException(503, 'Could not update the authorized-user file. Check server file permissions.') from exc
        return {'users': users()}

    @app.post('/api/admin/users')
    def add_user(payload: Login, username=Depends(auth)):
        return manage_user(payload.username, username)

    @app.delete('/api/admin/users/{name}')
    def remove_user(name: str, username=Depends(auth)):
        return manage_user(name, username, remove=True)

    @app.post('/api/admin/backup')
    async def backup(request: Request, username=Depends(auth)):
        if not admin_username or username != admin_username:
            raise HTTPException(403, 'Only the configured admin can download a full backup.')
        try:
            client_state = json.loads(await body(request))
            if not isinstance(client_state, dict):
                raise ValueError()
            for storage in ('session', 'local'):
                entries = client_state.get(storage, {})
                if not isinstance(entries, dict) or any(not isinstance(k, str) or not k.startswith('kiss:') or not isinstance(v, str) for k, v in entries.items()):
                    raise ValueError()
            client_state = {key: client_state.get(key, {}) for key in ('session', 'local')}
        except (ValueError, TypeError):
            raise HTTPException(422, 'Invalid browser backup data.')
        directory = tempfile.TemporaryDirectory(prefix='kiss-backup-')
        created = datetime.now(timezone.utc)
        def generate():
            with users_file.with_suffix(users_file.suffix + '.lock').open('a') as lock:
                fcntl.flock(lock, fcntl.LOCK_SH)
                users_text = users_file.read_text() if users_file.exists() else ''
                # Require the archived admin setting to match the running server.
                config_text = config_file.read_text() if config_file.exists() else ''
                parsed = tomllib.loads(config_text)
                if parsed.get('admin_username', '') != admin_username:
                    raise ValueError('Admin config changed on disk. Restart the backend before taking a backup.')
                return build_backup(ROOT, data_dir, users_text, config_text, client_state, directory.name, created.isoformat())
        try:
            # Finish archive generation before serving it; a disconnect cannot orphan the temp directory.
            generation = asyncio.create_task(asyncio.to_thread(generate))
            try:
                archive = await asyncio.shield(generation)
            except asyncio.CancelledError:
                # A worker thread cannot be cancelled; let it finish before deleting its files.
                try:
                    await generation
                finally:
                    directory.cleanup()
                raise
        except (OSError, ValueError, sqlite3.Error) as exc:
            directory.cleanup()
            raise HTTPException(503, f'Could not generate backup: {str(exc)[:200]}') from exc
        except BaseException:
            directory.cleanup()
            raise
        return FileResponse(archive, media_type='application/zip', filename=f'kiss-backup-{created.strftime("%Y%m%dT%H%M%SZ")}.zip',
                            background=BackgroundTask(directory.cleanup))

    @app.post('/api/admin/restore')
    async def restore_backup(request: Request, username=Depends(auth)):
        nonlocal restoring
        if not admin_username or username != admin_username:
            raise HTTPException(403, 'Only the configured admin can restore a workspace.')
        payload = await body(request, limit=RESTORE_UPLOAD_LIMIT)
        with tempfile.TemporaryDirectory(prefix='kiss-restore-') as directory:
            try:
                preview = inspect_backup(payload, directory)
            except (ValueError, TypeError, KeyError, sqlite3.Error, zipfile.BadZipFile, RuntimeError, EOFError, zlib.error) as exc:
                raise HTTPException(422, f'Invalid workspace backup: {str(exc)[:180]}') from exc
            confirmation = request.headers.get('X-Kiss-Restore-Confirm')
            if not confirmation:
                return preview
            if confirmation != preview['sha256']:
                raise HTTPException(409, 'Backup changed. Review it again before restoring.')
            if any(not task.done() for task in jobs):
                raise HTTPException(409, 'Finish or cancel running scans, discovery, and automation before restoring.')
            if active_requests > 1:
                raise HTTPException(409, 'Another request is in progress. Try restoring again in a moment.')
            restoring = True
            try:
                # Keep the running admin/config and never execute code from an uploaded archive.
                with users_file.with_suffix(users_file.suffix + '.lock').open('a') as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    original_users = users_file.read_text() if users_file.exists() else ''
                    original_config = config_file.read_text() if config_file.exists() else ''
                    recovery = build_backup(ROOT, data_dir, original_users, original_config, {}, directory, datetime.now(timezone.utc).isoformat())
                    recovery_path = data_dir / f'pre-restore-{time.time_ns()}.zip'
                    # Copy across filesystems before the atomic rename within data_dir.
                    recovery_temp = recovery_path.with_suffix('.tmp')
                    try:
                        recovery_temp.write_bytes(recovery.read_bytes())
                        recovery_temp.replace(recovery_path)
                    finally:
                        recovery_temp.unlink(missing_ok=True)
                    def write_users(text):
                        with tempfile.NamedTemporaryFile(mode='w', dir=users_file.parent, delete=False) as output:
                            temporary = Path(output.name)
                            output.write(text)
                        try:
                            temporary.replace(users_file)
                        finally:
                            temporary.unlink(missing_ok=True)
                    try:
                        with db() as conn:
                            conn.execute('BEGIN IMMEDIATE')
                            restore_records(conn, Path(directory) / 'restore.sqlite3')
                            write_users('\n'.join(sorted(set(preview['users']) | {admin_username})) + '\n')
                    except BaseException:
                        write_users(original_users)
                        raise
                return {'ok': True, 'recovery_file': recovery_path.name, 'admin_username': admin_username}
            except (OSError, sqlite3.Error, ValueError) as exc:
                raise HTTPException(503, f'Could not restore workspace: {str(exc)[:180]}') from exc
            finally:
                restoring = False

    def match_network(address, networks):
        try:
            ip = ipaddress.ip_address(address)
            matches = [n for n in networks if ip in ipaddress.ip_network(n['cidr'])]
            return max(matches, key=lambda n: ipaddress.ip_network(n['cidr']).prefixlen)['id'] if matches else None
        except ValueError:
            return None

    def new_host(address, hostname='', network_id=None, cloud=False):
        return {'id': secrets.token_hex(12), 'address': address, 'hostname': hostname, 'network_id': network_id,
                'cloud': cloud, 'owner': None, 'notes': '', 'status': 'Unreviewed', 'revision': 1, 'ports': [], 'scripts': [], 'reachability': 'unknown'}

    @app.post('/api/scope')
    async def batch(payload: Batch, username=Depends(auth)):
        if payload.kind not in {'network', 'host', 'cloud'}:
            raise HTTPException(422, 'Choose networks, hosts, or cloud hosts.')
        try:
            dns_server, dns_zone = validate_dns(payload.dns_server, payload.dns_zone)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        parsed = []
        for index, line in enumerate(payload.text.splitlines(), 1):
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            parts = line.replace(',', ' ', 1).split(maxsplit=1)
            address, label = parts[0], parts[1].strip() if len(parts) > 1 else ''
            try:
                if payload.kind == 'network':
                    address = str(ipaddress.ip_network(address, strict=False))
                else:
                    try:
                        address = str(ipaddress.ip_address(address))
                    except ValueError:
                        if re.fullmatch(r'[\d.]+', address) or not re.fullmatch(r'(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?', address):
                            raise ValueError()
                        address = address.lower()
                parsed.append((address, label))
            except ValueError:
                raise HTTPException(422, f'Line {index}: invalid {payload.kind} address.')
        if not parsed:
            raise HTTPException(422, 'Enter at least one scope item.')
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            networks = records(conn, 'networks')
            if payload.network_id and payload.network_id not in {n['id'] for n in networks}:
                raise HTTPException(422, 'Network not found.')
            hosts = records(conn, 'hosts')
            count = 0
            added_networks = []
            for address, label in parsed:
                if payload.kind == 'network':
                    if any(n['cidr'] == address for n in networks):
                        continue
                    network = {'id': secrets.token_hex(12), 'cidr': address, 'name': label or address, 'dns_server': dns_server, 'dns_zone': dns_zone}
                    networks.append(network)
                    added_networks.append(network)
                    put(conn, 'networks', network)
                else:
                    if any(h['address'] == address for h in hosts):
                        continue
                    host = new_host(address, label, payload.network_id or match_network(address, networks), payload.kind == 'cloud')
                    hosts.append(host)
                    put(conn, 'hosts', host)
                count += 1
            for host in hosts:
                if not host['cloud'] and not host['network_id']:
                    host['network_id'] = match_network(host['address'], networks)
                    put(conn, 'hosts', host)
            if count:
                activity(conn, username, 'added scope', 'scope', label=f'{count} {payload.kind} entries')
        if payload.discover:
            for network in added_networks:
                queue_discovery(network['id'], username)
        return {'added': count}

    def ingest_scan(raw, username, discovered=False, target_host_id=None):
        try:
            incoming, scanned_at = parse_scan(raw, allow_empty=discovered)
        except Exception as exc:
            raise HTTPException(422, f'Could not read Nmap XML: {str(exc)[:200]}')
        digest = hashlib.sha256(raw).hexdigest()
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if conn.execute('SELECT 1 FROM blobs WHERE id=?', (digest,)).fetchone():
                return {'duplicate': True, 'hosts': 0}
            networks, hosts = records(conn, 'networks'), records(conn, 'hosts')
            for entry in incoming:
                if discovered and entry['reachability'] != 'up':
                    continue
                host = next((h for h in hosts if h['id'] == target_host_id), None) if target_host_id else next((h for h in hosts if h['address'] == entry['address'] or (entry['hostname'] and h['address'].lower() == entry['hostname'].lower())), None)
                if host is None:
                    host = new_host(entry['address'], entry['hostname'], match_network(entry['address'], networks))
                    hosts.append(host)
                if host['address'] != entry['address']:
                    host['hostname'] = host['hostname'] or host['address']
                    host['address'] = entry['address']
                if not host.get('hostname_manual'):
                    host['hostname'] = host['hostname'] or entry['hostname']
                if scanned_at >= host.get('scanned_at', ''):
                    host['reachability'] = entry['reachability']
                    host['scanned_at'] = scanned_at
                    host['scripts'] = entry['scripts'] or host['scripts']
                    if entry.get('os'):
                        host['os'] = {**entry['os'], 'scan_id': digest, 'scanned_at': scanned_at}
                if entry.get('port_scanned') and scanned_at >= host.get('port_scanned_at', ''):
                    host['port_scanned_at'] = scanned_at
                    host['port_scan_id'] = digest
                # Update only explicit observations. Missing ports in partial scans are not closed ports.
                by_port = {(p['port'], p['protocol']): p for p in host['ports']}
                for port in entry['ports']:
                    key = (port['port'], port['protocol'])
                    if key not in by_port or scanned_at >= by_port[key]['scanned_at']:
                        by_port[key] = {**port, 'scan_id': digest}
                host['ports'] = sorted(by_port.values(), key=lambda p: (p['port'], p['protocol']))
                host['revision'] += 1
                put(conn, 'hosts', host)
            conn.execute('INSERT INTO blobs VALUES (?, ?, ?, ?)', (digest, 'scan', 'application/xml', raw))
            put(conn, 'scans', {'id': digest, 'scanned_at': scanned_at, 'imported_at': time.time(), 'finder': username, 'hosts': len(incoming)})
            if not discovered and not target_host_id:
                activity(conn, username, 'imported a scan', 'scope', label=f'{len(incoming)} hosts')
        return {'hosts': len(incoming), 'duplicate': False}

    @app.post('/api/import')
    async def import_scan(request: Request, username=Depends(auth)):
        return ingest_scan(await body(request), username)

    def discovery_status(network_id, status, message, **extra):
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            network = get(conn, 'networks', network_id)
            previous = network.get('discovery', {})
            actor = extra.pop('actor', previous.get('actor', 'System'))
            network['discovery'] = {'status': status, 'message': message, 'actor': actor, **extra}
            if status != previous.get('status'):
                activity(conn, actor, f'discovery {status.lower()}', 'network', network_id, network['name'], message)
            put(conn, 'networks', network)

    def ingest_zone(entries, raw, network_id, username, dns_server, dns_zone):
        digest = hashlib.sha256(raw).hexdigest()
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            hosts = records(conn, 'hosts')
            for entry in entries:
                host = next((h for h in hosts if h['address'] == entry['address']), None)
                if host is None:
                    host = new_host(entry['address'], network_id=network_id)
                    hosts.append(host)
                names = [entry['hostname'], *entry['aliases']]
                if not host.get('hostname_manual'):
                    host['hostname'] = host['hostname'] or names[0]
                host['aliases'] = sorted(set(host.get('aliases', []) + names) - {host['hostname']})
                host['dns_source'] = {'server': dns_server, 'zone': dns_zone, 'scan_id': digest}
                host['revision'] += 1
                put(conn, 'hosts', host)
            conn.execute('INSERT OR IGNORE INTO blobs VALUES (?, ?, ?, ?)', (digest, 'scan', 'application/xml', raw))
            put(conn, 'scans', {'id': digest, 'scanned_at': datetime.now(timezone.utc).isoformat(),
                               'imported_at': time.time(), 'finder': username, 'hosts': len(entries), 'source': 'DNS zone transfer'})

    async def discover(network_id, cidr, username, dns_server='', dns_zone=''):
        dns_message = ''
        try:
            async with discovery_slot:
                if dns_server and dns_zone:
                    discovery_status(network_id, 'Running', f'Trying zone transfer for {dns_zone}…')
                    try:
                        entries, zone_raw = await run_zone_transfer(cidr, dns_server, dns_zone)
                        ingest_zone(entries, zone_raw, network_id, username, dns_server, dns_zone)
                        dns_message = f'Zone transfer added or matched {len(entries)} in-scope addresses. '
                        reverse_dns = ''
                    except (ValueError, OSError) as exc:
                        dns_message = f'Zone transfer unavailable ({str(exc)[:160]}). Used reverse DNS instead. '
                        reverse_dns = dns_server
                else:
                    reverse_dns = dns_server
                    if dns_server:
                        dns_message = 'Used reverse DNS (no zone supplied). '
                discovery_status(network_id, 'Running', dns_message.replace('Used reverse DNS', 'Using reverse DNS') + 'Discovering hosts from the server…')
                raw = await run_discovery(cidr, reverse_dns) if reverse_dns else await run_discovery(cidr)
                incoming, _ = parse_scan(raw, allow_empty=True)
                count = sum(host['reachability'] == 'up' for host in incoming)
                ingest_scan(raw, username, discovered=True)
                discovery_status(network_id, 'Complete', dns_message + f'{count} responding hosts found. Nonresponding hosts may still be online.', finished_at=time.time())
        except asyncio.CancelledError:
            discovery_status(network_id, 'Interrupted', 'Server stopped. Retry discovery.')
            raise
        except Exception as exc:
            message = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
            discovery_status(network_id, 'Failed', (dns_message + message)[:600])

    def queue_discovery(network_id, username):
        with db() as conn:
            network = get(conn, 'networks', network_id)
        if network.get('discovery', {}).get('status') in {'Queued', 'Running'}:
            return
        try:
            discovery_command(network['cidr'])
            if len(jobs) >= 16:
                raise ValueError('Discovery queue is full. Retry when another subnet finishes.')
        except ValueError as exc:
            discovery_status(network_id, 'Not started', str(exc), actor=username)
            return
        discovery_status(network_id, 'Queued', 'Waiting for discovery. One subnet runs at a time.', actor=username)
        task = asyncio.create_task(discover(network_id, network['cidr'], username, network.get('dns_server', ''), network.get('dns_zone', '')))
        jobs.add(task)
        task.add_done_callback(jobs.discard)

    @app.put('/api/networks/{id}/dns')
    async def update_dns(id: str, payload: DnsSettings, username=Depends(auth)):
        try:
            server, zone = validate_dns(payload.dns_server, payload.dns_zone)
        except ValueError as exc:
            raise HTTPException(422, str(exc))
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            network = get(conn, 'networks', id)
            if network.get('discovery', {}).get('status') in {'Queued', 'Running'}:
                raise HTTPException(409, 'Wait for the current discovery to finish before changing DNS settings.')
            activity(conn, username, 'updated DNS settings', 'network', id, network['name'])
            network.update(dns_server=server, dns_zone=zone)
            put(conn, 'networks', network)
        return network

    @app.post('/api/networks/{id}/discover')
    async def retry_discovery(id: str, username=Depends(auth)):
        queue_discovery(id, username)
        return {'ok': True}

    def port_status(host_id, status, message, **extra):
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            host = get(conn, 'hosts', host_id)
            previous = host.get('port_scan', {})
            actor = extra.pop('actor', previous.get('actor', 'System'))
            host['port_scan'] = {'status': status, 'message': message, 'actor': actor, **extra}
            if status != previous.get('status'):
                activity(conn, actor, f'port scan {status.lower()}', 'host', host_id, host['hostname'] or host['address'], message)
            put(conn, 'hosts', host)

    def port_progress(host_id, progress):
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            host = get(conn, 'hosts', host_id)
            if host.get('port_scan', {}).get('status') != 'Running':
                return
            host['port_scan'].update(progress, progress_at=time.time())
            put(conn, 'hosts', host)

    async def scan_host(host_id, address, username):
        try:
            async with port_scan_slot:
                port_status(host_id, 'Running', 'Scanning all TCP ports, service versions, and default scripts…', started_at=time.time())
                raw, target = await run_port_scan(address, on_progress=lambda progress: port_progress(host_id, progress))
                incoming, _ = parse_scan(raw)
                if len(incoming) != 1 or incoming[0]['address'] != target:
                    raise ValueError('Scan output did not match the selected host. No results imported.')
                ingest_scan(raw, username, target_host_id=host_id)
                count = sum(p['state'] == 'open' for p in incoming[0]['ports'])
                port_status(host_id, 'Complete', f'{count} open TCP ports found on {target}. Results imported.', finished_at=time.time())
        except asyncio.CancelledError:
            port_status(host_id, 'Cancelled', 'Scan stopped. Previous evidence was kept.')
            raise
        except Exception as exc:
            message = str(exc.detail) if isinstance(exc, HTTPException) else str(exc)
            port_status(host_id, 'Failed', message[:400])

    @app.post('/api/hosts/{id}/scan')
    async def start_port_scan(id: str, username=Depends(auth)):
        with db() as conn:
            host = get(conn, 'hosts', id)
        if id in port_tasks:
            return {'ok': True, 'already_running': True}
        if len(jobs) >= 16:
            raise HTTPException(409, 'Scan queue is full. Try again when another scan finishes.')
        port_status(id, 'Queued', 'Waiting for a port scan slot. One host runs at a time.', actor=username)
        task = asyncio.create_task(scan_host(id, host['address'], username))
        jobs.add(task)
        port_tasks[id] = task
        def finished(task):
            jobs.discard(task)
            port_tasks.pop(id, None)
        task.add_done_callback(finished)
        return {'ok': True}

    @app.post('/api/hosts/{id}/scan/cancel')
    async def cancel_port_scan(id: str, username=Depends(auth)):
        with db() as conn:
            get(conn, 'hosts', id)
        task = port_tasks.get(id)
        if task:
            with db() as conn:
                host = get(conn, 'hosts', id)
                host['port_scan']['actor'] = username
                put(conn, 'hosts', host)
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            port_status(id, 'Cancelled', 'Scan stopped. Previous evidence was kept.')
        return {'ok': True}

    @app.put('/api/hosts/{id}/hostname')
    def rename_host(id: str, payload: HostRename, username=Depends(auth)):
        name = payload.hostname.strip().rstrip('.')
        if name and not re.fullmatch(r'[A-Za-z0-9_](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?', name):
            raise HTTPException(422, 'Use a hostname containing letters, digits, dots, underscores or hyphens.')
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            host = get(conn, 'hosts', id)
            if host['revision'] != payload.revision:
                raise HTTPException(409, 'This host changed. Close this dialog and try again.')
            old_name = host['hostname'] or host['address']
            host.update(hostname=name, hostname_manual=True, revision=host['revision'] + 1)
            put(conn, 'hosts', host)
            activity(conn, username, 'renamed host', 'host', id, name or host['address'], f'Previously {old_name}')
        return host

    @app.delete('/api/hosts/{id}')
    def delete_host(id: str, revision: int, username=Depends(auth)):
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            host = get(conn, 'hosts', id)
            if host['revision'] != revision:
                raise HTTPException(409, 'This host changed. Close this dialog and try again.')
            if id in port_tasks or host.get('port_scan', {}).get('status') in {'Queued', 'Running'}:
                raise HTTPException(409, 'Cancel the port scan before deleting this host.')
            if any(n.get('discovery', {}).get('status') in {'Queued', 'Running'} for n in records(conn, 'networks')):
                raise HTTPException(409, 'Wait for host discovery to finish before deleting hosts.')
            finding_count = sum(any(item['host_id'] == id for item in f['scope']) for f in records(conn, 'findings'))
            credential_count = sum(c.get('host_id') == id for c in records(conn, 'credentials'))
            if finding_count or credential_count:
                raise HTTPException(409, f'This host is linked to {finding_count} findings and {credential_count} credentials. Update those references before deleting it.')
            conn.execute("DELETE FROM records WHERE kind='hosts' AND id=?", (id,))
            activity(conn, username, 'deleted host', 'host', id, host['hostname'] or host['address'])
        return {'ok': True}

    @app.put('/api/hosts/{id}')
    def update_host(id: str, payload: HostEdit, username=Depends(auth)):
        if payload.owner and payload.owner not in users():
            raise HTTPException(422, 'Choose an owner from the team.')
        if payload.status not in {'Unreviewed', 'Investigating', 'Reviewed'}:
            raise HTTPException(422, 'Invalid host status.')
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            host = get(conn, 'hosts', id)
            if host['revision'] != payload.revision:
                raise HTTPException(409, 'This host changed. Your draft is preserved. Reload the latest record before saving.')
            old_owner = host.get('owner')
            host.update(notes=payload.notes, status=payload.status, revision=host['revision'] + 1)
            if 'owner' in payload.model_fields_set:
                host['owner'] = payload.owner or None
            put(conn, 'hosts', host)
            owner_changed = old_owner != host.get('owner')
            activity(conn, username, 'changed owner' if owner_changed else 'updated host', 'host', id, host['hostname'] or host['address'],
                     f"Owner: {host.get('owner') or 'Unassigned'}" if owner_changed else f"Status: {host['status']}")
        return host

    def save_finding(payload, username, id=None):
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if not payload.title.strip() or not payload.scope or not payload.finders:
                raise HTTPException(422, 'Add a title, at least one host, and a finder.')
            if payload.status not in {'Draft', 'Ready'} or not set(payload.finders) <= set(users()):
                raise HTTPException(422, 'Invalid status or finder.')
            for item in payload.scope:
                host = get(conn, 'hosts', item.host_id)
                allowed = {f"{p['port']}/{p['protocol']}" for p in host['ports']}
                if not set(item.ports) <= allowed:
                    raise HTTPException(422, 'Selected port was not found on this host.')
            revision = 1
            if id:
                old = get(conn, 'findings', id)
                if old['revision'] != payload.revision:
                    raise HTTPException(409, 'This finding changed. Your draft is preserved. Reload the latest record before saving.')
                revision = old['revision'] + 1
            finding = {**payload.model_dump(), 'id': id or secrets.token_hex(12), 'revision': revision, 'updated_at': time.time()}
            put(conn, 'findings', finding)
            activity(conn, username, 'updated finding' if id else 'added finding', 'finding', finding['id'], finding['title'], finding['status'])
        return finding

    @app.post('/api/findings')
    def create_finding(payload: Finding, username=Depends(auth)):
        return save_finding(payload, username)

    @app.put('/api/findings/{id}')
    def update_finding(id: str, payload: Finding, username=Depends(auth)):
        return save_finding(payload, username, id)

    def save_credential(payload, username, id=None):
        if payload.kind not in {'domain', 'local', 'service', 'api', 'ssh', 'other'}:
            raise HTTPException(422, 'Choose a credential type.')
        if payload.status not in {'Valid', 'Unverified', 'Invalid'}:
            raise HTTPException(422, 'Choose a credential status.')
        if payload.secret_type not in {'Password', 'NTLM hash', 'Token', 'Private key', 'Other'}:
            raise HTTPException(422, 'Choose a secret type.')
        if payload.secret_type != 'Password' and not payload.secret:
            raise HTTPException(422, 'Enter the secret, or choose Password for an empty password.')
        if payload.kind in {'domain', 'local', 'service', 'ssh'} and not payload.username.strip():
            raise HTTPException(422, 'Enter the account username.')
        if payload.kind == 'domain' and not payload.domain.strip():
            raise HTTPException(422, 'Specify the domain for this account.')
        if payload.kind in {'local', 'service', 'ssh'} and not (payload.host_id or payload.system.strip()):
            raise HTTPException(422, 'Select a system or enter its hostname, address, or endpoint.')
        if payload.kind in {'service', 'api', 'other'} and not payload.service.strip():
            raise HTTPException(422, 'Specify the service or what this credential is for.')
        finder = payload.finder or username
        if finder not in users():
            raise HTTPException(422, 'Choose a finder from the team.')
        with db() as conn:
            conn.execute('BEGIN IMMEDIATE')
            if payload.host_id:
                get(conn, 'hosts', payload.host_id)
            old = get(conn, 'credentials', id) if id else None
            if old and old['revision'] != payload.revision:
                raise HTTPException(409, 'This credential changed. Your draft is kept. Load the latest version before saving.')
            value = {**payload.model_dump(), 'id': id or secrets.token_hex(12), 'revision': old['revision'] + 1 if old else 1,
                     'finder': finder, 'added_by': old['added_by'] if old else username,
                     'updated_by': username, 'updated_at': time.time()}
            # Do not strip secrets: whitespace and line breaks can be significant.
            put(conn, 'credentials', value)
            activity(conn, username, 'updated credential' if id else 'added credential', 'credential', value['id'],
                     value['username'] or value['service'], ' · '.join(filter(None, [value['domain'], value['service'], value['system'], value['status']])))
        return value

    @app.post('/api/credentials')
    def create_credential(payload: Credential, username=Depends(auth)):
        return save_credential(payload, username)

    @app.put('/api/credentials/{id}')
    def update_credential(id: str, payload: Credential, username=Depends(auth)):
        return save_credential(payload, username, id)

    @app.post('/api/attachments')
    async def upload(request: Request, username=Depends(auth)):
        raw = await body(request, 10 * 1024 * 1024)
        try:
            with warnings.catch_warnings():
                warnings.simplefilter('error', Image.DecompressionBombWarning)
                with Image.open(io.BytesIO(raw)) as image:
                    if image.format not in {'PNG', 'JPEG', 'WEBP', 'GIF'} or image.width * image.height > 25000000:
                        raise ValueError()
                    image.load()
                    output = io.BytesIO()
                    image.convert('RGBA').save(output, 'PNG')
                    clean = output.getvalue()
        except (UnidentifiedImageError, OSError, ValueError, Image.DecompressionBombWarning, Image.DecompressionBombError):
            raise HTTPException(415, 'Paste a PNG, JPEG, WebP, or GIF image under 10 MB and 25 megapixels.')
        id = hashlib.sha256(clean).hexdigest()
        with db() as conn:
            conn.execute('INSERT OR IGNORE INTO blobs VALUES (?, ?, ?, ?)', (id, 'image', 'image/png', clean))
        return {'path': f'/api/attachments/{id}'}

    def blob(id, kind, as_text=False):
        with db() as conn:
            row = conn.execute('SELECT * FROM blobs WHERE id=? AND kind=?', (id, kind)).fetchone()
        if not row:
            raise HTTPException(404, 'File not found.')
        if as_text:
            return Response(scan_text(row['data']), media_type='text/plain', headers={'Content-Disposition': f'inline; filename="scan-{id[:8]}.txt"', 'X-Content-Type-Options': 'nosniff'})
        headers = {'Content-Disposition': f'attachment; filename="scan-{id[:8]}.xml"'} if kind == 'scan' else {}
        return Response(row['data'], media_type=row['mime'], headers=headers)

    @app.get('/api/attachments/{id}')
    def attachment(id: str, username=Depends(auth)):
        return blob(id, 'image')

    @app.get('/api/scans/{id}/text')
    def scan_evidence(id: str, username=Depends(auth)):
        return blob(id, 'scan', as_text=True)

    @app.get('/api/scans/{id}')
    def scan(id: str, username=Depends(auth)):
        return blob(id, 'scan')

    @app.get('/api/export')
    def export(username=Depends(auth)):
        with db() as conn:
            hosts = {h['id']: h for h in records(conn, 'hosts')}
            parts = ['# Findings']
            for finding in records(conn, 'findings'):
                parts.extend([f"\n## {finding['title']}", f"\nFinders: {', '.join(finding['finders'])}", '\n### Scope'])
                for item in finding['scope']:
                    host = hosts[item['host_id']]
                    parts.append(f"- {host['hostname'] or host['address']} ({host['address']}): {', '.join(item['ports']) or 'Host-wide'}")
                for label, key in [('Description', 'description'), ('Steps to reproduce', 'steps'), ('Remediation', 'remediation')]:
                    parts.extend([f'\n### {label}\n', finding[key]])
        return Response('\n'.join(parts), media_type='text/markdown', headers={'Content-Disposition': 'attachment; filename="findings.md"'})

    if (ROOT / 'dist/assets').exists():
        app.mount('/assets', StaticFiles(directory=ROOT / 'dist/assets'), name='assets')

    @app.get('/')
    @app.get('/home')
    @app.get('/scope')
    @app.get('/findings')
    @app.get('/credentials')
    @app.get('/users')
    @app.get('/cheatsheet')
    @app.get('/automation')
    def index():
        if not (ROOT / 'dist/index.html').exists():
            raise HTTPException(503, 'Build the frontend with npm run build, or use the Vite development server.')
        return FileResponse(ROOT / 'dist/index.html')

    return app


app = create_app()
