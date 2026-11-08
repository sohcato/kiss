import { useCallback, useEffect, useState } from 'react';
import { House, Play, BookOpen, Cloud, FileText, KeyRound, Layers, LogOut, Moon, Network, Server, Sun, UserRound } from 'lucide-react';
import { api } from './api';
import kissLogo from './assets/kiss.svg';
import Scope from './Scope';
import Home from './Home';
import UserManagement from './UserManagement';
import useRoute, { routeHref, shouldNavigate } from './useRoute';
import Findings from './Findings';
import Credentials from './Credentials';
import Cheatsheet from './Cheatsheet';
import Automation from './Automation';

function NavLink({ to, navigate, children, ...props }) {
  return <a {...props} href={routeHref(to)} onClick={event => {
    if (shouldNavigate(event)) { event.preventDefault(); navigate(to); }
  }}>{children}</a>;
}

function Login({ onLogin, expired }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [passwordRequired, setPasswordRequired] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  useEffect(() => { api('/login').then(info => setPasswordRequired(info.password_required)).catch(() => {}); }, []);
  async function submit(event) {
    event.preventDefault(); setBusy(true); setError('');
    try { await api('/login', { method: 'POST', json: { username, password } }); await onLogin(); }
    catch (err) { setError(err.message); }
    finally { setBusy(false); }
  }
  return <main className="login"><div className="login-content"><div className="wordmark"><img src={kissLogo} alt="" width="32" height="32" />KISS</div><p className="muted">Team workspace</p><h1>Pick up where<br />your team left off.</h1><p className="login-intro">Hosts, evidence, and findings.<br />One shared place for the competition.</p>
    <form onSubmit={submit}><label className="field">Username<input autoFocus autoComplete="username" required value={username} onChange={e => setUsername(e.target.value)} placeholder="Your authorized username" maxLength={64} /></label>{passwordRequired && <label className="field">Password<input type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)} placeholder="Shared team password" maxLength={256} /></label>}<button className="primary" disabled={busy}>{busy ? 'Signing in…' : 'Enter workspace'}</button>{error && <p role="alert" className="error">{error}</p>}{expired && <p className="notice">Your session ended. Sign in again; local drafts are kept in this tab.</p>}</form><p className="hint">Your server admin manages the username list.<br />For your team’s trusted LAN or VPN.</p>
  </div></main>;
}

export default function App() {
  const [state, setState] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [expired, setExpired] = useState(false);
  const [route, navigate] = useRoute();
  const page = route.page;
  const network = route.network || 'all';
  const setPage = page => navigate({ page });
  const editing = route.finding === 'new' ? 'new' : state?.findings.find(item => item.id === route.finding) || null;
  const setEditing = value => navigate({ page: 'findings', finding: value === 'new' ? 'new' : value?.id });
  const [theme, setTheme] = useState(() => { try { return localStorage.getItem('kiss:theme') || 'light'; } catch { return 'light'; } });
  const refresh = useCallback(async () => {
    try { const next = await api('/state'); setState(next); setError(''); }
    catch (err) {
      if (err.status === 401) { setState(previous => { if (previous) setExpired(true); return null; }); }
      else setError(err.message);
    } finally { setLoading(false); }
  }, []);
  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const closeDetails = event => {
      if (event.key === 'Escape' && !event.defaultPrevented && !event.isComposing && !document.querySelector('dialog[open]')) {
        document.querySelectorAll('#workspace details[open]').forEach(node => { node.open = false; });
      }
    };
    window.addEventListener('keydown', closeDetails);
    return () => window.removeEventListener('keydown', closeDetails);
  }, []);
  const activeScans = !!state && (state.networks.some(n => ['Queued', 'Running'].includes(n.discovery?.status)) || state.hosts.some(h => ['Queued', 'Running'].includes(h.port_scan?.status)));
  useEffect(() => {
    if (!state) return;
    const running = activeScans;
    const timer = setInterval(refresh, running ? 2000 : 10000);
    return () => clearInterval(timer);
  }, [!!state, activeScans, refresh]);
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try { localStorage.setItem('kiss:theme', theme); } catch { /* Theme still works without storage. */ }
  }, [theme]);
  async function logout() {
    try { await api('/logout', { method: 'POST' }); setState(null); setExpired(false); setPage('home'); }
    catch (err) { setError(err.message); }
  }
  function openActivity(event) {
    if (event.kind === 'automation') navigate({ page: 'automation', run: event.target_id });
    else if (event.kind === 'finding') navigate({ page: 'findings', finding: event.target_id });
    else if (event.kind === 'credential') navigate({ page: 'credentials', credential: event.target_id });
    else navigate({ page: 'scope', network: event.kind === 'network' ? event.target_id : null, host: event.kind === 'host' ? event.target_id : null });
  }
  function newFinding(host) {
    const key = `kiss:${state.username}:finding:new`;
    // Preserve an existing unfinished new finding and add the newly selected host.
    let draft;
    try { draft = JSON.parse(sessionStorage.getItem(key)); } catch { /* Start a new draft. */ }
    if (!draft || draft.id) draft = { title: '', description: '', steps: '', remediation: '', finders: [state.username], scope: [], status: 'Draft', revision: 0 };
    if (!draft.scope.some(item => item.host_id === host.id)) draft.scope.push({ host_id: host.id, ports: [] });
    try { sessionStorage.setItem(key, JSON.stringify(draft)); } catch { /* The passed record carries scope without storage. */ }
    setEditing('new');
  }
  if (loading) return <main className="loading" aria-label="Loading workspace"><div className="skeleton" /><div className="skeleton" /><div className="skeleton" /></main>;
  if (!state) return <><Login onLogin={refresh} expired={expired} />{error && <div role="alert" className="connection-error">Could not reach the server: {error} <button onClick={refresh}>Retry</button></div>}</>;
  return <div className="app-shell">
    <a className="skip-link" href="#workspace">Skip to workspace</a>
    <aside className="sidebar"><div className="brand"><div className="wordmark"><img src={kissLogo} alt="" width="32" height="32" />KISS</div><p>Team workspace</p></div>
      <nav aria-label="Main navigation"><NavLink navigate={navigate} className={page === 'home' ? 'nav-item active' : 'nav-item'} aria-current={page === 'home' ? 'page' : undefined} to={{ page: 'home' }}><House /> Home</NavLink><NavLink navigate={navigate} className={page === 'scope' ? 'nav-item active' : 'nav-item'} aria-current={page === 'scope' ? 'page' : undefined} to={{ page: 'scope' }}><Server /> Scope</NavLink><NavLink navigate={navigate} className={page === 'findings' ? 'nav-item active' : 'nav-item'} aria-current={page === 'findings' ? 'page' : undefined} to={{ page: 'findings' }}><FileText /> Findings</NavLink><NavLink navigate={navigate} className={page === 'credentials' ? 'nav-item active' : 'nav-item'} aria-current={page === 'credentials' ? 'page' : undefined} to={{ page: 'credentials' }}><KeyRound /> Credentials</NavLink><NavLink navigate={navigate} className={page === 'cheatsheet' ? 'nav-item active' : 'nav-item'} aria-current={page === 'cheatsheet' ? 'page' : undefined} to={{ page: 'cheatsheet' }}><BookOpen /> Cheatsheet</NavLink><NavLink navigate={navigate} className={page === 'automation' ? 'nav-item active' : 'nav-item'} aria-current={page === 'automation' ? 'page' : undefined} to={{ page: 'automation' }}><Play /> Automation</NavLink></nav>
      <nav className="network-nav" aria-label="Networks"><h2>Networks</h2><NavLink navigate={navigate} className={`nav-item ${page === 'scope' && network === 'all' ? 'current' : ''}`} to={{ page: 'scope' }}><Layers /> All hosts<span className="nav-count">{state.hosts.length}</span></NavLink>
        {state.networks.map(n => <NavLink navigate={navigate} key={n.id} className={`nav-item ${page === 'scope' && network === n.id ? 'current' : ''}`} to={{ page: 'scope', network: n.id }}><Network /><span className="network-name">{n.name}<small>{n.name === n.cidr ? '' : n.cidr}</small></span></NavLink>)}
        <NavLink navigate={navigate} className={`nav-item ${page === 'scope' && network === 'cloud' ? 'current' : ''}`} to={{ page: 'scope', network: 'cloud' }}><Cloud /> Cloud hosts</NavLink><NavLink navigate={navigate} className={`nav-item ${page === 'scope' && network === 'unassigned' ? 'current' : ''}`} to={{ page: 'scope', network: 'unassigned' }}><Server /> Unassigned</NavLink>
      </nav>
      <div className="sidebar-bottom"><button className="nav-item theme-toggle" aria-label={theme === 'light' ? 'Dark theme' : 'Light theme'} title={theme === 'light' ? 'Dark theme' : 'Light theme'} onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>{theme === 'light' ? <Moon /> : <Sun />}<span>{theme === 'light' ? 'Dark theme' : 'Light theme'}</span></button><div className="user-line"><UserRound />{state.is_admin ? <NavLink navigate={navigate} to={{ page: 'users' }} className="user-menu-button" title="Manage team users" aria-label={`Manage users (${state.username})`}>{state.username}</NavLink> : <span>{state.username}</span>}<button className="icon-button" onClick={logout} aria-label="Sign out" title={`Sign out (${state.username})`}><LogOut size={17} /></button></div></div>
    </aside>
    <div className={`workspace ${page === 'scope' ? 'scope-workspace' : ''}`} id="workspace" tabIndex={-1}>
      {error && <div className="connection-error" role="alert">Refresh failed: {error} <button onClick={refresh}>Retry</button></div>}
      {page === 'automation' ? <Automation state={state} runId={route.run} onSelect={run => navigate({ page: 'automation', run })} /> : page === 'cheatsheet' ? <Cheatsheet state={state} /> : page === 'users' ? <UserManagement state={state} refresh={refresh} onBack={() => setPage('home')} /> : page === 'home' ? <Home state={state} onOpen={openActivity} /> : page === 'scope' ? <Scope selected={route.host || null} setSelected={host => navigate({ ...route, host })} state={state} network={network} refresh={refresh} onFinding={newFinding} /> : page === 'credentials' ? <Credentials editId={route.edit} detailId={route.credential} onEdit={edit => navigate({ page: 'credentials', edit })} onDetail={credential => navigate({ page: 'credentials', credential })} state={state} refresh={refresh} /> : <Findings state={state} editing={editing} setEditing={setEditing} refresh={refresh} />}
    </div>
  </div>;
}
