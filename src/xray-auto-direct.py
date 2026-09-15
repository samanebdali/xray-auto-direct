#!/usr/bin/env python3
import fcntl, ipaddress, json, os, re, shutil, socket, sqlite3, ssl, subprocess, sys, tempfile, time, urllib.parse
from pathlib import Path

ACCESS_LOG=Path('/var/log/x-ui/access.log')
STATE_DIR=Path('/var/lib/xray-auto-direct')
STATE_FILE=STATE_DIR/'state.json'
APPLY_CHANGES=os.environ.get('XRAY_AUTODIRECT_APPLY','0')=='1'
BACKUP_DIR=STATE_DIR/'backups'
ACTIVE_CFG=Path('/usr/local/x-ui/bin/config.json')
DB=Path('/etc/x-ui/x-ui.db')
PATH_STATE=Path('/run/xray-path-monitor.state')
XRAY='/usr/local/x-ui/bin/xray-linux-amd64'
WARP_PROXY='socks5h://127.0.0.1:20808'
MARK=102
MAX_PROBES=2
GOOD_COOLDOWN=1800
FAIL_COOLDOWN=20
SINGLE_HIT_DELAY=20
SINGLE_HIT_MAX_AGE=3600
CONFIRM_FAILURES=2
PROBE_TIMEOUT=3
MAX_LOG_READ=512*1024
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126 Safari/537.36'
SO_MARK=getattr(socket,'SO_MARK',36)


def log(msg):
    print(time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()), msg, flush=True)


def load_json(path, default):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def save_state(st):
    tmp=STATE_FILE.with_suffix('.tmp')
    tmp.write_text(json.dumps(st, indent=2, sort_keys=True))
    os.chmod(tmp,0o600)
    os.replace(tmp,STATE_FILE)


def iran_ranges():
    p=subprocess.run(['xt_geoip_query','-D','/usr/share/xt_geoip','-4','IR'],text=True,capture_output=True,timeout=10)
    if p.returncode:
        raise RuntimeError('cannot load IR GeoIP ranges')
    out=[]
    for ln in p.stdout.splitlines():
        if '-' not in ln: continue
        a,b=ln.strip().split('-',1)
        out.append((int(ipaddress.IPv4Address(a)),int(ipaddress.IPv4Address(b))))
    if not out: raise RuntimeError("IR GeoIP ranges empty; fail-closed")
    return sorted(out)

IR_RANGES=iran_ranges()
IR_LAST_LOAD=time.monotonic()

def refresh_iran_ranges():
    global IR_RANGES, IR_LAST_LOAD
    if time.monotonic()-IR_LAST_LOAD<60: return
    fresh=iran_ranges()
    IR_RANGES=fresh; IR_LAST_LOAD=time.monotonic()

def ip_is_ir(ip):
    try: x=int(ipaddress.IPv4Address(ip))
    except Exception: return False
    lo,hi=0,len(IR_RANGES)-1
    while lo<=hi:
        m=(lo+hi)//2; a,b=IR_RANGES[m]
        if x<a: hi=m-1
        elif x>b: lo=m+1
        else: return True
    return False


def normalize_host(h):
    h=h.strip().strip('[]').rstrip('.').lower()
    if h.startswith('tcp:') or h.startswith('udp:'): h=h[4:]
    if h.startswith('//'): h=h[2:]
    try: h=h.encode('idna').decode('ascii')
    except Exception: return None
    try:
        ipaddress.ip_address(h); return None
    except Exception: pass
    if '.' not in h or len(h)>253: return None
    if h.endswith('.ir') or h.endswith('.xn--mgba3a4f16a'): return None
    if not re.fullmatch(r'[a-z0-9._-]+',h): return None
    return h


POLICY_FILE=Path('/etc/xray-auto-direct/policy.json')
DEFAULT_WARP_SUFFIXES=('openai.com','chatgpt.com','oaistatic.com','oaiusercontent.com','cdn.auth0.com')

def policy_lists():
    """Return validated (direct, warp) suffix tuples; malformed policy fails safe."""
    try:
        raw=json.loads(POLICY_FILE.read_text())
        def clean(name):
            values=raw.get(name,[])
            if not isinstance(values,list): raise ValueError(f'{name} must be a list')
            out=[]
            for value in values:
                host=normalize_host(str(value).strip().lstrip('.'))
                if not host: raise ValueError(f'invalid suffix in {name}')
                out.append(host)
            return tuple(sorted(set(out)))
        direct=tuple(sorted(set(clean('pinned_direct_suffixes')+clean('manual_direct_suffixes'))))
        warp=clean('pinned_warp_suffixes') or DEFAULT_WARP_SUFFIXES
        overlap=set(direct)&set(warp)
        if overlap: raise ValueError('suffix in both Direct and WARP policy: '+', '.join(sorted(overlap)))
        return direct,warp
    except Exception as exc:
        log('policy invalid; using safe default WARP exclusions: '+repr(exc))
        return (),DEFAULT_WARP_SUFFIXES

def policy_pinned_suffixes():
    direct,warp=policy_lists()
    return tuple(sorted(set(direct+warp)))

def extract_accessed(st, pinned_suffixes=()):
    if not ACCESS_LOG.exists(): return []
    with ACCESS_LOG.open('rb') as f:
        stat=os.fstat(f.fileno()); inode=stat.st_ino; size=stat.st_size
        off=int(st.get('access_offset',0)) if st.get('access_inode')==inode else 0
        if off<0 or size<off: off=0
        if size-off>MAX_LOG_READ: off=max(0,size-MAX_LOG_READ)
        if off:
            f.seek(off-1)
            if f.read(1)!=b'\n':
                f.readline(max(0,size-off)+1)
                off=min(f.tell(),size)
        f.seek(off)
        data=f.read(min(MAX_LOG_READ,size-off))
        end=data.rfind(b'\n')+1
        st['access_offset']=off+end; st['access_inode']=inode
    found=[]
    for raw in data[:end].splitlines():
        ln=raw.decode('utf-8',errors='ignore')
        if ' accepted ' not in ln or '[inbound-80 -> warp]' not in ln: continue
        m=re.search(r'\baccepted\s+(?:(?:tcp|udp):|//)?([^\s\[\]]+):(\d+)\b',ln)
        if not m: continue
        host=normalize_host(m.group(1)); port=int(m.group(2))
        if host and port in (80,443) and not any(host==x or host.endswith('.'+x) for x in pinned_suffixes): found.append((host,port))
    return found


def direct_patterns(cfg):
    pats=[]
    for r in cfg.get('routing',{}).get('rules',[]):
        if r.get('outboundTag')=='direct' and isinstance(r.get('domain'),list):
            for d in r['domain']:
                if d.startswith('domain:'): pats.append(('suffix',d[7:].lower()))
                elif d.startswith('full:'): pats.append(('full',d[5:].lower()))
    return pats


def already_direct(host,pats):
    for typ,val in pats:
        if typ=='full' and host==val: return True
        if typ=='suffix' and (host==val or host.endswith('.'+val)): return True
    return False


def resolve_v4(host):
    ips=[]
    try:
        for ai in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM):
            ip=ai[4][0]
            if ip not in ips: ips.append(ip)
    except Exception: pass
    return ips


CHALLENGE_MARKERS=(
    'performing security verification','security verification','verify you are human',
    'checking your browser','just a moment','cf-chl-','challenge-platform',
    'challenges.cloudflare.com','turnstile','captcha','arkose','not a bot',
    '/cdn-cgi/challenge-platform/'
)


def warp_probe(host,port):
    scheme='https' if port==443 else 'http'; url=f'{scheme}://{host}/'
    head=['curl','-4','-sS','-o','/dev/null','-I','-L','--max-redirs','3','--proto-redir','=http,https','--proxy',WARP_PROXY,'--connect-timeout','2','--max-time',str(PROBE_TIMEOUT),'-A',UA,'-w','%{http_code}',url]
    try:
        p=subprocess.run(head,text=True,capture_output=True,timeout=PROBE_TIMEOUT+3)
        raw=p.stdout.strip(); code=int(raw[-3:]) if len(raw)>=3 and raw[-3:].isdigit() else 0
        if code==405:
            get=head.copy(); get.remove('-I'); get[get.index('-o'):get.index('-o')]=['--range','0-0']
            p=subprocess.run(get,text=True,capture_output=True,timeout=PROBE_TIMEOUT+3)
            raw=p.stdout.strip(); code=int(raw[-3:]) if len(raw)>=3 and raw[-3:].isdigit() else 0
        if not code:
            return None,'network'
        if code not in (403,429,451):
            return code,'status'

        # A policy status may be only an anti-bot interstitial that a real browser can pass.
        with tempfile.TemporaryDirectory(prefix='xray-autodirect-probe-') as td:
            hp=Path(td)/'headers'; bp=Path(td)/'body'
            get=['curl','-4','-sS','-L','--max-redirs','3','--proto-redir','=http,https','--proxy',WARP_PROXY,
                 '--connect-timeout','2','--max-time',str(PROBE_TIMEOUT),'-A',UA,
                 '-H','Accept: text/html,application/xhtml+xml,*/*;q=0.8','--range','0-32767','--max-filesize','65536',
                 '-D',str(hp),'-o',str(bp),'-w','%{http_code}',url]
            q=subprocess.run(get,text=True,capture_output=True,timeout=PROBE_TIMEOUT+3)
            raw=q.stdout.strip(); gcode=int(raw[-3:]) if len(raw)>=3 and raw[-3:].isdigit() else code
            text=''
            try: text+=hp.read_text(errors='ignore')
            except Exception: pass
            try: text+=' '+bp.read_text(errors='ignore')[:65536]
            except Exception: pass
            low=text.lower()
            if gcode and 200<=gcode<400:
                return gcode,'get_ok'
            if 'cf-mitigated: challenge' in low or any(m in low for m in CHALLENGE_MARKERS):
                return gcode or code,'challenge'
            return gcode or code,'hard_http'
    except Exception:
        return None,'network'


def marked_status(host,port):
    redirects={301,302,303,307,308}
    deadline=time.monotonic()+4.5
    def request_once(h,p,scheme,path,method):
        if time.monotonic()>=deadline: return None,None,'deadline'
        ips=resolve_v4(h)
        if not ips: return None,None,'no_ipv4'
        if any(ip_is_ir(ip) for ip in ips): return None,None,'iran_ip'
        for ip in ips[:2]:
            remaining=deadline-time.monotonic()
            if remaining<=0: return None,None,'deadline'
            s=None
            try:
                tout=max(0.5,min(1.5,remaining))
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(tout)
                s.setsockopt(socket.SOL_SOCKET,SO_MARK,MARK); s.connect((ip,p))
                if scheme=='https':
                    ctx=ssl.create_default_context(); s=ctx.wrap_socket(s,server_hostname=h); s.settimeout(tout)
                req=(f'{method} {path} HTTP/1.1\r\nHost: {h}\r\nUser-Agent: {UA}\r\nAccept: */*\r\nConnection: close\r\n'
                     + ('Range: bytes=0-0\r\n' if method=='GET' else '') + '\r\n').encode()
                s.sendall(req); data=b''
                while b'\r\n\r\n' not in data and len(data)<8192 and time.monotonic()<deadline:
                    c=s.recv(1024)
                    if not c: break
                    data+=c
                head=data.split(b'\r\n\r\n',1)[0].decode('latin1','ignore')
                lines=head.split('\r\n'); m=re.match(r'HTTP/\S+\s+(\d{3})',lines[0] if lines else '')
                if not m: continue
                headers={}
                for line in lines[1:]:
                    if ':' in line:
                        k,v=line.split(':',1); headers[k.strip().lower()]=v.strip()
                return int(m.group(1)),headers.get('location'),'ok'
            except Exception:
                pass
            finally:
                try:
                    if s: s.close()
                except Exception: pass
        return None,None,'connect_error'

    scheme='https' if port==443 else 'http'; cur_host=host; cur_port=port; path='/'
    for _ in range(3):
        if time.monotonic()>=deadline: return None,'deadline'
        code,loc,reason=request_once(cur_host,cur_port,scheme,path,'HEAD')
        if code==405:
            code,loc,reason=request_once(cur_host,cur_port,scheme,path,'GET')
        if code in redirects and loc:
            base=f'{scheme}://{cur_host}:{cur_port}{path}'
            u=urllib.parse.urlsplit(urllib.parse.urljoin(base,loc))
            if u.scheme not in ('http','https') or not u.hostname:
                return code,'ok'
            nh=normalize_host(u.hostname)
            if not nh: return code,'invalid_redirect_host'
            np=u.port or (443 if u.scheme=='https' else 80)
            if np not in (80,443): return code,'redirect_nonweb_port'
            if any(ip_is_ir(ip) for ip in resolve_v4(nh)):
                return None,'iran_ip'
            cur_host,cur_port,scheme=nh,np,u.scheme
            path=u.path or '/'
            if u.query: path+='?'+u.query
            continue
        return code,reason
    return code,'redirect_limit'

def is_warp_bad(code,kind):
    if kind in ('challenge','get_ok'): return False
    return code is None or code in (403,429,451) or code>=500


def confirm_target(code):
    return 3 if code in (403,429,451) else CONFIRM_FAILURES

def is_reserved_good(code):
    return code is not None and 200<=code<400


def sqlite_backup(src,dst):
    a=sqlite3.connect(src); b=sqlite3.connect(dst)
    try: a.backup(b)
    finally: b.close(); a.close()


API_SERVER='127.0.0.1:62789'
SHADOW_HOST='127.0.0.1'
SHADOW_PORT=20808
LOOP_INTERVAL=1.0


def shadow_ready():
    s=None
    try:
        s=socket.create_connection((SHADOW_HOST,SHADOW_PORT),timeout=0.3)
        return True
    except Exception:
        return False
    finally:
        try:
            if s: s.close()
        except Exception: pass


def shadow_warp_healthy():
    if not shadow_ready(): return False
    try:
        p=subprocess.run(['curl','-sS','--socks5-hostname',f'{SHADOW_HOST}:{SHADOW_PORT}',
                          '--connect-timeout','2','--max-time','4','https://www.cloudflare.com/cdn-cgi/trace'],
                         text=True,capture_output=True,timeout=6)
        return p.returncode==0 and ('warp=on' in p.stdout or 'warp=plus' in p.stdout)
    except Exception:
        return False


def runtime_rules_file(cfg, path):
    obj={'routing':{'rules':cfg.get('routing',{}).get('rules',[]),'balancers':cfg.get('routing',{}).get('balancers',[])}}
    path.write_text(json.dumps(obj,indent=2,ensure_ascii=False)+'\n')
    os.chmod(path,0o600)


def api_apply_rules(path):
    return subprocess.run([XRAY,'api','adrules','-s',API_SERVER,'-t','3',str(path)],
                          cwd='/usr/local/x-ui',text=True,capture_output=True,timeout=6)


def api_alive():
    p=subprocess.run([XRAY,'api','lsrules','-s',API_SERVER,'-t','2'],
                     cwd='/usr/local/x-ui',stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=4)
    return p.returncode==0


def live_add_direct(hosts):
    hosts=sorted(set(h for h in hosts if h))
    if not hosts: return True
    if not shadow_warp_healthy():
        log('v1 promotion blocked: shadow unhealthy before preparation')
        return False
    ts=time.strftime('%Y%m%d-%H%M%S',time.gmtime()); bdir=BACKUP_DIR/ts; bdir.mkdir(mode=0o700,parents=True)
    shutil.copy2(ACTIVE_CFG,bdir/'config.json'); sqlite_backup(str(DB),str(bdir/'x-ui.db'))
    tmp=ACTIVE_CFG.with_name(ACTIVE_CFG.stem+'.autodirect-v1.json')
    rt_new=STATE_DIR/'runtime-new.json'; rt_old=STATE_DIR/'runtime-old.json'
    mutated=False; live_attempted=False; db_mutated=False
    old_db_value=None; new_db_value=None
    db_mode=None; db_row_id=None
    old_pid=None
    try:
        try:
            old_pid=subprocess.check_output(['pgrep','-o','-f','^bin/xray-linux-amd64 -c bin/config.json$'],text=True,timeout=2).strip()
        except Exception: old_pid=''
        old_cfg_text=ACTIVE_CFG.read_text()
        cfg=json.loads(old_cfg_text)
        old_cfg=json.loads(json.dumps(cfg))
        target=None
        for r in cfg.get('routing',{}).get('rules',[]):
            if r.get('outboundTag')=='direct' and isinstance(r.get('domain'),list): target=r; break
        if target is None: raise RuntimeError('direct domain rule not found')
        pats=direct_patterns(cfg)
        actual=[]
        for h in hosts:
            if already_direct(h,pats): continue
            v='domain:'+h
            if v not in target['domain']:
                target['domain'].append(v); actual.append(h)
        if not actual: return True

        con=sqlite3.connect(DB)
        try:
            # Current x-ui stores routing rules in its own table; older/custom
            # deployments keep them in xrayTemplateConfig. Support both safely.
            has_rules=con.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='routing_rules'").fetchone()
            if has_rules:
                for row_id,raw in con.execute("SELECT id,raw_json FROM routing_rules ORDER BY sort,id"):
                    try: candidate=json.loads(raw)
                    except Exception: continue
                    if candidate.get('outboundTag')=='direct' and isinstance(candidate.get('domain'),list):
                        db_mode='routing_rules'; db_row_id=row_id; old_db_value=raw; dbc=candidate; break
            if db_mode is None:
                row=con.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone()
                if not row: raise RuntimeError('xrayTemplateConfig missing')
                old_db_value=row[0]; dbc=json.loads(old_db_value)
                for candidate in dbc.get('routing',{}).get('rules',[]):
                    if candidate.get('outboundTag')=='direct' and isinstance(candidate.get('domain'),list):
                        db_mode='template'; break
                else: raise RuntimeError('DB direct domain rule missing')
            dt=dbc if db_mode=='routing_rules' else candidate
            for h in actual:
                v='domain:'+h
                if v not in dt['domain']: dt['domain'].append(v)
        finally: con.close()

        tmp.write_text(json.dumps(cfg,indent=2,ensure_ascii=False)+'\n'); os.chmod(tmp,ACTIVE_CFG.stat().st_mode & 0o777)
        test=subprocess.run([XRAY,'run','-test','-c',str(tmp)],cwd='/usr/local/x-ui',text=True,capture_output=True,timeout=20)
        if test.returncode: raise RuntimeError('xray config validation failed: '+test.stderr[-500:])
        if not api_alive(): raise RuntimeError('RoutingService API unavailable before apply')
        runtime_rules_file(cfg,rt_new); runtime_rules_file(old_cfg,rt_old)

        if not shadow_warp_healthy():
            raise RuntimeError('shadow unhealthy immediately before live promotion')
        if ACTIVE_CFG.read_text()!=old_cfg_text:
            raise RuntimeError("active config changed concurrently; apply cancelled")
        os.replace(tmp,ACTIVE_CFG); mutated=True
        con=sqlite3.connect(DB)
        try:
            new_db_value=json.dumps(dbc,ensure_ascii=False)
            if db_mode=='routing_rules':
                changed=con.execute("UPDATE routing_rules SET raw_json=? WHERE id=? AND raw_json=?",(new_db_value,db_row_id,old_db_value))
            else:
                changed=con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig' AND value=?",(new_db_value,old_db_value))
            if changed.rowcount!=1:
                con.rollback(); raise RuntimeError('DB routing rule changed concurrently; apply cancelled')
            con.commit(); db_mutated=True
        finally: con.close()

        live_attempted=True
        p=api_apply_rules(rt_new)
        if p.returncode: raise RuntimeError('live routing apply failed: '+(p.stderr or p.stdout)[-500:])
        if not api_alive(): raise RuntimeError('RoutingService API unavailable after apply')
        new_pid=subprocess.check_output(['pgrep','-o','-f','^bin/xray-linux-amd64 -c bin/config.json$'],text=True,timeout=2).strip()
        if old_pid and new_pid!=old_pid: raise RuntimeError(f'production Xray PID changed {old_pid}->{new_pid}')
        if subprocess.run(['systemctl','is-active','--quiet','x-ui.service']).returncode:
            raise RuntimeError('x-ui inactive after live apply')
        log('AUTO-DIRECT-v1 LIVE add: '+', '.join(actual)+f'; pid={new_pid}; no restart')
        return True
    except Exception as exc:
        tmp.unlink(missing_ok=True)
        log('v1 promotion failed: '+repr(exc))
        if mutated:
            try:
                shutil.copy2(bdir/'config.json',ACTIVE_CFG)
                if db_mutated:
                    con=sqlite3.connect(DB)
                    try:
                        if db_mode=='routing_rules':
                            changed=con.execute("UPDATE routing_rules SET raw_json=? WHERE id=? AND raw_json=?",(old_db_value,db_row_id,new_db_value))
                        else:
                            changed=con.execute("UPDATE settings SET value=? WHERE key='xrayTemplateConfig' AND value=?",(old_db_value,new_db_value))
                        con.commit()
                        if changed.rowcount!=1: log('v1 DB rollback skipped: routing changed concurrently; manual review required')
                    finally: con.close()
                if live_attempted:
                    q=api_apply_rules(rt_old)
                    log('v1 live rollback='+('ok' if q.returncode==0 else 'FAILED'))
                else:
                    log('v1 file rollback=ok; runtime was not changed')
            except Exception as rex:
                log('v1 rollback ERROR '+repr(rex))
        return False
    finally:
        rt_new.unlink(missing_ok=True); rt_old.unlink(missing_ok=True)


def select_candidates(st, now, pats):
    retries=[]; multi=[]; singles=[]
    for h,e in st['hosts'].items():
        if already_direct(h,pats): continue
        fails=int(e.get('fails',0)); last_probe=int(e.get('last_probe',0))
        if fails>0:
            if now-last_probe>=FAIL_COOLDOWN: retries.append((last_probe,h,e))
            continue
        if now-last_probe<GOOD_COOLDOWN: continue
        hits=int(e.get('pending_hits',0)); pending_since=int(e.get('pending_since',e.get('last_seen',now)))
        if hits>=2: multi.append((int(e.get('last_seen',0)),h,e))
        elif hits==1 and SINGLE_HIT_DELAY<=now-pending_since<=SINGLE_HIT_MAX_AGE:
            singles.append((int(e.get('last_seen',0)),h,e))
    retries.sort(key=lambda x:x[0]); multi.sort(key=lambda x:x[0],reverse=True); singles.sort(key=lambda x:x[0],reverse=True)
    selected=[]
    for _,h,e in retries:
        if len(selected)>=MAX_PROBES: break
        selected.append((h,e,'retry'))
    if len(selected)<MAX_PROBES and multi:
        _,h,e=multi.pop(0); selected.append((h,e,'multi'))
    if len(selected)<MAX_PROBES and singles:
        _,h,e=singles.pop(0); selected.append((h,e,'single'))
    while len(selected)<MAX_PROBES and (multi or singles):
        lane=multi if multi else singles; _,h,e=lane.pop(0); selected.append((h,e,'multi' if lane is multi else 'single'))
    return selected


def cycle(st):
    refresh_iran_ranges()
    now=int(time.time()); cfg=json.loads(ACTIVE_CFG.read_text()); pats=direct_patterns(cfg); pinned_suffixes=policy_pinned_suffixes()
    for host,port in extract_accessed(st,pinned_suffixes):
        e=st['hosts'].setdefault(host,{'port':port,'fails':0,'last_probe':0,'last_seen':now,'pending_hits':0,'pending_since':now})
        hits=int(e.get('pending_hits',0))
        if hits<=0: e['pending_since']=now
        e['port']=port; e['last_seen']=now; e['pending_hits']=hits+1
    st['hosts']={h:e for h,e in st['hosts'].items() if now-int(e.get('last_seen',now))<30*86400 and not any(h==x or h.endswith('.'+x) for x in pinned_suffixes)}
    selected=select_candidates(st,now,pats)
    if not selected:
        save_state(st); return
    if not shadow_warp_healthy():
        log('v1 shadow WARP unhealthy; probes skipped fail-closed'); save_state(st); return
    promoted=[]
    for host,e,_lane in selected:
        port=int(e.get('port',443)); ips=resolve_v4(host)
        e['last_probe']=int(time.time()); e['pending_hits']=0; e['pending_since']=0
        if not ips: e['fails']=0; e['last']='no_ipv4'; continue
        if any(ip_is_ir(ip) for ip in ips):
            e['fails']=0; e['last']='blocked_ir_ip'; log(f'skip {host}: resolves to IR'); continue
        wc,wkind=warp_probe(host,port); rc,reason=marked_status(host,port)
        if not shadow_warp_healthy():
            e['fails']=0; e['pending_hits']=1; e['pending_since']=int(time.time())
            e['last']='shadow_unhealthy_discarded'
            for pending_host in promoted:
                st['hosts'][pending_host]['fails']=0
            log('v1 shadow unhealthy after probe; cycle discarded fail-closed')
            save_state(st); return
        e['last']=f'shadow_warp={wc}/{wkind} reserved={rc}'
        if reason=='iran_ip': e['fails']=0; continue
        if wkind=='challenge': e['fails']=0; log(f'skip challenge {host}: shadow={wc} reserved={rc}'); continue
        if is_warp_bad(wc,wkind) and is_reserved_good(rc):
            need=confirm_target(wc); e['fails']=int(e.get('fails',0))+1
            log(f'candidate {host}: shadow={wc}/{wkind} reserved={rc} confirm={e["fails"]}/{need}')
            if e['fails']>=need: promoted.append(host)
        else: e['fails']=0
    save_state(st)
    if promoted:
        promoted=sorted(set(promoted))
        if not APPLY_CHANGES:
            log('v1 DRY-RUN confirmed: '+', '.join(promoted)); return
        if not shadow_warp_healthy():
            for h in promoted: st['hosts'][h]['fails']=0
            log('v1 shadow unhealthy before promotion; candidates discarded fail-closed')
            save_state(st); return
        if live_add_direct(promoted):
            for h in promoted:
                if h in st['hosts']:
                    st['hosts'][h]['fails']=0; st['hosts'][h]['last']='promoted_direct_live'
            save_state(st)
            dirs=sorted([p for p in BACKUP_DIR.iterdir() if p.is_dir()],reverse=True)
            for old in dirs[20:]: shutil.rmtree(old,ignore_errors=True)
        else:
            log('v1 promotion rolled back')


def selftest():
    ok=True
    print('shadow_ready=',shadow_ready())
    ok &= shadow_ready()
    print('shadow_warp_healthy=',shadow_warp_healthy())
    ok &= shadow_warp_healthy()
    try:
        p=subprocess.run(['curl','-sS','--socks5-hostname',f'{SHADOW_HOST}:{SHADOW_PORT}','--connect-timeout','3','--max-time','6','https://www.cloudflare.com/cdn-cgi/trace'],text=True,capture_output=True,timeout=8)
        warp='warp=on' in p.stdout or 'warp=plus' in p.stdout
        print('shadow_trace_warp=',warp); ok &= warp
    except Exception:
        print('shadow_trace_warp=False'); ok=False
    print('routing_api=',api_alive()); ok &= api_alive()
    try:
        con=sqlite3.connect(DB); row=con.execute("SELECT value FROM settings WHERE key='xrayTemplateConfig'").fetchone(); con.close()
        a=json.loads(ACTIVE_CFG.read_text()); b=json.loads(row[0]) if row else {}
        same=direct_patterns(a)==direct_patterns(b)
        print('active_db_direct_equal=',same); ok &= same
    except Exception:
        print('active_db_direct_equal=False'); ok=False
    try:
        pid=subprocess.check_output(['pgrep','-o','-f','^bin/xray-linux-amd64 -c bin/config.json$'],text=True,timeout=2).strip()
        print('production_pid=',pid)
    except Exception: ok=False
    return 0 if ok else 2


def manual_probe(arg):
    host=arg; port=443
    if ':' in arg and arg.rsplit(':',1)[1].isdigit(): host,ps=arg.rsplit(':',1); port=int(ps)
    host=normalize_host(host)
    if not host or port not in (80,443): print('invalid host/port'); return 2
    if not shadow_warp_healthy(): print('shadow unavailable/unhealthy'); return 2
    if any(ip_is_ir(ip) for ip in resolve_v4(host)): print('blocked_ir_ip'); return 2
    wc,wkind=warp_probe(host,port); rc,reason=marked_status(host,port)
    if not shadow_warp_healthy(): print('shadow became unhealthy; result discarded'); return 2
    print(f'host={host} port={port} shadow_warp={wc}/{wkind} reserved={rc}/{reason} candidate={is_warp_bad(wc,wkind) and is_reserved_good(rc)}')
    return 0


def sync_policy_direct():
    direct,_=policy_lists()
    if not direct:
        return True
    if not APPLY_CHANGES:
        log('v1 policy Direct sync skipped in dry-run')
        return True
    log('v1 policy Direct sync requested: '+', '.join(direct))
    return live_add_direct(direct)

def main():
    STATE_DIR.mkdir(mode=0o700,parents=True,exist_ok=True); BACKUP_DIR.mkdir(mode=0o700,parents=True,exist_ok=True)
    if len(sys.argv)>=2 and sys.argv[1]=='--selftest': return selftest()
    if len(sys.argv)>=2 and sys.argv[1]=='--sync-policy': return 0 if sync_policy_direct() else 2
    if len(sys.argv)>=3 and sys.argv[1]=='--probe': return manual_probe(sys.argv[2])
    lock=open('/run/xray-auto-direct.lock','w'); fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    st=load_json(STATE_FILE,{'hosts':{}}); st.setdefault('hosts',{})
    if ACCESS_LOG.exists() and 'access_inode' not in st:
        s=ACCESS_LOG.stat(); st['access_inode']=s.st_ino; st['access_offset']=s.st_size; save_state(st)
        log('v1 initialized at access-log EOF; no historical replay')
    if not sync_policy_direct():
        log('v1 policy Direct sync failed; controller remains running fail-closed')
    last_err=''
    last_shadow_health=0.0
    shadow_bad=0
    while True:
        now_mono=time.monotonic()
        if now_mono-last_shadow_health>=60:
            last_shadow_health=now_mono
            if shadow_warp_healthy():
                if shadow_bad: log('v1 shadow WARP recovered without restart')
                shadow_bad=0
            else:
                shadow_bad+=1
                log(f'v1 shadow health failure {shadow_bad}/3')
                if shadow_bad>=3:
                    try:
                        r=subprocess.run(['systemctl','restart','xray-autodirect-shadow.service'],timeout=15)
                        time.sleep(3)
                        if r.returncode==0 and shadow_warp_healthy():
                            log('v1 shadow self-heal restart=ok')
                            shadow_bad=0
                        else:
                            log('v1 shadow self-heal restart did not restore WARP; remaining fail-closed')
                            shadow_bad=0
                    except Exception as rex:
                        log('v1 shadow self-heal ERROR '+repr(rex))
                        shadow_bad=0
        try:
            cycle(st); last_err=''
        except Exception as exc:
            msg=repr(exc)
            if msg!=last_err: log('v1 cycle ERROR '+msg); last_err=msg
        time.sleep(LOOP_INTERVAL)

if __name__=='__main__':
    try: sys.exit(main())
    except BlockingIOError: sys.exit(0)
    except KeyboardInterrupt: sys.exit(0)
    except Exception as e:
        log('v1 FATAL '+repr(e)); sys.exit(1)
