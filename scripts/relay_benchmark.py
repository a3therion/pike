#!/usr/bin/env python3
"""Repeated release-binary loopback load measurements; not a production capacity SLA."""
import argparse, concurrent.futures, hashlib, http.client, json, os, platform, socket, statistics, subprocess, tempfile, threading, time
from pathlib import Path
from http import client as http_client
import local_tunnel_smoke as smoke
class Upstream(smoke.http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args):pass
    def do_GET(self):
        size=1024 if self.path=='/small' else 8*1024*1024
        self.send_response(200);self.send_header('Content-Length',str(size));self.end_headers()
        block=b'x'*min(size,65536)
        for _ in range(size//len(block)):self.wfile.write(block)
def percentile(samples,q):return sorted(samples)[min(len(samples)-1,int(q*len(samples)))]
def measure(port,clients,count):
    def worker(n):
        c=http_client.HTTPConnection('127.0.0.1',port,timeout=30);times=[]
        try:
            for _ in range(n):
                start=time.perf_counter();c.request('GET','/small',headers={'Host':smoke.SUBDOMAIN+'.'+smoke.DOMAIN});r=c.getresponse();body=r.read()
                if r.status!=200 or body!=b'x'*1024:raise RuntimeError(f'HTTP {r.status}, bytes={len(body)}')
                times.append((time.perf_counter()-start)*1000)
        finally:c.close()
        return times
    begin=time.perf_counter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as pool:
        groups=list(pool.map(worker,[count//clients+(i<count%clients) for i in range(clients)]))
    samples=[x for group in groups for x in group];elapsed=time.perf_counter()-begin
    return dict(requests=len(samples),seconds=elapsed,requestsPerSecond=len(samples)/elapsed,p50Ms=statistics.median(samples),p95Ms=percentile(samples,.95),p99Ms=percentile(samples,.99))
def run(transport,args):
    with tempfile.TemporaryDirectory(prefix='pike-benchmark-') as tmp,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as blackhole:
        root=Path(tmp);blackhole.bind(('127.0.0.1',0));relay=smoke.reserve_free_port(socket.SOCK_DGRAM);http=smoke.reserve_free_port()
        smoke.write_server_config(root/'server.toml',relay,http,smoke.reserve_free_port())
        with (root/'server.toml').open('a') as f:f.write('\n[abuse]\nauto_suspend_requests_per_minute = 1000000\n')
        smoke.write_client_config(root/'client.toml',relay if transport=='quic' else blackhole.getsockname()[1],smoke.reserve_free_port(),http,transport)
        upstream=smoke.ThreadingHTTPServer(('127.0.0.1',0),Upstream);threading.Thread(target=upstream.serve_forever,daemon=True).start()
        env={**os.environ,'RUST_LOG':'error','NO_COLOR':'1'};server=client=None;rss=[];done=threading.Event()
        try:
            server=smoke.start_relay(root/'server.toml',env,root/'server.log')
            smoke.wait_for_http(f'http://127.0.0.1:{http}/health',expected_status=200,headers={'Host':smoke.DOMAIN},timeout=30,process=server)
            client=smoke.start_process([str(smoke.CLI_BIN),'--config',str(root/'client.toml'),'http',str(upstream.server_port),'--subdomain',smoke.SUBDOMAIN,'--host','127.0.0.1'],env=env,log_path=root/'client.log')
            smoke.wait_for_http(f'http://127.0.0.1:{http}/small',expected_status=200,headers={'Host':smoke.SUBDOMAIN+'.'+smoke.DOMAIN},timeout=30,process=client)
            def sample_rss():
                value=subprocess.run(['ps','-o','rss=','-p',str(server.pid)],capture_output=True,text=True).stdout.strip()
                if value:rss.append(int(value)*1024)
            sample_rss()
            def monitor():
                while not done.wait(.02):
                    value=subprocess.run(['ps','-o','rss=','-p',str(server.pid)],capture_output=True,text=True).stdout.strip()
                    if value:rss.append(int(value)*1024)
            threading.Thread(target=monitor,daemon=True).start();measure(http,args.clients,8)
            samples=[measure(http,args.clients,args.requests) for _ in range(args.rounds)]
            start=time.perf_counter();c=http_client.HTTPConnection('127.0.0.1',http,timeout=30);c.request('GET','/large',headers={'Host':smoke.SUBDOMAIN+'.'+smoke.DOMAIN});r=c.getresponse();digest=hashlib.sha256();size=0
            while chunk:=r.read(65536):digest.update(chunk);size+=len(chunk)
            assert r.status==200 and size==8*1024*1024 and digest.hexdigest()==hashlib.sha256(b'x'*size).hexdigest();c.close()
            return dict(transport=transport,clients=args.clients,samples=samples,medianRequestsPerSecond=statistics.median(s['requestsPerSecond'] for s in samples),medianP95Ms=statistics.median(s['p95Ms'] for s in samples),peakRelayRssBytes=max(rss or [0]),largeDownloadBytes=size,largeDownloadSeconds=time.perf_counter()-start,failures=0)
        except Exception:
            for p in [root/'server.log',root/'client.log']:
                if p.exists():print(p.read_text()[-3000:])
            raise
        finally:
            done.set();smoke.stop_process(client,'benchmark client');smoke.stop_process(server,'benchmark relay');upstream.shutdown();upstream.server_close()
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--requests', type=int, default=64)
    parser.add_argument('--rounds', type=int, default=3)
    parser.add_argument('--clients', type=int, default=8)
    parser.add_argument('--before-bin-dir', type=Path)
    parser.add_argument('--after-bin-dir', type=Path)
    args = parser.parse_args()
    if min(args.requests, args.rounds, args.clients) < 1:
        parser.error('positive workload parameters required')
    if bool(args.before_bin_dir) != bool(args.after_bin_dir):
        parser.error('paired comparison requires both binary directories')
    phases = {'current': smoke.REPO_ROOT / 'target/release'}
    if args.before_bin_dir:
        phases = {'before': args.before_bin_dir, 'after': args.after_bin_dir}
    result = {
        'environment': {
            'platform': platform.platform(), 'python': platform.python_version(),
            'profile': 'release', 'topology': 'loopback',
            'inspection': 'default headers only',
            'cloud': 'disabled; journal benchmark separate',
            'method': 'fresh relay per sample; alternating phase order per round; sampled RSS at 20ms',
        },
        'binarySha256': {
            phase: {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
                    for name in ['pike-server', 'pike']}
            for phase, folder in phases.items()
        },
        'results': [],
    }
    for transport in ['quic', 'websocket']:
        for index in range(args.rounds):
            order = list(phases)
            if index % 2:
                order.reverse()
            for phase in order:
                folder = phases[phase]
                smoke.SERVER_BIN = folder / 'pike-server'
                smoke.CLI_BIN = folder / 'pike'
                sample = run(transport, argparse.Namespace(**{**vars(args), 'rounds': 1}))
                result['results'].append(dict(phase=phase, round=index + 1, **sample))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
