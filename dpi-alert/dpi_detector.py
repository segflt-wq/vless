#!/usr/bin/env python3
"""
DPI scan detector.
Sources: nginx stream log + tcpdump pcap
Config: /etc/dpi-alert/dpi_detector.yml
Usage: python3 dpi_detector.py [--config /etc/dpi-alert/dpi_detector.yml]
"""

from __future__ import annotations

import re
import argparse
import sys
import ipaddress
import urllib.request
import urllib.parse
import json
import os
import glob
import subprocess
import copy
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
import dpkt

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_CONFIG  = "/etc/dpi-alert/dpi_detector.yml"
STATE_FILE      = "/var/lib/dpi-alert/last_ts.txt"
TELEGRAM_ENV    = "/etc/default/telegram"
REPUTATION_FILE = "/var/lib/dpi-alert/reputation.json"

GRAYLIST_FILE_DEFAULT          = Path("/etc/nginx/graylist.conf")
GRAYLIST_CONTAINER_DEFAULT     = "nginx_stream"
SUSPICIOUS_PERFECT_LOG_DEFAULT = "/var/log/dpi-alert/suspicious-perfect.log"
BY_CONNECTIONS_LOG_DEFAULT     = "/var/log/dpi-alert/by-connections.log"

def load_config(path: str) -> dict:
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        print(f"[ERROR] Config file not found: {path}", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Find client IPs (multiple — handles dynamic IP changes)
# ---------------------------------------------------------------------------
def find_client_ips(lines: list[str], client_sni: str, client_backend: str) -> set[str]:
    """
    Возвращает множество всех IP, которые использовали наш SNI+backend.
    Учитывает смену динамического IP провайдером.
    """
    ips = set()
    for line in lines:
        parsed = parse_line(line)
        if parsed and parsed['backend'] == client_backend \
                  and parsed['sni'] == client_sni:
            ips.add(parsed['remote'])
    return ips

# ---------------------------------------------------------------------------
# Graylist
# ---------------------------------------------------------------------------
def _reload_nginx(container: str) -> bool:
    try:
        subprocess.run(
            ['docker', 'exec', container, 'nginx', '-s', 'reload'],
            check=True, capture_output=True, timeout=10
        )
        print(f"[NGINX] Reloaded ({container})")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Nginx reload failed: {e.stderr.decode()}", file=sys.stderr)
        return False
    except FileNotFoundError:
        print(f"[ERROR] Docker not found or container '{container}' not running", file=sys.stderr)
        return False

def _read_graylist(file: Path) -> set[str]:
    ips = set()
    if not file.exists():
        return ips
    for line in file.read_text().split('\n'):
        line = line.split('#')[0].strip()
        if line:
            ips.add(line.split()[0])
    return ips

def graylist_ip(ip: str, file: Path, container: str) -> bool:
    """Добавляет IP в серый список."""
    current = _read_graylist(file)
    if ip in current:
        print(f"[GRAY] {ip} уже в списке")
        return False
    try:
        with open(file, 'a') as f:
            f.write(f"{ip} 1;  # added {datetime.now().isoformat()}\n")
        print(f"[GRAY] {ip} добавлен")
        return _reload_nginx(container)
    except Exception as e:
        print(f"[ERROR] Failed to write graylist: {e}", file=sys.stderr)
        return False

# ---------------------------------------------------------------------------
# Suspicious-perfect logger
# ---------------------------------------------------------------------------
def log_suspicious_perfect(log_path: Path, parsed: dict, reasons: list[str], score: int):
    try:
        os.makedirs(log_path.parent, exist_ok=True)
        entry = {
            'ts':         parsed['ts'].isoformat(),
            'remote':     parsed['remote'],
            'sni':        parsed['sni'],
            'backend':    parsed['backend'],
            'duration':   parsed['duration'],
            'bytes_sent': parsed['sent'],
            'bytes_recv': parsed['recv'],
            'score':      score,
            'reasons':    reasons,
            'note':       'correct SNI but suspicious behavior'
        }
        with open(log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
        print(f"[PERFECT-LOG] {parsed['remote']} logged (score={score})")
    except Exception as e:
        print(f"[WARN] Failed to log suspicious-perfect: {e}", file=sys.stderr)

# ---------------------------------------------------------------------------
# BY connections logger
# ---------------------------------------------------------------------------
def log_by_connection(log_path: Path, parsed: dict, reason: str):
    """
    Логирует любой коннект из BY-диапазона который не является
    легитимным клиентским трафиком.
    Формат JSONL.
    """
    try:
        os.makedirs(log_path.parent, exist_ok=True)
        entry = {
            'ts':         parsed['ts'].isoformat(),
            'remote':     parsed['remote'],
            'backend':    parsed['backend'],
            'sni':        parsed['sni'],
            'status':     parsed['status'],
            'duration':   parsed['duration'],
            'bytes_sent': parsed['sent'],
            'bytes_recv': parsed['recv'],
            'reason':     reason,
        }
        with open(log_path, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    except Exception as e:
        print(f"[WARN] Failed to log BY connection: {e}", file=sys.stderr)

# ---------------------------------------------------------------------------
# Reputation
# ---------------------------------------------------------------------------
def load_reputation(path: str) -> dict:
    try:
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    except Exception as e:
        print(f"[WARN] Не удалось загрузить репутацию: {e}", file=sys.stderr)
    return {}

def save_reputation(path: str, rep: dict):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w') as f:
            json.dump(rep, f, indent=2)
    except Exception as e:
        print(f"[WARN] Не удалось сохранить репутацию: {e}", file=sys.stderr)

def update_reputation(rep: dict, ip: str, score: int, reasons: list[str]) -> dict:
    # FIX: deep copy чтобы не мутировать вложенные объекты исходного dict
    rep = copy.deepcopy(rep)
    now = datetime.now().isoformat()
    if ip not in rep:
        rep[ip] = {
            'first_seen':  now,
            'last_seen':   now,
            'total_score': 0,
            'hit_count':   0,
            'reasons':     {},
        }
    rep[ip]['last_seen']    = now
    rep[ip]['hit_count']   += 1
    rep[ip]['total_score'] += score
    for r in reasons:
        rep[ip]['reasons'][r] = rep[ip]['reasons'].get(r, 0) + 1
    cutoff = (datetime.now() - timedelta(days=90)).isoformat()
    return {k: v for k, v in rep.items() if v['last_seen'] > cutoff}

def get_reputation_score(rep: dict, ip: str) -> int:
    if ip in rep:
        hits = rep[ip]['hit_count']
        if hits >= 10: return 5
        elif hits >= 5: return 3
        elif hits >= 2: return 2
    return 0

# ---------------------------------------------------------------------------
# Telegram
# ---------------------------------------------------------------------------
def load_telegram_creds(path: str) -> tuple[str, str] | None:
    token = chat_id = None
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith('TOKEN='):
                    token = line.split('=', 1)[1].strip().strip('"').strip("'")
                elif line.startswith('CHAT_ID='):
                    chat_id = line.split('=', 1)[1].strip().strip('"').strip("'")
        if token and chat_id:
            return token, chat_id
        print(f"[WARN] TOKEN или CHAT_ID не найдены в {path}", file=sys.stderr)
        return None
    except FileNotFoundError:
        print(f"[WARN] Telegram credentials file not found: {path}", file=sys.stderr)
        return None

def send_telegram(token: str, chat_id: str, text: str):
    url  = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id":    chat_id,
        "text":       text,
        "parse_mode": "HTML",
    }).encode()
    try:
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            if not result.get("ok"):
                print(f"[WARN] Telegram API error: {result}", file=sys.stderr)
    except Exception as e:
        print(f"[WARN] Telegram send failed: {e}", file=sys.stderr)

def format_telegram_message(
    nginx_results: list[tuple[dict, list[str]]],
    pcap_results:  list[dict],
) -> str:
    lines = ["🚨 <b>DPI scan detected</b>\n"]

    if nginx_results:
        lines.append("📋 <b>Nginx detector</b>")
        by_ip = defaultdict(list)
        for parsed, reasons in nginx_results:
            by_ip[parsed['remote']].append((parsed, reasons))
        for ip, entries in sorted(by_ip.items(), key=lambda x: -len(x[1])):
            lines.append(f"  🇧🇾 <b>{ip}</b> ({len(entries)} hits)")
            for parsed, reasons in entries:
                ts       = parsed['ts'].strftime("%d/%m %H:%M:%S")
                duration = f"{parsed['duration']:.3f}s" if parsed['duration'] else "?"
                why      = " | ".join(r for r in reasons if not r.startswith("BY-"))
                lines.append(
                    f"    {ts}  sni={parsed['sni']}"
                    f"  bytes={parsed['sent']}/{parsed['recv']}"
                    f"  dur={duration}\n    → {why}"
                )
        lines.append("")

    if pcap_results:
        lines.append("🔬 <b>Pcap detector</b>")
        by_ip = defaultdict(list)
        for r in pcap_results:
            by_ip[r['src_ip']].append(r)
        for ip, entries in sorted(by_ip.items(), key=lambda x: -len(x[1])):
            lines.append(f"  🇧🇾 <b>{ip}</b> ({len(entries)} SYN)")
            for r in entries:
                ts  = datetime.fromtimestamp(r['ts']).strftime("%d/%m %H:%M:%S")
                why = " | ".join(r['reasons'])
                lines.append(
                    f"    {ts}  win={r['window']}"
                    f"  mss={r['mss'] or '?'}  ttl={r['ttl']}"
                    f"\n    → {why}"
                )
        lines.append("")

    return "\n".join(lines)

# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
def load_last_ts(path: str) -> datetime | None:
    try:
        with open(path) as f:
            ts = datetime.fromisoformat(f.read().strip())
            # FIX: если datetime naive (нет timezone offset) — считаем UTC,
            # чтобы не было TypeError при сравнении с aware datetime из лога
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return ts
    except (FileNotFoundError, ValueError):
        return None

def save_last_ts(path: str, ts: datetime):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as f:
        f.write(ts.isoformat())

# ---------------------------------------------------------------------------
# IP matching
# ---------------------------------------------------------------------------
def build_networks(cidrs: list[str]) -> list[ipaddress.IPv4Network]:
    return [ipaddress.ip_network(r) for r in cidrs]

def is_belarus_ip(ip: str, networks: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in networks)
    except ValueError:
        return False

# ---------------------------------------------------------------------------
# Log parser
# ---------------------------------------------------------------------------
LOG_RE = re.compile(
    r'^(?P<remote>\S+)\s+->\s+(?P<backend>\S+)\s+\[(?P<ts>[^\]]+)\]\s+'
    r'(?P<status>\S+)\s+bytes=(?P<sent>\d+)/(?P<recv>\d+)\s+'
    r'conn=(?P<conn>\d+)\s+sni=(?P<sni>\S+)\s+'
    r'duration=(?P<duration>\S+)\s+proto=(?P<proto>\S+)$'
)

def parse_line(line: str) -> dict | None:
    m = LOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    d['sent'] = int(d['sent'])
    d['recv'] = int(d['recv'])
    d['conn'] = int(d['conn'])
    d['ts']   = datetime.strptime(d['ts'], "%d/%b/%Y:%H:%M:%S %z")
    try:
        d['duration'] = float(d['duration'])
    except (ValueError, TypeError):
        d['duration'] = None
    return d

# ---------------------------------------------------------------------------
# Read log
# ---------------------------------------------------------------------------
def read_lines(path: str, last_ts: datetime | None) -> list[str]:
    try:
        result = []
        with open(path) as f:
            for line in f:
                line = line.rstrip()
                if not line:
                    continue
                if last_ts is None:
                    result.append(line)
                else:
                    parsed = parse_line(line)
                    # FIX: оба datetime теперь aware (last_ts нормализован в load_last_ts),
                    # сравнение безопасно
                    if parsed and parsed['ts'] > last_ts:
                        result.append(line)
        return result
    except FileNotFoundError:
        print(f"[ERROR] Log file not found: {path}", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------------------
# Find client IP / last timestamp
# ---------------------------------------------------------------------------
def find_client_ip(lines: list[str], client_sni: str, client_backend: str) -> str | None:
    for line in reversed(lines):
        parsed = parse_line(line)
        if parsed and parsed['backend'] == client_backend \
                  and parsed['sni'] == client_sni:
            return parsed['remote']
    return None

def find_last_ts(lines: list[str]) -> datetime | None:
    for line in reversed(lines):
        parsed = parse_line(line)
        if parsed:
            return parsed['ts']
    return None

# ---------------------------------------------------------------------------
# Nginx detector
# ---------------------------------------------------------------------------
def analyze_nginx(
    lines:            list[str],
    client_ips:       set[str],
    cfg:              dict,
    networks:         list,
    reputation:       dict,
    perfect_log_path: Path | None = None,
    by_log_path:      Path | None = None,
) -> tuple[list[tuple[dict, list[str]]], dict]:

    client_sni     = cfg['client']['sni']
    client_backend = cfg['client']['backend']

    rate_window        = cfg['thresholds']['rate_window_sec']
    rate_threshold     = cfg['thresholds']['rate_threshold']
    tiny_bytes         = cfg['thresholds']['tiny_bytes']
    score_threshold    = cfg['thresholds']['score_threshold']
    correlation_window = timedelta(seconds=cfg['thresholds']['correlation_window_sec'])
    short_session_sec  = cfg['thresholds']['short_session_sec']
    burst_window       = cfg['thresholds'].get('burst_window_sec', 5)
    burst_threshold    = cfg['thresholds'].get('burst_threshold', 10)

    detect_half_handshake = cfg.get('nginx_detector', {}).get('detect_half_handshake', False)
    log_perfect           = cfg.get('suspicious_perfect', {}).get('enabled', True)

    ip_hits      = defaultdict(list)
    ip_bursts    = defaultdict(list)
    client_times = []
    results      = []
    updated_rep  = dict(reputation)

    # Сбор timestamps клиентского трафика
    for line in lines:
        parsed = parse_line(line)
        if parsed and parsed['remote'] in client_ips and parsed['backend'] == client_backend and parsed['sni'] == client_sni:
            client_times.append(parsed['ts'])

    # Анализ чужого трафика
    for line in lines:
        parsed = parse_line(line)
        if not parsed:
            continue

        remote   = parsed['remote']
        backend  = parsed['backend']
        sni      = parsed['sni']
        sent     = parsed['sent']
        recv     = parsed['recv']
        now      = parsed['ts']
        duration = parsed['duration']

        # ✅ FIX: корректная проверка принадлежности к множеству клиентских IP
        if remote in client_ips:
            continue
        if not is_belarus_ip(remote, networks):
            continue

        # FIX: логируем ЛЮБОЙ BY-коннект не от клиента, независимо от статуса/SNI/backend.
        # Причины добавляем для контекста, но запись происходит всегда.
        if by_log_path:
            by_reasons = []
            if parsed['status'] != '200':
                by_reasons.append(f"status={parsed['status']}")
            if 'fallback' in backend:
                by_reasons.append("backend=fallback")
            if not (sni == client_sni and backend == client_backend):
                by_reasons.append("not_client_traffic")
            # Всегда пишем — "ok" если нет специфичных причин (чистый коннект с правильным SNI)
            log_by_connection(by_log_path, parsed, " | ".join(by_reasons) if by_reasons else "ok")

        score            = 0
        reasons          = []
        behavioral_flags = []

        rep_bonus = get_reputation_score(reputation, remote)
        if rep_bonus > 0 and remote not in client_ips: 
            score += rep_bonus
            reasons.append(f"reputation(+{rep_bonus})")
            behavioral_flags.append("reputation")

        if 'fallback' in backend:
            score += 2
            reasons.append("backend=fallback(+2)")

        if sni in ('-', ''):
            score += 3
            reasons.append("SNI=empty(+3)")
        elif sni != client_sni:
            score += 1
            reasons.append(f"SNI='{sni}'(+1)")

        if sent + recv < tiny_bytes:
            score += 2
            reasons.append(f"tiny bytes({sent}↑/{recv}↓)(+2)")
            behavioral_flags.append("tiny_bytes")

        if duration is not None and duration < short_session_sec:
            score += 3
            reasons.append(f"short session({duration:.3f}s)(+3)")
            behavioral_flags.append("short_session")

        window_start = now - timedelta(seconds=rate_window)
        ip_hits[remote] = [t for t in ip_hits[remote] if t > window_start]
        ip_hits[remote].append(now)
        if len(ip_hits[remote]) >= rate_threshold:
            score += 2
            reasons.append(f"rate={len(ip_hits[remote])}/{rate_window}s(+2)")
            behavioral_flags.append("rate")

        burst_start = now - timedelta(seconds=burst_window)
        ip_bursts[remote] = [t for t in ip_bursts[remote] if t > burst_start]
        ip_bursts[remote].append(now)
        if len(ip_bursts[remote]) >= burst_threshold:
            score += 3
            reasons.append(f"burst={len(ip_bursts[remote])}/{burst_window}s(+3)")
            behavioral_flags.append("burst")

        correlated = any(
            timedelta(0) <= now - ct <= correlation_window
            for ct in client_times
        )
        if correlated:
            score += 5
            reasons.append("correlated(+5)")
            behavioral_flags.append("correlated")

        if detect_half_handshake and duration is not None:
            if duration < 0.5 and recv < 100 and sent > 0:
                score += 4
                reasons.append(f"half-handshake(dur={duration:.3f}s, recv={recv})(+4)")
                behavioral_flags.append("half_handshake")

        # Suspicious-perfect: правильный SNI + правильный бэкенд + поведенческие флаги
        if (log_perfect and perfect_log_path and
                sni == client_sni and
                backend == client_backend and
                behavioral_flags):
            log_suspicious_perfect(perfect_log_path, parsed, behavioral_flags, score)

        if score >= score_threshold:
            reasons.append(f"BY-ALERT score={score}")
            results.append((parsed, reasons))
            updated_rep = update_reputation(updated_rep, remote, score, reasons)

    return results, updated_rep

# ---------------------------------------------------------------------------
# Pcap detector
# ---------------------------------------------------------------------------
def get_mss(tcp: dpkt.tcp.TCP) -> int | None:
    try:
        opts = dpkt.tcp.parse_opts(tcp.opts)
        for opt_type, opt_data in opts:
            if opt_type == dpkt.tcp.TCP_OPT_MSS:
                return int.from_bytes(opt_data, 'big')
    except Exception:
        pass
    return None

def get_pcap_files(pcap_dir: str, pattern: str, min_size: int) -> list[str]:
    files = glob.glob(os.path.join(pcap_dir, pattern))
    if not files:
        return []
    files = [f for f in files if os.path.getsize(f) >= min_size]
    if not files:
        return []
    files.sort(key=os.path.getmtime)
    # Последний файл пропускается намеренно: tcpdump ещё может писать в него
    return files[:-1]

def analyze_pcap(cfg: dict, networks: list, reputation: dict, client_ips: set[str]) -> tuple[list[dict], dict]:
    pcap_cfg        = cfg.get('pcap', {})
    pcap_dir        = pcap_cfg.get('dir', '/var/log/tcpdump')
    pattern         = pcap_cfg.get('pattern', 'tls-*.pcap')
    min_size        = pcap_cfg.get('min_size_bytes', 24)
    score_threshold = cfg['thresholds']['pcap_score_threshold']

    suspicious_windows = set(pcap_cfg.get('suspicious_windows', [0, 512, 1024, 2048, 4096]))
    normal_mss_range   = (
        pcap_cfg.get('normal_mss_min', 1200),
        pcap_cfg.get('normal_mss_max', 1460),
    )

    files = get_pcap_files(pcap_dir, pattern, min_size)
    if not files:
        return [], reputation

    results     = []
    updated_rep = dict(reputation)

    for fpath in files:
        print(f"[PCAP] Анализируем: {fpath}")
        try:
            with open(fpath, 'rb') as f:
                try:
                    pcap = dpkt.pcap.Reader(f)
                except Exception as e:
                    print(f"[PCAP] Ошибка открытия {fpath}: {e}", file=sys.stderr)
                    continue

                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        ip  = eth.data
                        if not isinstance(ip.data, dpkt.tcp.TCP):
                            continue
                        tcp = ip.data

                        is_syn     = bool(tcp.flags & dpkt.tcp.TH_SYN)
                        is_syn_ack = bool(tcp.flags & dpkt.tcp.TH_ACK)
                        if not is_syn or is_syn_ack:
                            continue

                        src_ip = str(ipaddress.ip_address(ip.src))
                        
                        # ✅ FIX: исключаем клиентские IP из анализа pcap
                        if src_ip in client_ips:
                            continue
                            
                        if not is_belarus_ip(src_ip, networks):
                            continue

                        mss    = get_mss(tcp)
                        window = tcp.win
                        ttl    = ip.ttl

                        score   = 0
                        reasons = []

                        rep_bonus = get_reputation_score(reputation, src_ip)
                        if rep_bonus > 0:
                            score += rep_bonus
                            reasons.append(f"reputation(+{rep_bonus})")

                        if window in suspicious_windows:
                            score += 3
                            reasons.append(f"suspicious window={window}(+3)")
                        if mss is None:
                            score += 2
                            reasons.append("no MSS option(+2)")
                        elif not (normal_mss_range[0] <= mss <= normal_mss_range[1]):
                            score += 2
                            reasons.append(f"unusual MSS={mss}(+2)")
                        if ttl not in (64, 128) and (ttl == 255 or ttl < 50):
                            score += 1
                            reasons.append(f"unusual TTL={ttl}(+1)")

                        if score >= score_threshold:
                            results.append({
                                'src_ip':  src_ip,
                                'ts':      ts,
                                'window':  window,
                                'mss':     mss,
                                'ttl':     ttl,
                                'score':   score,
                                'reasons': reasons,
                            })
                            updated_rep = update_reputation(updated_rep, src_ip, score, reasons)

                    except Exception:
                        continue

        except Exception as e:
            print(f"[PCAP] Ошибка чтения {fpath}: {e}", file=sys.stderr)
            continue

        try:
            os.remove(fpath)
            print(f"[PCAP] Удалён: {fpath}")
        except Exception as e:
            print(f"[PCAP] Ошибка удаления {fpath}: {e}", file=sys.stderr)

    return results, updated_rep

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def print_nginx_results(results: list[tuple[dict, list[str]]]):
    by_ip = defaultdict(list)
    for parsed, reasons in results:
        by_ip[parsed['remote']].append((parsed, reasons))
    print("\n=== NGINX DETECTOR: ПОДОЗРИТЕЛЬНЫЕ BY-IP ===")
    for ip, entries in sorted(by_ip.items(), key=lambda x: -len(x[1])):
        print(f"\n  🇧🇾 {ip}  ({len(entries)} hits)")
        for parsed, reasons in entries:
            ts       = parsed['ts'].strftime("%d/%m %H:%M:%S")
            duration = f"{parsed['duration']:.3f}s" if parsed['duration'] else "?"
            why      = " | ".join(r for r in reasons if not r.startswith("BY-"))
            print(f"    {ts}  sni={parsed['sni']:<30}  "
                  f"bytes={parsed['sent']}/{parsed['recv']}  "
                  f"dur={duration}  → {why}")

def print_pcap_results(results: list[dict]):
    by_ip = defaultdict(list)
    for r in results:
        by_ip[r['src_ip']].append(r)
    print("\n=== PCAP DETECTOR: ПОДОЗРИТЕЛЬНЫЕ BY-IP ===")
    for ip, entries in sorted(by_ip.items(), key=lambda x: -len(x[1])):
        print(f"\n  🇧🇾 {ip}  ({len(entries)} SYN)")
        for r in entries:
            ts  = datetime.fromtimestamp(r['ts']).strftime("%d/%m %H:%M:%S")
            why = " | ".join(r['reasons'])
            print(f"    {ts}  win={r['window']}  "
                  f"mss={r['mss'] or '?'}  ttl={r['ttl']}  "
                  f"score={r['score']}  → {why}")

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="DPI scan detector")
    parser.add_argument('--config',        default=DEFAULT_CONFIG, help="Path to config yml")
    parser.add_argument('--graylist-add',  metavar='IP',           help="Добавить IP в серый список")
    parser.add_argument('--graylist-list', action='store_true',    help="Показать серый список")
    args = parser.parse_args()

    cfg = load_config(args.config)

    gl_cfg             = cfg.get('graylist', {})
    graylist_enabled   = gl_cfg.get('enabled', True)
    graylist_file      = Path(gl_cfg.get('file', str(GRAYLIST_FILE_DEFAULT)))
    graylist_container = gl_cfg.get('container', GRAYLIST_CONTAINER_DEFAULT)

    sp_cfg           = cfg.get('suspicious_perfect', {})
    perfect_log_path = Path(sp_cfg.get('log_file', SUSPICIOUS_PERFECT_LOG_DEFAULT)) \
                       if sp_cfg.get('enabled', True) else None

    by_cfg      = cfg.get('by_connections', {})
    by_log_path = Path(by_cfg.get('log_file', BY_CONNECTIONS_LOG_DEFAULT)) \
                  if by_cfg.get('enabled', True) else None

    # CLI: показать серый список
    if args.graylist_list:
        if graylist_file.exists():
            print(f"📋 Серый список ({graylist_file}):")
            for line in graylist_file.read_text().split('\n'):
                if line.strip() and not line.startswith('#'):
                    print(f"  {line.strip()}")
        else:
            print("📭 Серый список пуст")
        sys.exit(0)

    # CLI: добавить IP вручную
    if args.graylist_add:
        if graylist_ip(args.graylist_add, graylist_file, graylist_container):
            print(f"✅ {args.graylist_add} добавлен в серый список")
        else:
            print(f"❌ Ошибка при добавлении {args.graylist_add}")
        sys.exit(0)

    networks = build_networks(cfg['belarus_cidrs'])

    log_file       = cfg['log_file']
    state_file     = cfg.get('state_file', STATE_FILE)
    rep_file       = cfg.get('reputation_db', REPUTATION_FILE)

    # Поле allowed_asns присутствует в конфиге, но фильтрация по ASN не реализована.
    # При необходимости — добавить whois/BGP-lookup и сравнение с cfg.get('allowed_asns', [])
    allowed_asns = cfg.get('allowed_asns', [])
    if allowed_asns:
        print(f"[INFO] allowed_asns в конфиге ({len(allowed_asns)} записей) — "
              f"фильтрация по ASN не реализована, поле игнорируется")

    tg_creds   = load_telegram_creds(TELEGRAM_ENV)
    reputation = load_reputation(rep_file)

    # ---- Nginx detector ----
    last_ts = load_last_ts(state_file)
    if last_ts is None:
        print("[INFO] State file not found — читаем лог целиком")
    else:
        print(f"[INFO] Продолжаем с: {last_ts.strftime('%d/%m/%Y %H:%M:%S %z')}")

    lines = read_lines(log_file, last_ts)

    if not lines:
        print("[INFO] Новых строк в nginx логе нет")
        nginx_results = []
    else:
        client_sni     = cfg['client']['sni']
        client_backend = cfg['client']['backend']

        client_ips = find_client_ips(lines, client_sni, client_backend)
        if client_ips:
            print(f"[INFO] Client IPs: {', '.join(sorted(client_ips))}")
        else:
            print("[WARN] Client IPs не найдены — анализируем весь трафик")
            client_ips = set()

        new_last_ts = find_last_ts(lines)
        if new_last_ts:
            save_last_ts(state_file, new_last_ts)
            print(f"[INFO] State сохранён: {new_last_ts.strftime('%d/%m/%Y %H:%M:%S %z')}")

        nginx_results, reputation = analyze_nginx(
            lines, client_ips, cfg, networks, reputation,
            perfect_log_path=perfect_log_path,
            by_log_path=by_log_path,
        )
        print(f"[INFO] Nginx: проанализировано строк={len(lines)}, "
              f"подозрительных={len(nginx_results)}")

    # ---- Pcap detector ----
    # ✅ FIX: передаём client_ips в analyze_pcap для фильтрации
    pcap_results, reputation = analyze_pcap(cfg, networks, reputation, client_ips)
    print(f"[INFO] Pcap: подозрительных SYN={len(pcap_results)}")

    # ---- Graylist: авто-добавление ----
    if graylist_enabled and (nginx_results or pcap_results):
        all_suspicious = set()
        for parsed, _ in nginx_results:
            all_suspicious.add(parsed['remote'])
        for r in pcap_results:
            all_suspicious.add(r['src_ip'])
        added = 0
        for ip in all_suspicious:
            if graylist_ip(ip, graylist_file, graylist_container):
                added += 1
        if added:
            print(f"[GRAY] Добавлено {added} IP в серый список")

    # ---- Сохранение репутации ----
    save_reputation(rep_file, reputation)
    print(f"[INFO] Репутация сохранена: {len(reputation)} IP в базе")

    # ---- Вывод и алерты ----
    if nginx_results:
        print_nginx_results(nginx_results)
    if pcap_results:
        print_pcap_results(pcap_results)

    if nginx_results or pcap_results:
        if tg_creds:
            msg = format_telegram_message(nginx_results, pcap_results)
            send_telegram(tg_creds[0], tg_creds[1], msg)
            print("[INFO] Telegram alert отправлен")
        else:
            print("[WARN] Telegram не настроен — алерт не отправлен")
    else:
        print("\n[OK] Подозрительных BY-IP не обнаружено")

if __name__ == "__main__":
    main()