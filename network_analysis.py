"""Separate, deterministic traffic-surge policy for on-demand investigations."""
import json
from collections import Counter
from datetime import datetime, timedelta
from server_analytics import ROLES

POLICY = {
    'id': 'recent-vs-previous-6h-v1',
    'baseline_hours': 6,
    'threshold_percent': 150,
    'minimum_coverage_percent': 80,
    'max_sample_seconds': 180,
    'max_stale_seconds': 180,
    'metric': 'NIC 송신+수신 바이트 / 유효 관측 시간 × 60',
    'meaning': '기준의 150% = 1.5배 = 50% 증가',
}


def metrics(rows, start, end):
    tx = rx = covered = 0.0
    cpu, ram, disk = [], [], []
    valid = 0
    last = None
    cursor = start
    for row in rows:
        ts = datetime.fromisoformat(row['ts'])
        p = json.loads(row['payload'])
        if start < ts <= end and p.get('resource_collection_ok'):
            cpu.append(p['cpu_percent'])
            ram.append(p['memory_percent'])
            disk.append(p['disk_percent'])
        interval = p.get('interval_seconds', 0)
        if not p.get('counter_valid') or not 0 < interval <= POLICY['max_sample_seconds']:
            continue
        # Clip intervals at the comparison boundary; exclude overlapping samples.
        left = max(start, ts - timedelta(seconds=interval), cursor)
        right = min(end, ts)
        seconds = (right - left).total_seconds()
        if seconds <= 0:
            continue
        tx += p['tx_bytes'] * seconds / interval
        rx += p['rx_bytes'] * seconds / interval
        covered += seconds
        valid += 1
        last = right
        cursor = right
    duration = (end - start).total_seconds()
    result = {
        'tx_bytes': round(tx, 3) if covered else None,
        'rx_bytes': round(rx, 3) if covered else None,
        'total_bytes': round(tx + rx, 3) if covered else None,
        'bytes_per_minute': (tx + rx) / covered * 60 if covered else None,
        'average_mbps': (tx + rx) / covered * 8 / 1e6 if covered else None,
        'covered_seconds': round(covered, 3),
        'coverage_percent': covered / duration * 100,
        'valid_samples': valid,
        'last_seen': last.isoformat() if last else None,
        'stale_seconds': (end - last).total_seconds() if last else None,
    }
    for name, values in [('cpu', cpu), ('ram', ram), ('disk', disk)]:
        result[name + '_avg'] = round(sum(values) / len(values), 2) if values else None
        result[name + '_max'] = max(values) if values else None
    return result


def compare(current, baseline):
    if current['coverage_percent'] < POLICY['minimum_coverage_percent']:
        return 'recent_incomplete', None
    if baseline['coverage_percent'] < POLICY['minimum_coverage_percent']:
        return 'baseline_incomplete', None
    if current['stale_seconds'] is None or current['stale_seconds'] > POLICY['max_stale_seconds']:
        return 'stale', None
    if not baseline['bytes_per_minute']:
        return 'zero_baseline', None
    ratio = current['bytes_per_minute'] / baseline['bytes_per_minute'] * 100
    return ('candidate' if round(ratio, 9) >= POLICY['threshold_percent'] else 'below_threshold'), ratio


def build(c, minutes, end):
    start = end - timedelta(minutes=minutes)
    baseline_start = start - timedelta(hours=POLICY['baseline_hours'])
    devices = c.execute('SELECT d.id,d.label,d.role,q.ips FROM devices d LEFT JOIN enrollment_requests q ON q.device_id=d.id WHERE d.active=1 ORDER BY d.id').fetchall()
    candidates, servers, deferred = [], [], []
    counts = Counter()
    observed = 0
    for d in devices:
        rows = c.execute('SELECT ts,payload FROM samples WHERE device=? AND ts>? AND ts<=? ORDER BY ts,batch', (d['id'], baseline_start.isoformat(), end.isoformat())).fetchall()
        current = metrics(rows, start, end)
        baseline = metrics(rows, baseline_start, start)
        status, ratio = compare(current, baseline)
        item = {'id': d['id'], 'label': d['label'], 'role': d['role'], 'ips': json.loads(d['ips'] or '[]'), 'current': current, 'baseline': baseline, 'comparison_status': status, 'ratio_percent': ratio, 'increase_percent': ratio - 100 if ratio is not None else None}
        observed += current['valid_samples'] > 0
        if d['role'] in ROLES:
            servers.append(item)
            continue
        counts[status] += 1
        if status == 'candidate':
            item['excess_bytes_per_minute'] = current['bytes_per_minute'] - baseline['bytes_per_minute']
            candidates.append(item)
        elif status != 'below_threshold':
            deferred.append({'id': d['id'], 'label': d['label'], 'ips': item['ips'], 'reason': status, 'recent_coverage_percent': current['coverage_percent'], 'baseline_coverage_percent': baseline['coverage_percent']})
    candidates.sort(key=lambda d: (-d['ratio_percent'], -d['excess_bytes_per_minute'], d['id']))
    for rank, d in enumerate(candidates, 1):
        d['rank'] = rank
    return {
        'version': 1, 'policy': dict(POLICY), 'minutes': minutes,
        'window_start': start.isoformat(), 'window_end': end.isoformat(),
        'baseline_start': baseline_start.isoformat(), 'baseline_end': start.isoformat(),
        'timezone': 'Asia/Seoul', 'candidates': candidates, 'servers': servers,
        'deferred': deferred, 'excluded_counts': dict(counts),
        'counts': {'registered': len(devices), 'pcs': sum(counts.values()), 'candidates': len(candidates), 'servers': len(servers), 'compared': counts['candidate'] + counts['below_threshold'], 'deferred': len(deferred), 'observed': observed},
        'limitations': [
            '트래픽 증가 후보이며 네트워크 루프·실제 지연 또는 침해가 확정된 것은 아닙니다.',
            '송신+수신을 포함한 장비 전체 통신량입니다. 인터넷 회선 사용량 또는 PC 간 합산 트래픽을 뜻하지 않습니다.',
            '두 구간 각각 80% 이상 수집되고 최근 관측이 3분 이내인 장비만 배수 비교합니다. 기준 통신량 0은 비교 보류합니다.',
            '구간 경계를 걸치는 표본은 표본 내 일정한 전송률로 나누어 계산합니다. 중복 시간과 3분 초과 표본은 제외합니다.',
            '비율 순위가 높아도 절대 통신량이 작을 수 있습니다. 백업·업데이트·대용량 전송과 스위치 자료를 함께 확인해야 합니다.',
        ],
    }
