"""Свободный локальный порт для пробных запусков (dnsproxy, mihomo, кандидат XRay).

Ловушка: порт-хоппинг Hysteria ставит nft-правило `fib daddr type local udp dport
<диапазон> redirect` и в prerouting, и в OUTPUT — весь UDP на эти порты, включая
127.0.0.1, уходит в Hysteria. Пробный сервис, севший в такой порт, запросов не
получает, и проверка ложно говорит «не ответил». Найдено 17.11.2026 на сервере с
хоппингом 20000-29999: пробный dnsproxy молчал, хотя слушал порт.
"""
import re
import socket


def hop_ranges():
    """Диапазоны хоппинга Hysteria [(a, b)], которые нельзя брать под пробный порт."""
    try:
        from .hysteria import load_settings
        cfg = load_settings()
    except Exception:
        return []
    if not cfg.get('hop_enabled'):
        return []
    m = re.match(r'^\s*(\d{1,5})\s*-\s*(\d{1,5})\s*$', str(cfg.get('hop_range') or ''))
    if not m:
        return []
    a, b = int(m.group(1)), int(m.group(2))
    return [(a, b)] if 1 <= a < b <= 65535 else []


def in_hop_range(port, ranges=None):
    return any(a <= port <= b for a, b in (hop_ranges() if ranges is None else ranges))


def free_port(udp=True):
    """Порт на 127.0.0.1, свободный по TCP (и UDP, если udp) и вне диапазонов хоппинга."""
    ranges = hop_ranges()
    for _ in range(60):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as t:
            t.bind(('127.0.0.1', 0))
            port = t.getsockname()[1]
        if in_hop_range(port, ranges):
            continue
        if udp:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                    u.bind(('127.0.0.1', port))
            except OSError:
                continue
        return port
    raise RuntimeError('не нашлось свободного порта для пробного запуска')
