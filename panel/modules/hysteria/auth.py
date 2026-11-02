#!/usr/bin/env python3
"""Скрипт аутентификации для hysteria (auth: type: command).

Сервер зовёт его как `auth.py <addr> <auth> <tx>` и ждёт:
  - код 0 и ID клиента в stdout — пустить;
  - любой ненулевой код — отказать.

Здесь же делается то, чего у hysteria нет своими средствами:
  * фильтрация по IP клиента (белый и чёрный списки) — адрес приходит первым
    аргументом, поэтому решение принимаем до установления сессии;
  * запись последнего IP и времени входа, чтобы карточка показывала «откуда
    заходил», как у XRay.

Список клиентов живёт в нашем clients.json, поэтому добавление, отключение и
удаление действуют сразу и не требуют перезапуска сервиса.
"""
import ipaddress
import json
import os
import sys
import time

PKG_DIR = os.path.dirname(os.path.abspath(__file__))
# Скрипт зовёт сама hysteria, а не панель, поэтому корень считается здесь заново.
# Пакет живёт в <panel_root>/modules/hysteria/ — два подъёма, не один. Ошибись
# тут на уровень, и auth.py будет читать несуществующий clients.json: сервис
# «работает», а не пускает никого.
PANEL_ROOT = os.path.dirname(os.path.dirname(PKG_DIR))
DATA_DIR = os.path.join(PANEL_ROOT, 'data', 'hysteria')
CLIENTS_FILE = os.path.join(DATA_DIR, 'clients.json')
LASTSEEN_FILE = os.path.join(DATA_DIR, 'lastseen.json')


def _client_ip(addr):
    """'1.2.3.4:5678' → '1.2.3.4'. IPv6 приходит как '[::1]:5678'."""
    addr = (addr or '').strip()
    if addr.startswith('['):
        return addr[1:addr.find(']')] if ']' in addr else ''
    return addr.rsplit(':', 1)[0] if ':' in addr else addr


def _ip_matches(ip, patterns):
    """IP против списка адресов и CIDR-масок."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for p in patterns or []:
        p = str(p or '').strip()
        if not p:
            continue
        try:
            if '/' in p:
                if addr in ipaddress.ip_network(p, strict=False):
                    return True
            elif addr == ipaddress.ip_address(p):
                return True
        except ValueError:
            continue
    return False


def _remember(cid, ip):
    """Последний IP и время — отдельным файлом, чтобы не переписывать clients.json
    на каждое подключение (там же лежат настройки, и гонка нам не нужна)."""
    if not cid:
        return
    try:
        data = {}
        if os.path.exists(LASTSEEN_FILE):
            with open(LASTSEEN_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f) or {}
        if not isinstance(data, dict):
            data = {}
        data[cid] = {'ip': ip, 'ts': int(time.time())}
        tmp = LASTSEEN_FILE + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, LASTSEEN_FILE)
    except Exception:
        pass


def main():
    addr = sys.argv[1] if len(sys.argv) > 1 else ''
    payload = sys.argv[2] if len(sys.argv) > 2 else ''
    if not payload:
        return 1
    try:
        with open(CLIENTS_FILE, 'r', encoding='utf-8') as f:
            clients = json.load(f)
    except Exception:
        # Нет файла или он битый — не пускаем никого. Открывать доступ при
        # нечитаемом списке клиентов нельзя.
        return 1
    if not isinstance(clients, list):
        return 1

    ip = _client_ip(addr)
    for c in clients:
        if not isinstance(c, dict) or c.get('password') != payload:
            continue
        if c.get('disabled'):
            return 1
        # Чёрный список важнее белого: явный запрет не должен обходиться.
        if _ip_matches(ip, c.get('block_ips')):
            return 1
        allow = [a for a in (c.get('allow_ips') or []) if str(a).strip()]
        if allow and not _ip_matches(ip, allow):
            return 1
        # ID для статистики — неизменяемый id клиента, а НЕ его имя: иначе
        # переименование обнуляло бы накопленный трафик.
        cid = str(c.get('id') or '').strip()
        if not cid:
            return 1
        _remember(cid, ip)
        print(cid)
        return 0
    return 1


if __name__ == '__main__':
    sys.exit(main())
