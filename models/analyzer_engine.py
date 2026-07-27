from collections import defaultdict, Counter
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple
import re


class AnalyzerEngine:
    """Moteur d'analyse des 30 indicateurs"""

    # IPs et domaines suspects (exemple - à remplacer par une vraie liste)
    SUSPICIOUS_IPS = {'185.220.101.1', '45.33.22.11', '91.121.87.34'}
    SUSPICIOUS_DOMAINS = {'evil.com', 'malware.download', 'c2-server.net'}
    LOLBINS = {'powershell', 'wmi', 'schtasks',
               'certutil', 'cmd.exe', 'wscript', 'cscript'}

    # Plage IP interne (exemple - à adapter)
    INTERNAL_NETWORKS = [
        re.compile(r'^192\.168\.\d+\.\d+$'),
        re.compile(r'^10\.\d+\.\d+\.\d+$'),
        re.compile(r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+$')
    ]

    def __init__(self):
        self.data = defaultdict(lambda: {
            'requests': 0,
            'ports_scanned': set(),
            'targets': set(),
            'users_attempted': set(),
            'failures': 0,
            'successes': 0,
            'bytes_out': 0,
            'timestamps': [],
            'domains_queried': set(),
            'protocols': set(),
            'processes': set(),
            'services': set(),
            'lolbin_calls': 0,
            'privilege_changes': 0,
            'log_cleared': False,
            'audit_disabled': False
        })
        self.hosts = defaultdict(lambda: defaultdict(int))
        self.users = defaultdict(
            lambda: {'failures': 0, 'successes': 0, 'src_ips': set(), 'timestamps': []})
        self.alert_log = []

    def process_log(self, log_entry: Dict):
        """Traite une entrée de log et met à jour les statistiques"""
        if not log_entry:
            return

        src_ip = log_entry.get('src_ip')
        dst_ip = log_entry.get('dst_ip')
        user = log_entry.get('user')
        port = log_entry.get('port')
        status = log_entry.get('status')
        timestamp = log_entry.get('timestamp')
        message = log_entry.get('message', '').lower()

        # Mise à jour des statistiques par IP
        if src_ip:
            self.data[src_ip]['requests'] += 1
            if timestamp:
                self.data[src_ip]['timestamps'].append(timestamp)

            if port:
                self.data[src_ip]['ports_scanned'].add(port)

            if dst_ip:
                self.data[src_ip]['targets'].add(dst_ip)
                self.hosts[dst_ip]['requests_received'] += 1

            if user:
                self.data[src_ip]['users_attempted'].add(user)

        # Mise à jour des stats utilisateurs (case-insensitive)
        if user:
            status_lower = status.lower() if status else ''
            if status_lower == 'failed':
                self.users[user]['failures'] += 1
            elif status_lower == 'success':
                self.users[user]['successes'] += 1

            if src_ip:
                self.users[user]['src_ips'].add(src_ip)
            if timestamp:
                self.users[user]['timestamps'].append(timestamp)

        # Détection C2 et DNS suspects
        for domain in self.SUSPICIOUS_DOMAINS:
            if domain in message:
                self.data[src_ip]['domains_queried'].add(domain)

        # Détection LOLBins
        for lolbin in self.LOLBINS:
            if lolbin in message:
                self.data[src_ip]['lolbin_calls'] += 1

        # Détection suppression de logs
        if 'log cleared' in message or 'audit log disabled' in message or 'event log cleared' in message:
            self.data[src_ip]['log_cleared'] = True
            self.alert_log.append({
                'type': 'log_cleared',
                'message': ' Suppression de logs détectée',
                'user': user if user else 'inconnu',
                'src_ip': src_ip if src_ip else 'inconnue',
                'event_id': log_entry.get('event_id', 'N/A')
            })

        if 'auditpol' in message or 'audit policy' in message:
            self.data[src_ip]['audit_disabled'] = True
            self.alert_log.append({
                'type': 'audit_policy_change',
                'message': ' Modification politique audit détectée',
                'user': user if user else 'inconnu',
                'src_ip': src_ip if src_ip else 'inconnue',
                'event_id': log_entry.get('event_id', 'N/A')
            })

        # Détection changement de privilèges
        if 'sudo' in message or 'admin group' in message or 'privilege' in message:
            self.data[src_ip]['privilege_changes'] += 1
            if user:
                self.alert_log.append({
                    'type': 'privilege_change',
                    'message': ' Changement de privilège détecté',
                    'user': user,
                    'src_ip': src_ip if src_ip else 'inconnue',
                    'event_id': log_entry.get('event_id', 'N/A')
                })

    def is_internal(self, ip: str) -> bool:
        """Vérifie si une IP est interne"""
        if not ip:
            return False
        for pattern in self.INTERNAL_NETWORKS:
            if pattern.match(ip):
                return True
        return False
