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

    def get_results(self) -> Dict:
        """Génère les résultats des 30 indicateurs"""
        results = {
            'reconnaissance_externe': {},
            'reconnaissance_interne': {},
            'credentials': {},
            'smb_lateral': {},
            'c2_exfiltration': {},
            'persistence': {},
            'suppression_traces': {},
            'alerts': self.alert_log
        }

        # A. RECONNAISSANCE EXTERNE (1-7)
        external_ips = {ip for ip in self.data if not self.is_internal(ip)}
        internal_ips = {ip for ip in self.data if self.is_internal(ip)}

        if external_ips:
            # 1. IP la plus active
            top_external = max(
                external_ips, key=lambda ip: self.data[ip]['requests'])
            results['reconnaissance_externe']['top_ip'] = (
                top_external, self.data[top_external]['requests'])

            # 2. Activité d'analyse externe
            results['reconnaissance_externe']['active_ips'] = [
                (ip, self.data[ip]['requests']) for ip in external_ips
            ]

            # 3. Analyse verticale (plusieurs ports sur même cible)
            vertical_scans = []
            for ip in external_ips:
                if len(self.data[ip]['ports_scanned']) > 5 and len(self.data[ip]['targets']) == 1:
                    vertical_scans.append({
                        'ip': ip,
                        'ports': list(self.data[ip]['ports_scanned']),
                        'target': list(self.data[ip]['targets'])[0]
                    })
            results['reconnaissance_externe']['vertical_scans'] = vertical_scans

            # 4. Analyse horizontale (même port, cibles multiples)
            horizontal_scans = []
            for ip in external_ips:
                if len(self.data[ip]['targets']) > 5 and len(self.data[ip]['ports_scanned']) == 1:
                    horizontal_scans.append({
                        'ip': ip,
                        'port': list(self.data[ip]['ports_scanned'])[0],
                        'targets': list(self.data[ip]['targets'])
                    })
            results['reconnaissance_externe']['horizontal_scans'] = horizontal_scans

            # 5. Ports analysés
            results['reconnaissance_externe']['ports_analyzed'] = {
                ip: list(self.data[ip]['ports_scanned']) for ip in external_ips
            }

            # 6. Ping sweep (beaucoup de cibles, port ICMP)
            ping_sweeps = []
            for ip in external_ips:
                if len(self.data[ip]['targets']) > 10 and 0 in self.data[ip]['ports_scanned']:
                    ping_sweeps.append(ip)
            results['reconnaissance_externe']['ping_sweeps'] = ping_sweeps

            # 7. Multi-services en < 5 min
            multi_service = []
            for ip in external_ips:
                timestamps = sorted(self.data[ip]['timestamps'])
                if len(timestamps) >= 3:
                    for i in range(len(timestamps) - 2):
                        t1 = datetime.fromisoformat(timestamps[i])
                        t3 = datetime.fromisoformat(timestamps[i+2])
                        if (t3 - t1).total_seconds() < 300:  # 5 min
                            multi_service.append(ip)
                            break
            results['reconnaissance_externe']['multi_service_ips'] = multi_service

        # B. RECONNAISSANCE INTERNE (8-11)
        if internal_ips:
            # 8. Hôte interne le plus ciblé
            if self.hosts:
                top_target = max(
                    self.hosts.keys(), key=lambda h: self.hosts[h]['requests_received'])
                results['reconnaissance_interne']['most_targeted'] = (
                    top_target, self.hosts[top_target]['requests_received'])

            # 9. Entrées pour IP interne analysant
            results['reconnaissance_interne']['internal_analyzer_entries'] = {
                ip: self.data[ip]['requests'] for ip in internal_ips
            }

            # 10. Scans horizontaux internes
            horizontal_internal = []
            for ip in internal_ips:
                if len(self.data[ip]['targets']) > 3 and len(self.data[ip]['ports_scanned']) == 1:
                    horizontal_internal.append({
                        'ip': ip,
                        'port': list(self.data[ip]['ports_scanned'])[0],
                        'targets': list(self.data[ip]['targets'])
                    })
            results['reconnaissance_interne']['horizontal_scans'] = horizontal_internal

            # 11. Scans verticaux internes
            vertical_internal = []
            for ip in internal_ips:
                if len(self.data[ip]['ports_scanned']) > 3 and len(self.data[ip]['targets']) == 1:
                    vertical_internal.append({
                        'ip': ip,
                        'target': list(self.data[ip]['targets'])[0],
                        'ports': list(self.data[ip]['ports_scanned'])
                    })
            results['reconnaissance_interne']['vertical_scans'] = vertical_internal

        # C. CREDENTIALS & AUTHENTIFICATION (12-16)
        if self.users:
            # 12. Utilisateur le plus ciblé (basé sur les échecs)
            if any(stats['failures'] > 0 for stats in self.users.values()):
                top_user = max(self.users.keys(),
                               key=lambda u: self.users[u]['failures'])
                results['credentials']['most_targeted_user'] = (
                    top_user, self.users[top_user]['failures']
                )
            else:
                results['credentials']['most_targeted_user'] = ('Aucun', 0)

            # 13. Credential stuffing (≥5 échecs en <10 min)
            credential_stuffing = []
            for user, stats in self.users.items():
                timestamps = sorted(stats['timestamps'])
                if len(timestamps) >= 5:
                    for i in range(len(timestamps) - 4):
                        try:
                            t1 = datetime.fromisoformat(timestamps[i])
                            t5 = datetime.fromisoformat(timestamps[i+4])
                            if (t5 - t1).total_seconds() < 600:  # 10 min
                                credential_stuffing.append(user)
                                break
                        except:
                            continue
            results['credentials']['credential_stuffing'] = credential_stuffing

            # 14. Brute-force réussi
            brute_force_success = []
            for user, stats in self.users.items():
                if stats['failures'] >= 3 and stats['successes'] >= 1:
                    brute_force_success.append(user)
            results['credentials']['brute_force_success'] = brute_force_success

            # 15. IPs externes avec utilisateurs inexistants
            external_invalid_users = []
            for ip in external_ips:
                if len(self.data[ip]['users_attempted']) > 3:
                    external_invalid_users.append(ip)
            results['credentials']['external_invalid_users'] = external_invalid_users

            # 16. Changements de privilèges
            privilege_changes = []
            for ip in self.data:
                if self.data[ip]['privilege_changes'] > 0:
                    privilege_changes.append({
                        'ip': ip,
                        'count': self.data[ip]['privilege_changes']
                    })
            results['credentials']['privilege_changes'] = privilege_changes

        # D. MOUVEMENT LATÉRAL & SMB (17-20)
        smb_ports = {445, 139}
        smb_activities = {
            ip: {
                'targets': self.data[ip]['targets'],
                'ports': self.data[ip]['ports_scanned'],
                'users': self.data[ip]['users_attempted']
            }
            for ip in self.data
            if smb_ports.intersection(self.data[ip]['ports_scanned'])
        }

        if smb_activities:
            # 17. Ports SMB utilisés
            results['smb_lateral']['smb_ports_used'] = list(smb_ports.intersection(
                set().union(*[act['ports'] for act in smb_activities.values()])
            ))

            # 18. Hôtes SMB vers plusieurs cibles
            smb_multi_target = [
                ip for ip, act in smb_activities.items()
                if len(act['targets']) > 2
            ]
            results['smb_lateral']['smb_multi_target'] = smb_multi_target

            # 19. Hôte le plus ciblé SMB
            smb_targets = {}
            for act in smb_activities.values():
                for target in act['targets']:
                    smb_targets[target] = smb_targets.get(target, 0) + 1
            if smb_targets:
                top_smb_target = max(smb_targets, key=smb_targets.get)
                results['smb_lateral']['most_targeted_smb'] = (
                    top_smb_target, smb_targets[top_smb_target])

            # 20. Utilisateurs utilisés SMB
            smb_users = set().union(*[act['users']
                                      for act in smb_activities.values()])
            results['smb_lateral']['smb_users'] = list(smb_users)

        # E. C2 & EXFILTRATION (21-25)
        # 21. Hôte avec communication C2
        c2_hosts = []
        for ip in self.data:
            if self.data[ip]['domains_queried']:
                c2_hosts.append((ip, list(self.data[ip]['domains_queried'])))
        results['c2_exfiltration']['c2_hosts'] = c2_hosts

        # 22. IPs associées au C2 (IPs externes qui reçoivent des connexions internes)
        c2_ips = set()
        for ip, data in self.data.items():
            if self.is_internal(ip):
                for dst in data['targets']:
                    if dst in self.SUSPICIOUS_IPS:
                        c2_ips.add(dst)
        # Ajouter aussi les domaines suspects résolus
        for ip in self.data:
            if self.data[ip]['domains_queried']:
                # On considère que l'IP qui fait la requête est compromise
                if self.is_internal(ip):
                    results['c2_exfiltration']['c2_hosts'] = results.get('c2_exfiltration', {}).get(
                        'c2_hosts', []) + [(ip, list(self.data[ip]['domains_queried']))]
        results['c2_exfiltration']['c2_ips'] = list(c2_ips)

        # 23. Exfiltration (volume anormal)
        exfil_hosts = [
            (ip, self.data[ip]['bytes_out']) for ip in self.data
            if self.data[ip]['bytes_out'] > 1000000  # > 1MB
        ]
        results['c2_exfiltration']['exfil_hosts'] = exfil_hosts

        # 24. DNS suspects
        dns_suspicious = [
            (ip, list(self.data[ip]['domains_queried'])) for ip in self.data
            if self.data[ip]['domains_queried']
        ]
        results['c2_exfiltration']['dns_suspicious'] = dns_suspicious

        # 25. Protocoles non standards
        non_standard = []
        for ip in self.data:
            if ip not in external_ips:  # Interne vers externe
                if len(self.data[ip]['protocols']) > 0:
                    non_standard.append({
                        'ip': ip,
                        'protocols': list(self.data[ip]['protocols'])
                    })
        results['c2_exfiltration']['non_standard_protocols'] = non_standard

        # F. PERSISTANCE & PRIVILÈGES (26-28)
        # 26. Services ajoutés/modifiés
        service_changes = []
        for ip in self.data:
            if self.data[ip]['services']:
                service_changes.append({
                    'ip': ip,
                    'services': list(self.data[ip]['services'])
                })
        results['persistence']['service_changes'] = service_changes

        # 27. LOLBins exécutés
        lolbin_users = [
            (ip, self.data[ip]['lolbin_calls']) for ip in self.data
            if self.data[ip]['lolbin_calls'] > 0
        ]
        results['persistence']['lolbin_calls'] = lolbin_users

        # 28. Activités hors heures de bureau (22h-6h)
        off_hours = []
        for ip in self.data:
            for ts in self.data[ip]['timestamps'][:10]:  # Limite pour performance
                try:
                    hour = datetime.fromisoformat(ts).hour
                    if hour < 6 or hour >= 22:
                        off_hours.append((ip, ts))
                        break
                except:
                    pass
        results['persistence']['off_hours_activities'] = off_hours[:20]  # Limite

        # G. SUPPRESSION DE TRACES (29-30)
        # 29. Log cleared
        log_cleared = [
            ip for ip in self.data if self.data[ip]['log_cleared']
        ]
        results['suppression_traces']['log_cleared'] = log_cleared

        # 30. Audit policy modifiée
        audit_disabled = [
            ip for ip in self.data if self.data[ip]['audit_disabled']
        ]
        results['suppression_traces']['audit_disabled'] = audit_disabled

        return results
