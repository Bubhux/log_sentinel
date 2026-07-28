from typing import Dict, Any


class TerminalView:
    """Affichage des résultats dans le terminal"""

    @staticmethod
    def display_header(title: str):
        print("\n" + "="*80)
        print(f" {title} ".center(80, "="))
        print("="*80)

    @staticmethod
    def display_results(report_data):
        """Affiche le rapport complet dans le terminal"""
        TerminalView.display_header(
            f"RAPPORT D'ANALYSE - {report_data.file_processed}")
        print(f"📁 Fichier: {report_data.file_processed}")
        print(f"📊 Total logs: {report_data.total_logs}")
        print(f"🕒 Timestamp: {report_data.timestamp}")
        print("="*80)

        results = report_data.results

        # A. Reconnaissance externe
        if results.get('reconnaissance_externe'):
            print("\n🔍 A. RECONNAISSANCE EXTERNE")
            ext = results['reconnaissance_externe']

            if ext.get('top_ip') and ext['top_ip'][0]:
                print(
                    f"  1. IP externe la plus active: {ext['top_ip'][0]} ({ext['top_ip'][1]} requêtes)")

            if ext.get('active_ips'):
                # Filtrer les None et formater
                active_ips = [
                    ip[0] for ip in ext['active_ips'][:5]
                    if ip and ip[0] is not None
                ]
                if active_ips:
                    print(
                        f"  2. IPs externes actives: {', '.join(active_ips)}")
                else:
                    print("  2. Aucune IP externe active valide")

            if ext.get('vertical_scans'):
                print(
                    f"  3. Scans verticaux détectés: {len(ext['vertical_scans'])} IPs")

            if ext.get('horizontal_scans'):
                print(
                    f"  4. Scans horizontaux détectés: {len(ext['horizontal_scans'])} IPs")

            if ext.get('ping_sweeps'):
                # Filtrer les None
                ping_sweeps = [
                    ip for ip in ext['ping_sweeps'] if ip is not None]
                if ping_sweeps:
                    print(f"  6. Ping sweeps: {', '.join(ping_sweeps)}")
                else:
                    print("  6. Aucun ping sweep valide")

        # B. Reconnaissance interne
        if results.get('reconnaissance_interne'):
            print("\n🏠 B. RECONNAISSANCE INTERNE")
            int_r = results['reconnaissance_interne']
            if int_r.get('most_targeted') and int_r['most_targeted'][0]:
                print(
                    f"  8. Hôte le plus ciblé: {int_r['most_targeted'][0]} ({int_r['most_targeted'][1]} requêtes)")

        # C. Credentials
        if results.get('credentials'):
            print("\n🔐 C. CREDENTIALS & AUTHENTIFICATION")
            cred = results['credentials']
            if cred.get('most_targeted_user') and cred['most_targeted_user'][0]:
                print(
                    f"  12. Utilisateur le plus ciblé: {cred['most_targeted_user'][0]} ({cred['most_targeted_user'][1]} échecs)")
            if cred.get('credential_stuffing'):
                # Filtrer les None
                stuffing = [
                    u for u in cred['credential_stuffing'] if u is not None]
                if stuffing:
                    print(f"  13. Credential stuffing: {', '.join(stuffing)}")
                else:
                    print("  13. Aucun credential stuffing détecté")

        # D. SMB
        if results.get('smb_lateral'):
            print("\n🔗 D. MOUVEMENT LATÉRAL & SMB")
            smb = results['smb_lateral']
            if smb.get('smb_multi_target'):
                # Filtrer les None
                multi = [ip for ip in smb['smb_multi_target'] if ip is not None]
                if multi:
                    print(f"  18. Hôtes SMB multi-cibles: {', '.join(multi)}")
                else:
                    print("  18. Aucun hôte SMB multi-cibles")

        # E. C2 & Exfiltration
        if results.get('c2_exfiltration'):
            print("\n☠️ E. C2 & EXFILTRATION")
            c2 = results['c2_exfiltration']
            if c2.get('c2_hosts'):
                # Filtrer les entrées avec IP None
                hosts = [host for host, _ in c2['c2_hosts']
                         if host is not None]
                print(f"  21. Hôtes avec C2: {len(hosts)} détectés")
            if c2.get('c2_ips'):
                # Filtrer les None
                ips = [ip for ip in c2['c2_ips'] if ip is not None]
                if ips:
                    print(f"  22. IPs C2: {', '.join(ips)}")
                else:
                    print("  22. Aucune IP C2 valide")

        # Alertes
        if report_data.alerts:
            print("\n🚨 ALERTES")
            for alert in report_data.alerts[:10]:
                # Si l'alerte est un dictionnaire structuré
                if isinstance(alert, dict):
                    msg = alert.get('message', '')
                    user = alert.get('user', 'inconnu')
                    src = alert.get('src_ip', 'inconnue')
                    event = alert.get('event_id', 'N/A')

                    # Affichage selon le type
                    if alert.get('type') == 'log_cleared':
                        print(
                            f"  ⚠️ {msg} (utilisateur: {user}, source: {src}, event: {event})")
                    elif alert.get('type') == 'audit_policy_change':
                        print(
                            f"  ⚠️ {msg} (utilisateur: {user}, source: {src}, event: {event})")
                    elif alert.get('type') == 'privilege_change':
                        print(
                            f"  ⚠️ {msg} (utilisateur: {user}, source: {src}, event: {event})")
                    else:
                        # Fallback pour les autres types
                        print(
                            f"  ⚠️ {msg} (utilisateur: {user}, source: {src})")
                else:
                    # Si c'est déjà une chaîne (pour compatibilité)
                    print(f"  {alert}")
            if len(report_data.alerts) > 10:
                print(
                    f"  ... et {len(report_data.alerts) - 10} autres alertes")

        print("\n" + "="*80)

    @staticmethod
    def display_menu():
        """Affiche le menu principal"""
        print("\n" + "="*80)
        print(" LOG ANALYZER - MENU PRINCIPAL ".center(80, "="))
        print("="*80)
        print("1. 📁 Analyser un fichier de logs")
        print("2. 📊 Afficher l'historique")
        print("3. ⚙️  Changer format de sortie")
        print("4. ❌ Quitter")
        print("="*80)

    @staticmethod
    def display_output_options():
        """Affiche les options de sortie"""
        print("\n📤 FORMATS DE SORTIE DISPONIBLES:")
        print("1. Terminal seulement")
        print("2. Rapport HTML")
        print("3. Rapport CSV")
        print("4. HTML + CSV")
        print("5. Retour au menu")
