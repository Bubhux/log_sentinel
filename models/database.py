import sqlite3
from datetime import datetime
from typing import Dict, List
import json


class Database:
    """Gestion de la base SQLite pour l'historique"""

    def __init__(self, db_path='log_analyzer.db'):
        self.db_path = db_path
        self._create_tables()

    def _create_tables(self):
        """Crée les tables nécessaires"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    file_processed TEXT NOT NULL,
                    total_logs INTEGER NOT NULL,
                    top_external_ip TEXT,
                    top_target_user TEXT,
                    alerts_count INTEGER,
                    summary TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    message TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analyses(id)
                )
            ''')
            conn.commit()

    def save_analysis(self, report_data):
        """Sauvegarde une analyse dans la base"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Résumé rapide
            summary = f"Analyse de {report_data.file_processed} - {report_data.total_logs} logs"

            # Extraire les infos clés
            top_external = report_data.results.get(
                'reconnaissance_externe', {}).get('top_ip', ('N/A', 0))[0]
            top_user = report_data.results.get('credentials', {}).get(
                'most_targeted_user', ('N/A', 0))[0]

            cursor.execute('''
                INSERT INTO analyses (timestamp, file_processed, total_logs, top_external_ip, top_target_user, alerts_count, summary)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                report_data.timestamp,
                report_data.file_processed,
                report_data.total_logs,
                top_external,
                top_user,
                len(report_data.alerts),
                summary
            ))

            analysis_id = cursor.lastrowid

            # Sauvegarder les alertes (convertir en chaîne lisible)
            for alert in report_data.alerts[:50]:
                if isinstance(alert, dict):
                    # Formater en texte lisible
                    msg = alert.get('message', '')
                    user = alert.get('user', 'inconnu')
                    src = alert.get('src_ip', 'inconnue')
                    event = alert.get('event_id', 'N/A')
                    alert_str = f"{msg} (utilisateur: {user}, source: {src}, event: {event})"
                else:
                    alert_str = str(alert)

                cursor.execute('''
                    INSERT INTO alerts (analysis_id, message) VALUES (?, ?)
                ''', (analysis_id, alert_str))

            conn.commit()
            return analysis_id

    def get_history(self, limit=10):
        """Récupère l'historique des analyses"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT id, timestamp, file_processed, total_logs, top_external_ip, top_target_user, alerts_count
                FROM analyses ORDER BY timestamp DESC LIMIT ?
            ''', (limit,))
            return cursor.fetchall()
