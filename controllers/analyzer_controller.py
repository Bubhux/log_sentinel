from datetime import datetime
from models.log_parser import LogParser
from models.analyzer_engine import AnalyzerEngine
from models.report_data import ReportData


class AnalyzerController:
    """Contrôleur principal d'analyse"""

    def __init__(self):
        self.parser = LogParser()
        self.engine = AnalyzerEngine()

    def analyze_file(self, filepath: str) -> ReportData:
        """Analyse un fichier de logs et retourne les résultats"""
        print(f"\n🔍 Analyse du fichier: {filepath}")

        # Parsing des logs
        logs = self.parser.parse_file(filepath)
        print(f"✅ {len(logs)} entrées de log parsées")

        # Traitement des logs par le moteur
        for log in logs:
            self.engine.process_log(log)

        # Génération des résultats
        results = self.engine.get_results()

        # Création du rapport
        report_data = ReportData(
            results=results,
            file_processed=filepath,
            total_logs=len(logs),
            timestamp=datetime.now().isoformat(),
            alerts=self.engine.alert_log
        )

        return report_data
