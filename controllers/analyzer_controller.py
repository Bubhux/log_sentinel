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
