from models.log_parser import LogParser
from models.analyzer_engine import AnalyzerEngine


class AnalyzerController:
    """Contrôleur principal d'analyse"""

    def __init__(self):
        self.parser = LogParser()
        self.engine = AnalyzerEngine()
