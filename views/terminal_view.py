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
