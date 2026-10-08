import csv
import os
from datetime import datetime


class CSVView:
    """Génération de rapport CSV avec nom horodaté"""

    @staticmethod
    def _generate_filename(base_name: str = "report") -> str:
        """
        Génère un nom de fichier avec timestamp.
        Format: report_YYYY-MM-DD_HH-MM-SS.csv
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return f"{base_name}_{timestamp}.csv"

    @staticmethod
    def generate(report_data, output_dir='outputs', base_name='report'):
        """
        Génère un rapport CSV avec un nom horodaté.
        
        Args:
            report_data: Données du rapport
            output_dir: Dossier de sortie
            base_name: Nom de base du fichier (sans extension)
        
        Returns:
            Chemin complet du fichier généré
        """
        os.makedirs(output_dir, exist_ok=True)

        # Générer le nom du fichier avec timestamp
        filename = CSVView._generate_filename(base_name)
        output_path = os.path.join(output_dir, filename)
