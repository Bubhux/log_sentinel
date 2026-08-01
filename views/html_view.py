import os
from datetime import datetime
from jinja2 import Environment, FileSystemLoader


class HTMLView:
    """Génération de rapport HTML avec Jinja2 et nom horodaté"""

    def __init__(self):
        # Initialiser l'environnement Jinja2
        self.env = Environment(
            loader=FileSystemLoader('templates'),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        # Ajouter un filtre personnalisé pour le formatage de la taille des fichiers
        self.env.filters['filesizeformat'] = self._filesizeformat

    @staticmethod
    def _filesizeformat(size):
        """
        Formate une taille en bytes en unités lisibles.
        Gère les valeurs None, les chaînes vides, et les valeurs non numériques.
        """
        # Si size est None, une chaîne vide, ou n'est pas un nombre
        if size is None or size == '':
            return "0 B"

        try:
            # Convertir en float (gère les chaînes numériques)
            size = float(size)
        except (ValueError, TypeError):
            return "0 B"

        # Si size est 0, retourner directement
        if size == 0:
            return "0 B"

        # Formater selon la taille
        if size < 1024:
            return f"{size:.0f} B"
        elif size < 1024 * 1024:
            return f"{size/1024:.1f} KB"
        elif size < 1024 * 1024 * 1024:
            return f"{size/(1024*1024):.1f} MB"
        else:
            return f"{size/(1024*1024*1024):.1f} GB"

    @staticmethod
    def _generate_filename(base_name: str = "report") -> str:
        """
        Génère un nom de fichier avec timestamp.
        Format: report_YYYY-MM-DD_HH-MM-SS.html
        """
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return f"{base_name}_{timestamp}.html"

    def generate(self, report_data, output_dir='outputs', base_name='report'):
        """
        Génère un rapport HTML avec un nom horodaté.
        
        Args:
            report_data: Données du rapport
            output_dir: Dossier de sortie
            base_name: Nom de base du fichier (sans extension)
        
        Returns:
            Chemin complet du fichier généré
        """
        os.makedirs(output_dir, exist_ok=True)

        # Générer le nom du fichier avec timestamp
        filename = self._generate_filename(base_name)
        output_path = os.path.join(output_dir, filename)

        # Charger le template
        template = self.env.get_template('report.html')

        # Préparer les données pour le template
        context = {
            'file_processed': report_data.file_processed,
            'total_logs': report_data.total_logs,
            'timestamp': report_data.timestamp,
            'results': report_data.results,
            'alerts': report_data.alerts
        }

        # Générer le HTML
        html = template.render(**context)

        # Sauvegarder le fichier
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

        return output_path
