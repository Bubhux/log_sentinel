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
