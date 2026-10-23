import os
from models.database import Database
from views.terminal_view import TerminalView
from views.html_view import HTMLView
from views.csv_view import CSVView
from controllers.analyzer_controller import AnalyzerController


class MenuController:
    """Gestionnaire du menu interactif"""

    def __init__(self):
        self.db = Database()
        self.output_format = 'terminal'  # default
        self.view = TerminalView()
        self.html_view = HTMLView()
        self.csv_view = CSVView()

    def run(self):
        """Boucle principale du menu"""
        while True:
            try:
                TerminalView.display_menu()
                choice = input("Votre choix (1-4): ").strip()

                if choice == '1':
                    self._handle_analyze()
                elif choice == '2':
                    self._handle_history()
                elif choice == '3':
                    self._handle_output_options()
                elif choice == '4':
                    print("👋 Au revoir !")
                    break
                else:
                    print("❌ Choix invalide. Veuillez choisir 1-4.")
            except KeyboardInterrupt:
                print("\n👋 Interruption - Au revoir !")
                break
            except Exception as e:
                print(f"❌ Erreur: {e}")

    def _get_logs_files(self) -> list:
        """Retourne la liste des fichiers de logs dans le dossier logs/"""
        if not os.path.exists('logs'):
            os.makedirs('logs')
        return [f for f in os.listdir('logs') if os.path.isfile(os.path.join('logs', f))]

    def _resolve_file_input(self, file_input: str) -> str:
        """
        Résout l'entrée utilisateur (numéro ou nom) en chemin complet.
        Retourne None si non trouvé.
        """
        if not file_input:
            return None

        files = self._get_logs_files()

        # 1. Vérifier si c'est un numéro
        if file_input.isdigit():
            try:
                index = int(file_input) - 1
                if 0 <= index < len(files):
                    return os.path.join('logs', files[index])
            except:
                pass

        # 2. Vérifier si c'est le nom d'un fichier dans logs/
        for f in files:
            if f == file_input:
                return os.path.join('logs', f)
            # Comparaison insensible à la casse
            if f.lower() == file_input.lower():
                return os.path.join('logs', f)

        # 3. Vérifier si c'est un chemin complet existant
        if os.path.exists(file_input):
            return file_input

        # 4. Vérifier si le fichier existe avec un chemin relatif
        if os.path.exists(os.path.join('logs', file_input)):
            return os.path.join('logs', file_input)

        # Rien trouvé
        return None
