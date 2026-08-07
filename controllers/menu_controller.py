import os
from models.database import Database
from views.terminal_view import TerminalView
from views.html_view import HTMLView


class MenuController:
    """Gestionnaire du menu interactif"""

    def __init__(self):
        self.db = Database()
        self.output_format = 'terminal'  # default
        self.view = TerminalView()
        self.html_view = HTMLView()

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
