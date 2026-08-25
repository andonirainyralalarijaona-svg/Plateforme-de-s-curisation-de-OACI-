"""
SERVICE D'AUTHENTIFICATION PARTAGÉ — SYSTÈME OACI MADAGASCAR
================================================================
Unique implémentation de la connexion, du verrouillage de compte et des
permissions, utilisée à la fois par `gestion_utilisateurs.py` (pour exiger
une connexion administrateur avant toute action sensible) et par
`gestion_oaci.py` (connexion principale de l'application).

Pourquoi un module séparé : dans les versions originales, la logique de
permission n'existait que dans essai.py, et gestion.py n'exigeait AUCUNE
authentification pour créer ou désactiver des comptes — un problème de
sécurité majeur (n'importe qui ayant accès au script pouvait créer un
compte administrateur). Centraliser cette logique garantit qu'elle est
appliquée de façon identique partout.

Conformité visée : OWASP ASVS V2.2 (verrouillage de compte), V4 (contrôle d'accès).
"""

from datetime import datetime, timedelta
from typing import Optional, Tuple

from database import DatabaseManager
from db_config import SecurityPolicy
from models import Utilisateur, JournalActivite, SessionDB
import security


PERMISSIONS_PAR_ROLE = {
    "administrateur": {"lire", "ecrire", "supprimer", "exporter", "admin"},
    "agent": {"lire", "ecrire", "exporter"},
    "lecteur": {"lire"},
}


class AuthService:
    def __init__(self, db: DatabaseManager, politique: SecurityPolicy):
        self.db = db
        self.politique = politique
        self.utilisateur_actuel: Optional[Utilisateur] = None
        self._id_utilisateur_actuel: Optional[int] = None

    def connecter(self, nom_utilisateur: str, mot_de_passe: str,
                  adresse_ip: str = "inconnue") -> Tuple[bool, str]:
        """Authentifie un utilisateur. Message d'erreur volontairement générique
        (on ne révèle jamais si c'est le compte ou le mot de passe qui est en cause,
        afin d'empêcher l'énumération de comptes valides)."""
        message_generique = "Identifiants incorrects."

        with self.db.session_scope() as session:
            user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur.strip().lower()).first()

            if not user:
                # Aucune fuite d'information : même comportement que "mauvais mot de passe"
                self._journaliser(session, None, "LOGIN_ECHEC", "UTILISATEUR",
                                   f"Tentative sur compte inexistant : {nom_utilisateur}", adresse_ip, succes=False)
                return False, message_generique

            if not user.actif:
                self._journaliser(session, user.id_utilisateur, "LOGIN_ECHEC", "UTILISATEUR",
                                   "Compte désactivé", adresse_ip, succes=False)
                return False, message_generique

            maintenant = datetime.now()
            if user.est_verrouille(maintenant):
                minutes_restantes = int((user.verrouille_jusqu_a - maintenant).total_seconds() // 60) + 1
                self._journaliser(session, user.id_utilisateur, "LOGIN_ECHEC", "UTILISATEUR",
                                   "Compte temporairement verrouillé", adresse_ip, succes=False)
                return False, f"Compte verrouillé suite à des échecs répétés. Réessayez dans {minutes_restantes} min."

            if not user.verifier_mot_de_passe(mot_de_passe):
                user.tentatives_echouees += 1
                verrouille_maintenant = user.tentatives_echouees >= self.politique.max_tentatives_login
                if verrouille_maintenant:
                    user.verrouille_jusqu_a = maintenant + timedelta(minutes=self.politique.duree_verrouillage_minutes)
                self._journaliser(session, user.id_utilisateur, "LOGIN_ECHEC", "UTILISATEUR",
                                   f"Mot de passe incorrect (tentative {user.tentatives_echouees})",
                                   adresse_ip, succes=False)
                if verrouille_maintenant:
                    return False, (f"Compte verrouillé pour {self.politique.duree_verrouillage_minutes} minutes "
                                    f"suite à {user.tentatives_echouees} échecs.")
                restant = self.politique.max_tentatives_login - user.tentatives_echouees
                return False, f"{message_generique} ({restant} tentative(s) avant verrouillage)"

            # --- Succès ---
            user.tentatives_echouees = 0
            user.verrouille_jusqu_a = None
            user.derniere_connexion = maintenant
            session.add(SessionDB(id_utilisateur=user.id_utilisateur, statut="ACTIVE", adresse_ip=adresse_ip))
            self._journaliser(session, user.id_utilisateur, "LOGIN_SUCCES", "UTILISATEUR",
                               "Connexion réussie", adresse_ip, succes=True)

            self._id_utilisateur_actuel = user.id_utilisateur
            nom_complet = user.nom_complet
            doit_changer = user.doit_changer_mot_de_passe

        # Recharge l'utilisateur dans une session propre pour éviter le DetachedInstanceError
        # une fois hors du bloc `with` (l'objet ORM reste utilisable ensuite).
        with self.db.session_scope() as session:
            self.utilisateur_actuel = session.get(Utilisateur, self._id_utilisateur_actuel)
            session.expunge(self.utilisateur_actuel)

        message = f"Bienvenue, {nom_complet}"
        if doit_changer:
            message += " (changement de mot de passe requis)"
        return True, message

    def deconnecter(self, adresse_ip: str = "inconnue"):
        if not self._id_utilisateur_actuel:
            return
        with self.db.session_scope() as session:
            session.query(SessionDB).filter_by(
                id_utilisateur=self._id_utilisateur_actuel, statut="ACTIVE"
            ).update({"statut": "FERMÉE", "date_deconnexion": datetime.now()})
            self._journaliser(session, self._id_utilisateur_actuel, "LOGOUT", "UTILISATEUR",
                               "Déconnexion", adresse_ip, succes=True)
        self.utilisateur_actuel = None
        self._id_utilisateur_actuel = None

    def a_permission(self, action_requise: str) -> bool:
        if not self.utilisateur_actuel:
            return False
        return action_requise in PERMISSIONS_PAR_ROLE.get(self.utilisateur_actuel.role, set())

    def est_authentifie(self) -> bool:
        return self.utilisateur_actuel is not None

    @staticmethod
    def _journaliser(session, id_utilisateur: Optional[int], action: str, entite: str,
                      details: str, adresse_ip: str, succes: bool):
        session.add(JournalActivite(
            id_utilisateur=id_utilisateur, action=action, entite_concernee=entite,
            details=details, adresse_ip=adresse_ip, succes=succes,
        ))
