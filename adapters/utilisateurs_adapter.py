"""
ADAPTATEUR — GESTION DES UTILISATEURS POUR L'INTERFACE WEB
==============================================================
Les fonctions de gestion_utilisateurs.py (creer_nouvel_utilisateur,
desactiver_utilisateur, etc.) utilisent input()/print() et ne peuvent donc
pas être appelées depuis Streamlit. Cet adaptateur reproduit exactement les
mêmes RÈGLES métier — en réutilisant les mêmes briques partagées
(security.py pour la validation et le hachage, models.py pour le schéma,
auth_service.py pour les permissions) — mais sous forme de fonctions pures
qui reçoivent des paramètres et renvoient (succès: bool, message: str) au
lieu de lire/écrire sur la console.

Aucune règle de validation n'est dupliquée : elles vivent uniquement dans
security.py et sont appelées ici, exactement comme dans gestion_utilisateurs.py.
"""

from dataclasses import dataclass
from typing import List, Optional, Tuple

from database import DatabaseManager
from models import Utilisateur, JournalActivite
from auth_service import AuthService
import security


@dataclass
class UtilisateurAffichage:
    nom_utilisateur: str
    nom_complet: str
    email: Optional[str]
    role: str
    actif: bool
    verrouille: bool
    doit_changer_mot_de_passe: bool


def lister_utilisateurs(db: DatabaseManager) -> List[UtilisateurAffichage]:
    with db.session_scope() as session:
        users = session.query(Utilisateur).order_by(Utilisateur.nom_utilisateur).all()
        return [
            UtilisateurAffichage(
                nom_utilisateur=u.nom_utilisateur,
                nom_complet=u.nom_complet,
                email=u.email,
                role=u.role,
                actif=u.actif,
                verrouille=u.est_verrouille(),
                doit_changer_mot_de_passe=u.doit_changer_mot_de_passe,
            )
            for u in users
        ]


def creer_utilisateur(db: DatabaseManager, politique, auth: AuthService, *, nom_utilisateur: str,
                       nom_complet: str, email: str, role: str, mot_de_passe: str,
                       mot_de_passe_confirmation: str) -> Tuple[bool, str]:
    nom_utilisateur = nom_utilisateur.strip().lower()

    if not security.nom_utilisateur_valide(nom_utilisateur):
        return False, "Nom d'utilisateur invalide (3 à 50 caractères : minuscules, chiffres, '.', '_', '-')."
    if not nom_complet.strip():
        return False, "Le nom complet est obligatoire."
    if not security.email_valide(email):
        return False, "Adresse e-mail invalide."
    if role not in ("administrateur", "agent", "lecteur"):
        return False, "Rôle invalide."
    if mot_de_passe != mot_de_passe_confirmation:
        return False, "Les deux mots de passe saisis ne correspondent pas."

    resultat = security.valider_force_mot_de_passe(mot_de_passe, politique)
    if not resultat.valide:
        return False, "Mot de passe insuffisant : " + " ; ".join(resultat.erreurs)

    with db.session_scope() as session:
        if session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first():
            return False, f"L'utilisateur '{nom_utilisateur}' existe déjà."

        nouvel_utilisateur = Utilisateur(
            nom_utilisateur=nom_utilisateur,
            mot_de_passe_hash=security.hacher_mot_de_passe(mot_de_passe, cout=politique.cout_bcrypt),
            nom_complet=nom_complet.strip(),
            email=email.strip() or None,
            role=role,
            actif=True,
        )
        session.add(nouvel_utilisateur)
        session.flush()
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action="CREATION_UTILISATEUR",
            entite_concernee="UTILISATEUR",
            details=f"Création de '{nom_utilisateur}' (rôle {role}) par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))

    return True, f"Utilisateur '{nom_utilisateur}' créé avec succès."


def _compter_administrateurs_actifs(session, exclure_id: Optional[int] = None) -> int:
    requete = session.query(Utilisateur).filter_by(role="administrateur", actif=True)
    if exclure_id is not None:
        requete = requete.filter(Utilisateur.id_utilisateur != exclure_id)
    return requete.count()


def basculer_activation(db: DatabaseManager, auth: AuthService, nom_utilisateur: str,
                         activer: bool) -> Tuple[bool, str]:
    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            return False, "Utilisateur introuvable."

        if not activer and user.role == "administrateur" \
                and _compter_administrateurs_actifs(session, exclure_id=user.id_utilisateur) == 0:
            return False, "Impossible de désactiver le dernier compte administrateur actif."

        user.actif = activer
        action = "REACTIVATION_UTILISATEUR" if activer else "DESACTIVATION_UTILISATEUR"
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action=action,
            entite_concernee="UTILISATEUR",
            details=f"{'Réactivation' if activer else 'Désactivation'} de '{nom_utilisateur}' "
                    f"par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))

    verbe = "réactivé" if activer else "désactivé"
    return True, f"L'utilisateur '{nom_utilisateur}' a été {verbe}."


def deverrouiller_compte(db: DatabaseManager, auth: AuthService, nom_utilisateur: str) -> Tuple[bool, str]:
    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            return False, "Utilisateur introuvable."
        if not user.est_verrouille() and user.tentatives_echouees == 0:
            return False, "Ce compte n'est pas verrouillé."

        user.tentatives_echouees = 0
        user.verrouille_jusqu_a = None
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action="DEVERROUILLAGE_COMPTE",
            entite_concernee="UTILISATEUR",
            details=f"Déverrouillage de '{nom_utilisateur}' par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))
    return True, f"Le compte '{nom_utilisateur}' a été déverrouillé."


def changer_son_mot_de_passe(db: DatabaseManager, politique, auth: AuthService, *,
                              mot_de_passe_actuel: str, nouveau_mot_de_passe: str,
                              confirmation: str) -> Tuple[bool, str]:
    """Permet à l'utilisateur connecté de changer lui-même son mot de passe
    (utilisé notamment lors du changement obligatoire à la première connexion)."""
    if nouveau_mot_de_passe != confirmation:
        return False, "Les deux mots de passe saisis ne correspondent pas."

    resultat = security.valider_force_mot_de_passe(nouveau_mot_de_passe, politique)
    if not resultat.valide:
        return False, "Mot de passe insuffisant : " + " ; ".join(resultat.erreurs)

    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur
        ).first()
        if not user or not user.verifier_mot_de_passe(mot_de_passe_actuel):
            return False, "Mot de passe actuel incorrect."

        user.mot_de_passe_hash = security.hacher_mot_de_passe(nouveau_mot_de_passe, cout=politique.cout_bcrypt)
        user.doit_changer_mot_de_passe = False
        session.add(JournalActivite(
            id_utilisateur=user.id_utilisateur, action="CHANGEMENT_MDP", entite_concernee="UTILISATEUR",
            details=f"Changement de mot de passe par '{user.nom_utilisateur}'", succes=True,
        ))

    # Reflète le changement sur l'objet détaché en session Streamlit, sans recharger toute la session.
    auth.utilisateur_actuel.doit_changer_mot_de_passe = False
    return True, "Mot de passe modifié avec succès."


def reinitialiser_mot_de_passe(db: DatabaseManager, politique, auth: AuthService,
                                nom_utilisateur: str) -> Tuple[bool, str]:
    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            return False, "Utilisateur introuvable."

        mot_de_passe_temp = security.generer_mot_de_passe_temporaire()
        user.mot_de_passe_hash = security.hacher_mot_de_passe(mot_de_passe_temp, cout=politique.cout_bcrypt)
        user.doit_changer_mot_de_passe = True
        user.tentatives_echouees = 0
        user.verrouille_jusqu_a = None
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action="REINITIALISATION_MDP",
            entite_concernee="UTILISATEUR",
            details=f"Réinitialisation du mot de passe de '{nom_utilisateur}' par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))

    return True, mot_de_passe_temp
