"""
GESTIONNAIRE D'UTILISATEURS — SYSTÈME OACI MADAGASCAR
========================================================
Réécriture sécurisée de gestion.py.

Changements de sécurité par rapport à la version originale :
  1. Authentification administrateur OBLIGATOIRE avant toute action
     (l'original ne demandait aucune authentification : n'importe qui
     pouvait créer un compte administrateur).
  2. Mots de passe hachés avec bcrypt + sel (au lieu de SHA-256 nu).
  3. Politique de mot de passe appliquée (longueur, complexité).
  4. Verrouillage de compte après échecs de connexion répétés.
  5. Identifiants de connexion à la base lus depuis l'environnement
     (au lieu d'être codés en dur dans le fichier).
  6. Journal d'audit systématique (création, désactivation, réinitialisation).
  7. Impossible de désactiver le dernier compte administrateur actif
     (au lieu d'un simple nom codé en dur "admin").
  8. Validation des entrées (nom d'utilisateur, email) via des expressions
     régulières strictes, en complément de la protection native de l'ORM
     contre l'injection SQL.

Usage : python gestion_utilisateurs.py
"""

import getpass
import sys

from db_config import charger_configuration, ConfigurationError
from database import DatabaseManager
from models import Utilisateur, JournalActivite
from auth_service import AuthService
import security


# ==============================================================================
# AFFICHAGE (aucune logique métier, uniquement de la présentation)
# ==============================================================================

def afficher_banniere(titre: str):
    print("\n" + "╔" + "═" * 68 + "╗")
    print("║" + titre.center(68) + "║")
    print("╚" + "═" * 68 + "╝")


def afficher_section(titre: str):
    print("\n" + "─" * 70 + f"\n  {titre}\n" + "─" * 70)


def pause():
    input("\n  [Appuyez sur Entrée pour continuer...]")


def saisir_mot_de_passe_confirme(politique, libelle: str = "Mot de passe") -> "str | None":
    """Demande un mot de passe deux fois (sans écho à l'écran), valide sa
    force, et vérifie la correspondance. Retourne None si l'utilisateur
    annule ou si la validation échoue après affichage des erreurs."""
    mdp = getpass.getpass(f"  {libelle} : ")
    resultat = security.valider_force_mot_de_passe(mdp, politique)
    if not resultat.valide:
        print("  ✗ Le mot de passe ne respecte pas la politique de sécurité :")
        for erreur in resultat.erreurs:
            print(f"      - {erreur}")
        return None

    confirmation = getpass.getpass("  Confirmez le mot de passe : ")
    if mdp != confirmation:
        print("  ✗ Les deux mots de passe ne correspondent pas.")
        return None

    return mdp


# ==============================================================================
# FONCTIONS MÉTIER
# ==============================================================================

def afficher_utilisateurs(db: DatabaseManager):
    afficher_banniere("LISTE DES UTILISATEURS ENREGISTRÉS")
    with db.session_scope() as session:
        users = session.query(Utilisateur).order_by(Utilisateur.nom_utilisateur).all()
        if not users:
            print("  Aucun utilisateur trouvé.")
            return

        print(f"  {'Nom d’utilisateur':<20} | {'Nom complet':<25} | {'Rôle':<15} | {'Actif':<6} | Statut")
        print("-" * 90)
        for u in users:
            statut_actif = "Oui" if u.actif else "Non"
            statut_verrou = "🔒 verrouillé" if u.est_verrouille() else "—"
            print(f"  {u.nom_utilisateur:<20} | {u.nom_complet:<25} | {u.role:<15} | {statut_actif:<6} | {statut_verrou}")
    print("=" * 90 + "\n")


def creer_nouvel_utilisateur(db: DatabaseManager, politique, auth: AuthService):
    afficher_banniere("CRÉATION D'UN NOUVEL UTILISATEUR")

    nom_utilisateur = input("  Nom d'utilisateur (minuscules, sans espace) : ").strip().lower()
    if not security.nom_utilisateur_valide(nom_utilisateur):
        print("  ✗ Format invalide (3 à 50 caractères : lettres minuscules, chiffres, '.', '_', '-').")
        return

    with db.session_scope() as session:
        if session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first():
            print(f"  ✗ ERREUR : l'utilisateur '{nom_utilisateur}' existe déjà.")
            return

    nom_complet = input("  Nom complet : ").strip()
    if not nom_complet:
        print("  ✗ Le nom complet est obligatoire.")
        return

    email = input("  Adresse e-mail (optionnel) : ").strip()
    if not security.email_valide(email):
        print("  ✗ Format d'e-mail invalide.")
        return

    print("\n  Rôles disponibles :")
    print("    1. administrateur  (accès total)")
    print("    2. agent           (lecture, écriture, export)")
    print("    3. lecteur         (lecture seule)")
    choix_role = input("  Choisissez le rôle (1, 2 ou 3) : ").strip()
    roles_map = {"1": "administrateur", "2": "agent", "3": "lecteur"}
    if choix_role not in roles_map:
        print("  ✗ Choix de rôle invalide.")
        return
    role = roles_map[choix_role]

    mot_de_passe = saisir_mot_de_passe_confirme(politique)
    if mot_de_passe is None:
        return

    print("\n  [RÉCAPITULATIF]")
    print(f"    Utilisateur : {nom_utilisateur}")
    print(f"    Nom complet : {nom_complet}")
    print(f"    Rôle        : {role}")
    if input("\n  Confirmer la création ? (O/N) : ").strip().upper() != "O":
        print("  ✗ Création annulée.")
        return

    with db.session_scope() as session:
        nouvel_utilisateur = Utilisateur(
            nom_utilisateur=nom_utilisateur,
            mot_de_passe_hash=security.hacher_mot_de_passe(mot_de_passe, cout=politique.cout_bcrypt),
            nom_complet=nom_complet,
            email=email or None,
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
    print(f"\n  ✅ Utilisateur '{nom_utilisateur}' créé avec succès.")


def _compter_administrateurs_actifs(session, exclure_id: "int | None" = None) -> int:
    requete = session.query(Utilisateur).filter_by(role="administrateur", actif=True)
    if exclure_id is not None:
        requete = requete.filter(Utilisateur.id_utilisateur != exclure_id)
    return requete.count()


def desactiver_utilisateur(db: DatabaseManager, auth: AuthService):
    afficher_banniere("DÉSACTIVATION D'UN UTILISATEUR")
    nom_utilisateur = input("  Nom d'utilisateur à désactiver : ").strip().lower()

    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            print("  ✗ Utilisateur introuvable.")
            return

        if user.role == "administrateur" and _compter_administrateurs_actifs(session, exclure_id=user.id_utilisateur) == 0:
            print("  ✗ Impossible de désactiver le dernier compte administrateur actif du système.")
            return

        if input(f"  Confirmer la désactivation de '{nom_utilisateur}' ? (O/N) : ").strip().upper() != "O":
            print("  ✗ Action annulée.")
            return

        user.actif = False
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action="DESACTIVATION_UTILISATEUR",
            entite_concernee="UTILISATEUR",
            details=f"Désactivation de '{nom_utilisateur}' par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))
    print(f"  ✅ L'utilisateur '{nom_utilisateur}' a été désactivé.")


def reactiver_utilisateur(db: DatabaseManager, auth: AuthService):
    afficher_banniere("RÉACTIVATION D'UN UTILISATEUR")
    nom_utilisateur = input("  Nom d'utilisateur à réactiver : ").strip().lower()

    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            print("  ✗ Utilisateur introuvable.")
            return
        if user.actif:
            print("  ℹ Ce compte est déjà actif.")
            return

        user.actif = True
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action="REACTIVATION_UTILISATEUR",
            entite_concernee="UTILISATEUR",
            details=f"Réactivation de '{nom_utilisateur}' par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))
    print(f"  ✅ L'utilisateur '{nom_utilisateur}' a été réactivé.")


def deverrouiller_compte(db: DatabaseManager, auth: AuthService):
    afficher_banniere("DÉVERROUILLAGE D'UN COMPTE")
    nom_utilisateur = input("  Nom d'utilisateur à déverrouiller : ").strip().lower()

    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            print("  ✗ Utilisateur introuvable.")
            return
        if not user.est_verrouille() and user.tentatives_echouees == 0:
            print("  ℹ Ce compte n'est pas verrouillé.")
            return

        user.tentatives_echouees = 0
        user.verrouille_jusqu_a = None
        session.add(JournalActivite(
            id_utilisateur=auth.utilisateur_actuel.id_utilisateur, action="DEVERROUILLAGE_COMPTE",
            entite_concernee="UTILISATEUR",
            details=f"Déverrouillage de '{nom_utilisateur}' par {auth.utilisateur_actuel.nom_utilisateur}",
            succes=True,
        ))
    print(f"  ✅ Le compte '{nom_utilisateur}' a été déverrouillé.")


def reinitialiser_mot_de_passe(db: DatabaseManager, politique, auth: AuthService):
    afficher_banniere("RÉINITIALISATION D'UN MOT DE PASSE")
    nom_utilisateur = input("  Nom d'utilisateur concerné : ").strip().lower()

    with db.session_scope() as session:
        user = session.query(Utilisateur).filter_by(nom_utilisateur=nom_utilisateur).first()
        if not user:
            print("  ✗ Utilisateur introuvable.")
            return

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

    print(f"\n  ✅ Mot de passe temporaire généré pour '{nom_utilisateur}' :")
    print(f"     {mot_de_passe_temp}")
    print("  ⚠ Communiquez-le à l'utilisateur par un canal sûr (jamais par e-mail en clair).")
    print("  ⚠ L'utilisateur devra le changer à sa prochaine connexion.")


# ==============================================================================
# POINT D'ENTRÉE
# ==============================================================================

def main():
    afficher_banniere("GESTION DES UTILISATEURS — BASE OACI MADAGASCAR")
    try:
        db_config, politique, _ = charger_configuration()
    except ConfigurationError as e:
        print(f"\n  ✗ ERREUR DE CONFIGURATION : {e}")
        sys.exit(1)

    db = DatabaseManager(db_config)
    if not db.verifier_connexion():
        print(f"\n  ✗ Impossible de se connecter à la base de données ({db_config.url_affichable()}).")
        print("  Vérifiez que PostgreSQL est démarré et que les variables d'environnement sont correctes.")
        sys.exit(1)
    db.creer_tables()

    auth = AuthService(db, politique)
    print("\n  Cet outil nécessite un compte administrateur.")
    for _ in range(politique.max_tentatives_login):
        nom = input("  Utilisateur : ").strip()
        mdp = getpass.getpass("  Mot de passe : ")
        succes, message = auth.connecter(nom, mdp)
        if succes and auth.a_permission("admin"):
            print(f"\n  ✅ {message}")
            break
        elif succes:
            print("\n  ✗ Ce compte n'a pas les droits administrateur nécessaires.")
            auth.deconnecter()
            sys.exit(1)
        else:
            print(f"  ✗ {message}")
    else:
        print("\n  Trop de tentatives échouées. Fermeture.")
        sys.exit(1)

    while True:
        afficher_banniere("GESTION DES UTILISATEURS")
        print(f"  Connecté : {auth.utilisateur_actuel.nom_complet} (administrateur)")
        afficher_section("MENU")
        print("  1. Voir la liste des utilisateurs")
        print("  2. Créer un nouvel utilisateur")
        print("  3. Désactiver un utilisateur")
        print("  4. Réactiver un utilisateur")
        print("  5. Déverrouiller un compte")
        print("  6. Réinitialiser un mot de passe")
        print("  0. Quitter")

        choix = input("\n  Votre choix : ").strip()
        if choix == "1":
            afficher_utilisateurs(db)
        elif choix == "2":
            creer_nouvel_utilisateur(db, politique, auth)
        elif choix == "3":
            desactiver_utilisateur(db, auth)
        elif choix == "4":
            reactiver_utilisateur(db, auth)
        elif choix == "5":
            deverrouiller_compte(db, auth)
        elif choix == "6":
            reinitialiser_mot_de_passe(db, politique, auth)
        elif choix == "0":
            auth.deconnecter()
            print("\n  Au revoir.\n")
            break
        else:
            print("  ✗ Choix invalide.")

        if choix != "0":
            pause()


if __name__ == "__main__":
    main()
