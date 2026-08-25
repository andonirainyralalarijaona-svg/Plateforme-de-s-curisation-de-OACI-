"""
SYSTÈME DE GESTION OACI — MADAGASCAR (5R)
============================================
Réécriture sécurisée de essai.py.

Changements de sécurité par rapport à la version originale :
  1. Authentification et verrouillage de compte délégués au module partagé
     `auth_service.py` (au lieu d'une logique dupliquée et sans verrouillage).
  2. Mots de passe hachés avec bcrypt + sel (au lieu de SHA-256 nu).
  3. Identifiants de connexion à la base lus depuis l'environnement — plus
     aucune saisie d'identifiants DB en clair au démarrage (le mot de passe
     PostgreSQL n'est plus jamais tapé dans le terminal courant du script).
  4. Comptes par défaut créés avec des mots de passe temporaires
     ALÉATOIRES et affichés une seule fois (au lieu de mots de passe fixes
     et publics comme "admin123").
  5. Validation stricte des entrées (immatriculation, code hexadécimal)
     avant toute écriture en base.
  6. Le nom de fichier d'export est un identifiant opaque horodaté ; le
     format est vérifié par une liste blanche avant construction du nom
     de fichier (empêche toute manipulation du chemin de sortie).
  7. Les erreurs techniques ne sont plus renvoyées telles quelles à
     l'utilisateur final (pas de fuite de détails internes de la base).

Usage : python gestion_oaci.py
"""

import getpass
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Tuple

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
import pandas as pd

from db_config import charger_configuration, ConfigurationError, AppConfig
from database import DatabaseManager
from models import Avion, CodeOACI, Attribution, Utilisateur, JournalActivite
from auth_service import AuthService
import security


# ==============================================================================
# INITIALISATION DES DONNÉES DE RÉFÉRENCE
# ==============================================================================

def initialiser_codes_oaci(db: DatabaseManager, app_config: AppConfig):
    with db.session_scope() as session:
        if session.query(CodeOACI).count() > 0:
            return

        debut = int(app_config.plage_debut, 16)
        fin = int(app_config.plage_fin, 16)
        print(f"  ⏳ Initialisation de {fin - debut + 1} codes OACI...")

        donnees_a_inserer = [
            {
                "code_hexa": format(code_int, "06X"),
                "code_binaire": format(code_int, "024b"),
                "code_pays": "054",
                "identifiant": format(code_int, "06X")[2:],
                "statut_disponibilite": "LIBRE",
            }
            for code_int in range(debut, fin + 1)
        ]
        session.bulk_insert_mappings(CodeOACI, donnees_a_inserer)
        print(f"  ✓ {len(donnees_a_inserer)} codes OACI initialisés.")


def initialiser_utilisateurs_defaut(db: DatabaseManager, politique) -> List[Tuple[str, str]]:
    """Crée les comptes par défaut UNIQUEMENT si la table est vide, avec des
    mots de passe temporaires aléatoires (jamais de mot de passe fixe connu
    publiquement). Retourne la liste (nom_utilisateur, mot_de_passe_temporaire)
    à afficher UNE SEULE FOIS à l'administrateur qui lance l'initialisation."""
    with db.session_scope() as session:
        if session.query(Utilisateur).count() > 0:
            return []

        comptes = [
            ("admin", "Administrateur ACM", "admin@acm.mg", "administrateur"),
            ("agent", "Agent ACM", "agent@acm.mg", "agent"),
            ("lecteur", "Lecteur ACM", "lecteur@acm.mg", "lecteur"),
        ]
        identifiants_generes = []
        for username, nom, email, role in comptes:
            mot_de_passe_temp = security.generer_mot_de_passe_temporaire()
            session.add(Utilisateur(
                nom_utilisateur=username,
                mot_de_passe_hash=security.hacher_mot_de_passe(mot_de_passe_temp, cout=politique.cout_bcrypt),
                nom_complet=nom,
                email=email,
                role=role,
                actif=True,
                doit_changer_mot_de_passe=True,
            ))
            identifiants_generes.append((username, mot_de_passe_temp))

        return identifiants_generes


# ==============================================================================
# SERVICE MÉTIER OACI
# ==============================================================================

class OACIService:
    def __init__(self, db: DatabaseManager, auth: AuthService):
        self.db = db
        self.auth = auth

    def obtenir_stats(self) -> Dict[str, Any]:
        with self.db.session_scope() as session:
            total = session.query(CodeOACI).count()
            utilises = session.query(CodeOACI).filter_by(statut_disponibilite="ATTRIBUÉ").count()

            statuts = dict(session.query(Avion.statut, func.count(Avion.id_avion)).group_by(Avion.statut).all())
            types = dict(
                session.query(Avion.modele, func.count(Avion.id_avion))
                .group_by(Avion.modele).order_by(func.count(Avion.id_avion).desc()).limit(5).all()
            )

            return {
                "total": total, "utilises": utilises, "libres": total - utilises,
                "occupation": (utilises / total * 100) if total > 0 else 0,
                "statuts": statuts, "types": types,
            }

    def enregistrer_avion(self, donnees: Dict) -> Tuple[bool, str]:
        if not self.auth.a_permission("ecrire"):
            return False, "Permission refusée."

        # --- Validation stricte des entrées (défense en profondeur) ---
        immat = (donnees.get("immatriculation") or "").strip().upper()
        code_oaci_saisi = (donnees.get("code_oaci") or "").strip().upper()

        if not security.immatriculation_valide(immat):
            return False, "Immatriculation invalide (format attendu : 5R-XXX)."
        if not security.code_hexa_valide(code_oaci_saisi):
            return False, "Code OACI invalide (6 caractères hexadécimaux attendus)."
        if not (donnees.get("constructeur") or "").strip():
            return False, "Le constructeur est obligatoire."
        if not (donnees.get("modele") or "").strip():
            return False, "Le modèle est obligatoire."
        if not (donnees.get("proprietaire") or "").strip():
            return False, "Le propriétaire est obligatoire."

        try:
            with self.db.session_scope() as session:
                avion = Avion(
                    immatriculation=immat,
                    constructeur=donnees["constructeur"].strip(),
                    modele=donnees["modele"].strip(),
                    numero_serie=(donnees.get("numero_serie") or "").strip() or None,
                    type_transpondeur=(donnees.get("type_transpondeur") or "").strip() or None,
                    proprietaire=donnees["proprietaire"].strip(),
                    exploitant=(donnees.get("exploitant") or "").strip() or immat,
                    base_operation=(donnees.get("base_operation") or "").strip() or None,
                )
                session.add(avion)
                session.flush()

                code_oaci = session.query(CodeOACI).filter_by(code_hexa=code_oaci_saisi).first()
                if not code_oaci:
                    return False, "Code OACI introuvable dans la base."
                if code_oaci.statut_disponibilite != "LIBRE":
                    return False, "Ce code OACI n'est plus disponible."

                session.add(Attribution(
                    id_avion=avion.id_avion, id_code=code_oaci.id_code,
                    id_utilisateur=self.auth.utilisateur_actuel.id_utilisateur,
                    remarques=security.nettoyer_texte_libre(donnees.get("remarques")),
                ))
                code_oaci.statut_disponibilite = "ATTRIBUÉ"

                session.add(JournalActivite(
                    id_utilisateur=self.auth.utilisateur_actuel.id_utilisateur, action="AJOUT",
                    entite_concernee="AVION",
                    details=f"Ajout {avion.immatriculation} -> {code_oaci.code_hexa}", succes=True,
                ))
                immat_confirmee = avion.immatriculation
                code_confirme = code_oaci.code_hexa

            return True, f"Avion {immat_confirmee} enregistré avec le code {code_confirme}"

        except IntegrityError:
            return False, "Cette immatriculation ou ce code est déjà utilisé."
        except SQLAlchemyError:
            # On ne renvoie jamais le détail technique de l'erreur à l'utilisateur final.
            return False, "Erreur base de données lors de l'enregistrement. Contactez l'administrateur."

    def rechercher_avions(self, critere: str, valeur: str) -> List[Dict]:
        criteres_autorises = {"immatriculation", "proprietaire", "statut"}
        if critere not in criteres_autorises:
            return []

        valeur_nettoyee = security.nettoyer_texte_libre(valeur, longueur_max=100)
        with self.db.session_scope() as session:
            query = session.query(Avion)
            if critere == "immatriculation":
                query = query.filter(Avion.immatriculation.ilike(f"%{valeur_nettoyee}%"))
            elif critere == "proprietaire":
                query = query.filter(Avion.proprietaire.ilike(f"%{valeur_nettoyee}%"))
            elif critere == "statut":
                query = query.filter(Avion.statut == valeur_nettoyee.upper())

            resultats = []
            for avion in query.all():
                attr = session.query(Attribution).filter_by(id_avion=avion.id_avion, statut="ACTIF").first()
                resultats.append({
                    "immatriculation": avion.immatriculation,
                    "constructeur": avion.constructeur, "modele": avion.modele,
                    "type_transpondeur": avion.type_transpondeur, "proprietaire": avion.proprietaire,
                    "statut": avion.statut,
                    "code_oaci": attr.code_oaci.code_hexa if attr else "Non attribué",
                })
            return resultats

    def exporter_donnees(self, format_export: str, dossier_sortie: str = ".") -> Tuple[bool, str]:
        if not self.auth.a_permission("exporter"):
            return False, "Permission refusée."

        formats_autorises = {"csv": "csv", "excel": "xlsx"}
        if format_export not in formats_autorises:
            return False, "Format d'export non pris en charge."

        try:
            with self.db.session_scope() as session:
                resultats = session.query(
                    Avion.immatriculation, Avion.constructeur, Avion.modele, Avion.type_transpondeur,
                    Avion.proprietaire, CodeOACI.code_hexa, CodeOACI.code_binaire, Attribution.date_attribution,
                ).join(Attribution, Avion.id_avion == Attribution.id_avion) \
                 .join(CodeOACI, Attribution.id_code == CodeOACI.id_code) \
                 .filter(Attribution.statut == "ACTIF").all()

                df = pd.DataFrame(resultats, columns=[
                    "Immatriculation", "Constructeur", "Modèle", "Transpondeur",
                    "Propriétaire", "Code_OACI_Hexa", "Code_OACI_Binaire", "Date_Attribution",
                ])

                # Nom de fichier généré par le système uniquement (jamais depuis une entrée
                # utilisateur), pour empêcher toute manipulation du chemin de sortie.
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                extension = formats_autorises[format_export]
                nom_fichier = f"export_oaci_{timestamp}.{extension}"
                chemin_complet = os.path.join(os.path.abspath(dossier_sortie), nom_fichier)

                if format_export == "csv":
                    df.to_csv(chemin_complet, index=False, encoding="utf-8-sig")
                else:
                    df.to_excel(chemin_complet, index=False)

                session.add(JournalActivite(
                    id_utilisateur=self.auth.utilisateur_actuel.id_utilisateur, action="EXPORT",
                    entite_concernee="SYSTEME", details=f"Export {format_export.upper()} : {nom_fichier}",
                    succes=True,
                ))

            return True, chemin_complet

        except (SQLAlchemyError, OSError):
            return False, "Erreur lors de l'export. Contactez l'administrateur."


# ==============================================================================
# INTERFACE CONSOLE (facultative — l'application principale est app.py/Streamlit)
# ==============================================================================

def afficher_banniere(titre: str):
    print("\n" + "╔" + "═" * 70 + "╗")
    print("║" + titre.center(70) + "║")
    print("╚" + "═" * 70 + "╝")


def afficher_section(titre: str):
    print("\n" + "─" * 70 + f"\n  {titre}\n" + "─" * 70)


def pause():
    input("\n  [Appuyez sur Entrée pour continuer...]")


def saisir_nouvel_avion(service: OACIService, app_config: AppConfig):
    afficher_banniere("ENREGISTREMENT D'UN NOUVEL AVION")
    afficher_section("INFORMATIONS AÉRONAUTIQUES")

    immat = input(f"  Immatriculation (ex: {app_config.prefixe_immat}-MAB) : ").strip().upper()
    if not immat.startswith(f"{app_config.prefixe_immat}-"):
        print(f"  ✗ Doit commencer par {app_config.prefixe_immat}-")
        return pause()

    donnees = {
        "immatriculation": immat,
        "constructeur": input("  Constructeur (ex: Cessna) : ").strip(),
        "modele": input("  Modèle (ex: 172) : ").strip(),
        "numero_serie": input("  Numéro de série : ").strip(),
        "type_transpondeur": input("  Type transpondeur (Mode A / Mode S / ADS-B) : ").strip(),
        "proprietaire": input("  Propriétaire : ").strip(),
        "exploitant": input("  Exploitant (si différent) : ").strip() or immat,
        "base_operation": input("  Base d'opération (ex: FMMI) : ").strip(),
        "remarques": input("  Remarques : ").strip(),
    }

    with service.db.session_scope() as session:
        code_libre = session.query(CodeOACI).filter_by(statut_disponibilite="LIBRE").order_by(CodeOACI.code_hexa).first()
        suggestion = code_libre.code_hexa if code_libre else None

    if not suggestion:
        print("  ✗ Aucun code OACI disponible !")
        return pause()

    print(f"\n  💡 Suggestion automatique : {suggestion}")
    choix = input("  Accepter ? (O=oui, N=choisir autre, Q=annuler) : ").strip().upper()

    if choix == "Q":
        return
    elif choix == "N":
        donnees["code_oaci"] = input("  Saisir le code OACI (6 hexa) : ").strip().upper()
    else:
        donnees["code_oaci"] = suggestion

    if input("\n  Confirmer l'enregistrement ? (O/N) : ").strip().upper() == "O":
        succes, msg = service.enregistrer_avion(donnees)
        print(f"\n  {'✅' if succes else '❌'} {msg}")
    pause()


def menu_principal(service: OACIService, auth: AuthService):
    while True:
        afficher_banniere(f"SYSTÈME OACI — MADAGASCAR")
        print(f"  Connecté : {auth.utilisateur_actuel.nom_complet} ({auth.utilisateur_actuel.role.upper()})")

        afficher_section("MENU PRINCIPAL")
        if auth.a_permission("ecrire"):
            print("  1. Enregistrer un avion")
        print("  2. Rechercher un avion")
        print("  3. Statistiques")
        if auth.a_permission("exporter"):
            print("  4. Exporter les données (CSV/Excel)")
        print("  9. Déconnexion")

        choix = input("\n  Votre choix : ").strip()

        if choix == "1" and auth.a_permission("ecrire"):
            saisir_nouvel_avion(service, AppConfig())
        elif choix == "2":
            afficher_section("RECHERCHE")
            critere = input("  Rechercher par (1: Immat, 2: Propriétaire, 3: Statut) : ").strip()
            map_critere = {"1": "immatriculation", "2": "proprietaire", "3": "statut"}
            if critere in map_critere:
                valeur = input(f"  {map_critere[critere].capitalize()} : ").strip()
                resultats = service.rechercher_avions(map_critere[critere], valeur)
                print(f"\n  ✓ {len(resultats)} résultat(s) trouvé(s)")
                for r in resultats:
                    print(f"    - {r['immatriculation']} | {r['code_oaci']} | {r['constructeur']} {r['modele']} | {r['statut']}")
            pause()
        elif choix == "3":
            stats = service.obtenir_stats()
            afficher_section("STATISTIQUES")
            print(f"  Total codes : {stats['total']} | Utilisés : {stats['utilises']} | Libres : {stats['libres']}")
            print(f"  Taux d'occupation : {stats['occupation']:.2f}%")
            pause()
        elif choix == "4" and auth.a_permission("exporter"):
            afficher_section("EXPORT")
            fmt = input("  Format (1: CSV, 2: Excel) : ").strip()
            if fmt in ["1", "2"]:
                format_str = "csv" if fmt == "1" else "excel"
                succes, msg = service.exporter_donnees(format_str)
                print(f"\n  {'✅' if succes else '❌'} {msg}")
            pause()
        elif choix == "9":
            auth.deconnecter()
            break


# ==============================================================================
# POINT D'ENTRÉE
# ==============================================================================

if __name__ == "__main__":
    afficher_banniere("INITIALISATION DU SYSTÈME OACI")
    try:
        db_config, politique, app_config = charger_configuration()
    except ConfigurationError as e:
        print(f"\n  ✗ ERREUR DE CONFIGURATION : {e}")
        sys.exit(1)

    print(f"  → Connexion à {db_config.url_affichable()} ...")
    db = DatabaseManager(db_config)
    if not db.verifier_connexion():
        print("  ✗ Impossible de se connecter à PostgreSQL. Vérifiez que le service est démarré.")
        sys.exit(1)

    try:
        db.creer_tables()
        print("  ✓ Tables vérifiées/créées.")

        initialiser_codes_oaci(db, app_config)
        identifiants_generes = initialiser_utilisateurs_defaut(db, politique)
        if identifiants_generes:
            print("\n  ⚠ Comptes par défaut créés — notez ces identifiants, ils ne seront plus affichés :")
            for nom, mdp in identifiants_generes:
                print(f"      {nom} / {mdp}")
            print("  ⚠ Un changement de mot de passe sera exigé à la première connexion.\n")

        auth = AuthService(db, politique)
        for _ in range(politique.max_tentatives_login):
            print("\n--- CONNEXION ---")
            user = input("Utilisateur : ").strip()
            pwd = getpass.getpass("Mot de passe : ")
            succes, msg = auth.connecter(user, pwd)
            if succes:
                print(f"\n✅ {msg}")
                break
            print(f"❌ {msg}")
        else:
            print("\n  Trop de tentatives échouées. Système verrouillé pour cette session.")
            sys.exit(1)

        service = OACIService(db, auth)
        menu_principal(service, auth)

    except SQLAlchemyError as e:
        print("\n❌ ERREUR DE BASE DE DONNÉES. Contactez l'administrateur système.")
        sys.exit(1)
