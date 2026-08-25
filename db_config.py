"""
CONFIGURATION CENTRALISÉE — SYSTÈME OACI MADAGASCAR
=====================================================
Ce module est la SEULE source de vérité pour :
  - la connexion à la base de données ;
  - les paramètres de sécurité (politique de mot de passe, verrouillage) ;
  - les constantes métier (préfixe immatriculation, plage de codes OACI).

Conformité visée :
  - ISO/IEC 27001 (A.9 Contrôle d'accès, A.10 Cryptographie) : aucun secret
    en dur dans le code source, tout est lu depuis l'environnement.
  - OWASP ASVS V2 (Authentification) : politique de mot de passe, verrouillage
    de compte après échecs répétés.

IMPORTANT :
  - Ce fichier ne contient AUCUN mot de passe, AUCUN identifiant.
  - Les valeurs sont lues depuis les variables d'environnement (ou un fichier
    .env local en développement, jamais versionné — voir .env.example).
  - `gestion_utilisateurs.py` et `gestion_oaci.py` importent ce module afin
    de garantir que les deux programmes se connectent TOUJOURS à la même
    base avec les mêmes règles de sécurité (une seule source de vérité).
"""

import os
import sys
from dataclasses import dataclass, field
from typing import Optional

try:
    from dotenv import load_dotenv
    # Charge un fichier .env local s'il existe (pratique en développement).
    # En production, les variables sont normalement injectées par
    # l'environnement d'exécution (systemd, Docker, Streamlit secrets, etc.)
    load_dotenv()
except ImportError:
    # python-dotenv est optionnel : si absent, on suppose que les variables
    # d'environnement sont déjà définies par le système.
    pass


class ConfigurationError(Exception):
    """Levée quand une variable d'environnement obligatoire est absente ou invalide."""
    pass


def _lire_variable_obligatoire(nom: str) -> str:
    valeur = os.environ.get(nom)
    if not valeur or not valeur.strip():
        raise ConfigurationError(
            f"La variable d'environnement obligatoire '{nom}' est absente ou vide. "
            f"Définissez-la (fichier .env, variables système, ou st.secrets) "
            f"avant de lancer l'application. Voir .env.example."
        )
    return valeur.strip()


def _lire_variable_optionnelle(nom: str, defaut: str) -> str:
    return os.environ.get(nom, defaut).strip()


def _lire_entier_optionnel(nom: str, defaut: int) -> int:
    valeur = os.environ.get(nom)
    if valeur is None or not valeur.strip():
        return defaut
    try:
        return int(valeur)
    except ValueError:
        raise ConfigurationError(f"La variable '{nom}' doit être un entier, reçu : '{valeur}'")


@dataclass(frozen=True)
class DatabaseConfig:
    """Paramètres de connexion PostgreSQL — lus exclusivement depuis l'environnement."""
    host: str
    port: str
    nom_base: str
    utilisateur: str
    mot_de_passe: str
    sslmode: str = "prefer"  # mettre "require" en production sur réseau non fiable

    @classmethod
    def depuis_environnement(cls) -> "DatabaseConfig":
        return cls(
            host=_lire_variable_optionnelle("OACI_DB_HOST", "localhost"),
            port=_lire_variable_optionnelle("OACI_DB_PORT", "5432"),
            nom_base=_lire_variable_optionnelle("OACI_DB_NAME", "oaci_madagascar"),
            utilisateur=_lire_variable_obligatoire("OACI_DB_USER"),
            mot_de_passe=_lire_variable_obligatoire("OACI_DB_PASSWORD"),
            sslmode=_lire_variable_optionnelle("OACI_DB_SSLMODE", "prefer"),
        )

    def url_connexion(self) -> str:
        """Construit l'URL de connexion SQLAlchemy. Le mot de passe n'est jamais loggé."""
        from urllib.parse import quote_plus
        mdp_echappe = quote_plus(self.mot_de_passe)
        user_echappe = quote_plus(self.utilisateur)
        return (
            f"postgresql+psycopg2://{user_echappe}:{mdp_echappe}"
            f"@{self.host}:{self.port}/{self.nom_base}?sslmode={self.sslmode}"
        )

    def url_affichable(self) -> str:
        """Version sans mot de passe, pour les logs / messages d'erreur."""
        return f"postgresql://{self.utilisateur}:***@{self.host}:{self.port}/{self.nom_base}"


@dataclass(frozen=True)
class SecurityPolicy:
    """Politique de sécurité applicative — ajustable via l'environnement."""
    # Politique de mot de passe (OWASP ASVS V2.1)
    longueur_min_mdp: int = field(default_factory=lambda: _lire_entier_optionnel("OACI_MDP_LONGUEUR_MIN", 12))
    exiger_majuscule: bool = True
    exiger_minuscule: bool = True
    exiger_chiffre: bool = True
    exiger_caractere_special: bool = True

    # Verrouillage de compte (OWASP ASVS V2.2)
    max_tentatives_login: int = field(default_factory=lambda: _lire_entier_optionnel("OACI_MAX_TENTATIVES", 5))
    duree_verrouillage_minutes: int = field(default_factory=lambda: _lire_entier_optionnel("OACI_VERROUILLAGE_MIN", 15))

    # Coût du hachage bcrypt (12 = recommandation actuelle OWASP, ~250ms/hash)
    cout_bcrypt: int = field(default_factory=lambda: _lire_entier_optionnel("OACI_BCRYPT_COST", 12))


@dataclass(frozen=True)
class AppConfig:
    """Constantes métier (non sensibles, peuvent rester ici)."""
    pays: str = "MADAGASCAR"
    prefixe_immat: str = "5R"
    plage_debut: str = "054000"
    plage_fin: str = "054FFF"
    organisme: str = "Autorité de l'Aviation Civile de Madagascar (ACM)"


def charger_configuration() -> "tuple[DatabaseConfig, SecurityPolicy, AppConfig]":
    """Point d'entrée unique pour charger toute la configuration.
    Lève ConfigurationError avec un message clair si un paramètre obligatoire manque."""
    db_config = DatabaseConfig.depuis_environnement()
    security_policy = SecurityPolicy()
    app_config = AppConfig()
    return db_config, security_policy, app_config


if __name__ == "__main__":
    # Auto-test rapide de la configuration (n'expose jamais le mot de passe)
    try:
        db, sec, app = charger_configuration()
        print(f"✓ Configuration chargée : {db.url_affichable()}")
        print(f"✓ Politique mot de passe : min {sec.longueur_min_mdp} caractères")
        print(f"✓ Verrouillage après {sec.max_tentatives_login} échecs, {sec.duree_verrouillage_minutes} min")
    except ConfigurationError as e:
        print(f"✗ Erreur de configuration : {e}", file=sys.stderr)
        sys.exit(1)
