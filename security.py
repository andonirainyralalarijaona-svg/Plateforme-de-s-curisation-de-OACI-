"""
MODULE SÉCURITÉ — SYSTÈME OACI MADAGASCAR
============================================
Centralise TOUTES les opérations cryptographiques et de validation liées
à l'authentification, afin qu'il n'existe qu'une seule implémentation
(évite la divergence entre gestion_utilisateurs.py et gestion_oaci.py
qui, dans les versions originales, hachaient les mots de passe en
SHA-256 nu — sans sel — ce qui est vulnérable aux attaques par
dictionnaire / rainbow tables).

Conformité visée : OWASP ASVS V2 (Authentification), NIST SP 800-63B.
  - Hachage : bcrypt (sel aléatoire intégré, facteur de coût réglable).
  - Aucune limite de longueur artificielle basse sur le mot de passe.
  - Aucune information sur la raison précise d'un échec de connexion
    (on ne dit jamais si c'est le nom d'utilisateur OU le mot de passe
    qui est incorrect — évite l'énumération de comptes).
"""

import re
import secrets
from dataclasses import dataclass
from typing import Optional

import bcrypt

from db_config import SecurityPolicy


# ==============================================================================
# HACHAGE DES MOTS DE PASSE
# ==============================================================================

def hacher_mot_de_passe(mot_de_passe: str, cout: int = 12) -> str:
    """Hache un mot de passe avec bcrypt (sel aléatoire généré automatiquement).
    Retourne une chaîne UTF-8 stockable telle quelle en base (colonne String(255))."""
    sel = bcrypt.gensalt(rounds=cout)
    empreinte = bcrypt.hashpw(mot_de_passe.encode("utf-8"), sel)
    return empreinte.decode("utf-8")


def verifier_mot_de_passe(mot_de_passe: str, empreinte_stockee: str) -> bool:
    """Vérifie un mot de passe contre son empreinte bcrypt.
    Robuste : ne lève jamais d'exception vers l'appelant (retourne False
    si l'empreinte stockée est corrompue ou dans un ancien format)."""
    try:
        return bcrypt.checkpw(mot_de_passe.encode("utf-8"), empreinte_stockee.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def empreinte_est_bcrypt(empreinte: str) -> bool:
    """Permet de détecter une ancienne empreinte SHA-256 (64 caractères hexa)
    lors d'une migration de données, pour forcer un changement de mot de passe."""
    return empreinte.startswith(("$2a$", "$2b$", "$2y$"))


# ==============================================================================
# POLITIQUE DE MOT DE PASSE
# ==============================================================================

@dataclass
class ResultatValidationMdp:
    valide: bool
    erreurs: list


def valider_force_mot_de_passe(mot_de_passe: str, politique: SecurityPolicy) -> ResultatValidationMdp:
    """Vérifie qu'un mot de passe respecte la politique de sécurité définie.
    Retourne la liste de TOUTES les règles non respectées (pour un message
    actionnable à l'utilisateur, pas juste 'mot de passe invalide')."""
    erreurs = []

    if len(mot_de_passe) < politique.longueur_min_mdp:
        erreurs.append(f"doit contenir au moins {politique.longueur_min_mdp} caractères")

    if politique.exiger_majuscule and not re.search(r"[A-ZÀ-Ý]", mot_de_passe):
        erreurs.append("doit contenir au moins une majuscule")

    if politique.exiger_minuscule and not re.search(r"[a-zà-ý]", mot_de_passe):
        erreurs.append("doit contenir au moins une minuscule")

    if politique.exiger_chiffre and not re.search(r"[0-9]", mot_de_passe):
        erreurs.append("doit contenir au moins un chiffre")

    if politique.exiger_caractere_special and not re.search(r"[^\w\s]", mot_de_passe):
        erreurs.append("doit contenir au moins un caractère spécial (ex: ! ? # @ %)")

    return ResultatValidationMdp(valide=(len(erreurs) == 0), erreurs=erreurs)


def generer_mot_de_passe_temporaire(longueur: int = 16) -> str:
    """Génère un mot de passe temporaire cryptographiquement sûr,
    utile pour la création de compte ou la réinitialisation."""
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(longueur))


# ==============================================================================
# VALIDATION DES ENTRÉES (défense en profondeur, en complément de l'ORM)
# ==============================================================================

REGEX_NOM_UTILISATEUR = re.compile(r"^[a-z0-9_.\-]{3,50}$")
REGEX_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
REGEX_IMMATRICULATION = re.compile(r"^5R-[A-Z]{2,4}$")
REGEX_CODE_HEXA = re.compile(r"^[0-9A-F]{6}$")


def nom_utilisateur_valide(nom: str) -> bool:
    """Minuscules, chiffres, points, tirets et underscores uniquement, 3 à 50 caractères.
    Empêche l'injection de caractères de contrôle ou d'espaces dans les identifiants."""
    return bool(REGEX_NOM_UTILISATEUR.match(nom))


def email_valide(email: str) -> bool:
    if not email:
        return True  # email optionnel
    return bool(REGEX_EMAIL.match(email))


def immatriculation_valide(immat: str) -> bool:
    return bool(REGEX_IMMATRICULATION.match(immat))


def code_hexa_valide(code: str) -> bool:
    return bool(REGEX_CODE_HEXA.match(code))


def nettoyer_texte_libre(texte: Optional[str], longueur_max: int = 500) -> str:
    """Nettoie un champ texte libre (remarques, etc.) : supprime les caractères
    de contrôle et tronque à une longueur raisonnable pour éviter les abus."""
    if not texte:
        return ""
    texte_nettoye = "".join(c for c in texte if c.isprintable() or c in "\n\t")
    return texte_nettoye.strip()[:longueur_max]
