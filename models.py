"""
MODÈLES DE DONNÉES PARTAGÉS — SYSTÈME OACI MADAGASCAR
========================================================
Les versions originales définissaient DEUX classes `Utilisateur` différentes
(une dans gestion.py, une dans essai.py) pointant sur la même table
`utilisateur`, avec des colonnes différentes et sans garantie de cohérence.

Ce module est désormais la SEULE définition du schéma, importée par
`gestion_utilisateurs.py` ET `gestion_oaci.py`. C'est indispensable pour
la sécurité : une politique de verrouillage de compte ou un format de
hachage ne peut être fiable que s'il n'existe qu'une seule définition
de la table utilisateur.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, Text, ForeignKey, Index, CheckConstraint
)
from sqlalchemy.orm import DeclarativeBase, relationship

import security


class Base(DeclarativeBase):
    pass


ROLES_VALIDES = ("administrateur", "agent", "lecteur")


class Utilisateur(Base):
    __tablename__ = "utilisateur"
    __table_args__ = (
        CheckConstraint("role IN ('administrateur', 'agent', 'lecteur')", name="ck_utilisateur_role"),
    )

    id_utilisateur = Column(Integer, primary_key=True)
    nom_utilisateur = Column(String(50), unique=True, nullable=False, index=True)
    mot_de_passe_hash = Column(String(255), nullable=False)
    nom_complet = Column(String(100), nullable=False)
    email = Column(String(100))
    role = Column(String(20), nullable=False)
    date_creation = Column(DateTime, default=datetime.now)
    actif = Column(Boolean, default=True, nullable=False)
    derniere_connexion = Column(DateTime)

    # --- Champs de sécurité pour le verrouillage de compte (OWASP ASVS V2.2) ---
    tentatives_echouees = Column(Integer, default=0, nullable=False)
    verrouille_jusqu_a = Column(DateTime, nullable=True)
    doit_changer_mot_de_passe = Column(Boolean, default=False, nullable=False)

    attributions = relationship("Attribution", back_populates="utilisateur")
    sessions = relationship("SessionDB", back_populates="utilisateur")
    journal = relationship("JournalActivite", back_populates="utilisateur")

    def verifier_mot_de_passe(self, mot_de_passe: str) -> bool:
        """Vérifie le mot de passe via bcrypt (voir security.py).
        Ne remplace PAS la logique de verrouillage, qui est gérée par AuthService."""
        return security.verifier_mot_de_passe(mot_de_passe, self.mot_de_passe_hash)

    def est_verrouille(self, maintenant: Optional[datetime] = None) -> bool:
        maintenant = maintenant or datetime.now()
        return bool(self.verrouille_jusqu_a and self.verrouille_jusqu_a > maintenant)


class Avion(Base):
    __tablename__ = "avion"
    __table_args__ = (Index("ix_avion_immat", "immatriculation"),)

    id_avion = Column(Integer, primary_key=True)
    immatriculation = Column(String(20), unique=True, nullable=False)
    constructeur = Column(String(100), nullable=False)
    modele = Column(String(100), nullable=False)
    numero_serie = Column(String(50))
    type_transpondeur = Column(String(30))
    proprietaire = Column(String(150), nullable=False)
    exploitant = Column(String(150))
    base_operation = Column(String(50))
    date_premiere_immatriculation = Column(DateTime, default=datetime.now)
    statut = Column(String(20), default="ACTIF")  # ACTIF, RADIÉ, SUSPENDU

    attributions = relationship("Attribution", back_populates="avion")


class CodeOACI(Base):
    __tablename__ = "code_oaci"
    __table_args__ = (Index("ix_code_hexa", "code_hexa"),)

    id_code = Column(Integer, primary_key=True)
    code_hexa = Column(String(6), unique=True, nullable=False)
    code_binaire = Column(String(24), nullable=False)
    code_pays = Column(String(3), nullable=False)
    identifiant = Column(String(4), nullable=False)
    statut_disponibilite = Column(String(20), default="LIBRE", index=True)  # LIBRE, ATTRIBUÉ, RÉSERVÉ

    attributions = relationship("Attribution", back_populates="code_oaci")


class Attribution(Base):
    __tablename__ = "attribution"
    __table_args__ = (
        Index("ix_attrib_avion", "id_avion"),
        Index("ix_attrib_code", "id_code"),
    )

    id_attribution = Column(Integer, primary_key=True)
    id_avion = Column(Integer, ForeignKey("avion.id_avion"), nullable=False)
    id_code = Column(Integer, ForeignKey("code_oaci.id_code"), nullable=False)
    id_utilisateur = Column(Integer, ForeignKey("utilisateur.id_utilisateur"), nullable=False)
    date_attribution = Column(DateTime, default=datetime.now)
    date_fin = Column(DateTime)
    statut = Column(String(20), default="ACTIF", index=True)
    remarques = Column(Text)

    avion = relationship("Avion", back_populates="attributions")
    code_oaci = relationship("CodeOACI", back_populates="attributions")
    utilisateur = relationship("Utilisateur", back_populates="attributions")


class JournalActivite(Base):
    """Journal d'audit — trace toute action sensible (ISO/IEC 27001 A.12.4)."""
    __tablename__ = "journal_activite"
    __table_args__ = (Index("ix_journal_date", "date_heure"),)

    id_journal = Column(Integer, primary_key=True)
    id_utilisateur = Column(Integer, ForeignKey("utilisateur.id_utilisateur"), nullable=True)
    action = Column(String(30), nullable=False)
    entite_concernee = Column(String(30))
    details = Column(Text)
    adresse_ip = Column(String(45))
    succes = Column(Boolean, default=True, nullable=False)
    date_heure = Column(DateTime, default=datetime.now)

    utilisateur = relationship("Utilisateur", back_populates="journal")


class SessionDB(Base):
    __tablename__ = "session"

    id_session = Column(Integer, primary_key=True)
    id_utilisateur = Column(Integer, ForeignKey("utilisateur.id_utilisateur"), nullable=False)
    date_connexion = Column(DateTime, default=datetime.now)
    date_deconnexion = Column(DateTime)
    adresse_ip = Column(String(45))
    statut = Column(String(20), default="ACTIVE")

    utilisateur = relationship("Utilisateur", back_populates="sessions")
