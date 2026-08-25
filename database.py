"""
GESTIONNAIRE DE CONNEXION — SYSTÈME OACI MADAGASCAR
======================================================
Fabrique unique de l'engine SQLAlchemy et des sessions, partagée par les deux
programmes métier (gestion_utilisateurs.py et gestion_oaci.py) afin qu'ils se
connectent TOUJOURS à la même base avec les mêmes réglages (pool, SSL, etc.).
Aucune logique métier ici.
"""

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from db_config import DatabaseConfig
from models import Base


class DatabaseManager:
    def __init__(self, db_config: DatabaseConfig, echo_sql: bool = False):
        self.config = db_config
        self.engine = create_engine(
            db_config.url_connexion(),
            pool_size=10,
            max_overflow=20,
            pool_pre_ping=True,   # vérifie que la connexion est vivante avant usage
            pool_recycle=1800,    # recycle les connexions au bout de 30 min (évite les coupures silencieuses)
            echo=echo_sql,        # ne JAMAIS activer en production (peut logguer des données sensibles)
        )
        self.SessionLocal = sessionmaker(bind=self.engine, expire_on_commit=False)

    def creer_tables(self):
        """Crée les tables si elles n'existent pas. Ne supprime ni ne modifie
        jamais une table existante (pas de migration destructive automatique)."""
        Base.metadata.create_all(self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    @contextmanager
    def session_scope(self) -> Iterator[Session]:
        """Context manager transactionnel : commit automatique si succès,
        rollback automatique si exception, fermeture garantie de la session."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def verifier_connexion(self) -> bool:
        """Test de connexion simple, sans exposer d'information sensible en cas d'échec."""
        try:
            with self.engine.connect():
                return True
        except Exception:
            return False
