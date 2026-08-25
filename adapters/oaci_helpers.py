"""
Aide à la saisie — suggestion du prochain code OACI libre.
Lecture seule, aucune écriture. Reprend la même requête que la version
console originale (saisir_nouvel_avion), simplement exposée en fonction
réutilisable pour l'interface web.
"""

from typing import Optional

from database import DatabaseManager
from models import CodeOACI


def code_oaci_suggere(db: DatabaseManager) -> Optional[str]:
    with db.session_scope() as session:
        code_libre = (
            session.query(CodeOACI)
            .filter_by(statut_disponibilite="LIBRE")
            .order_by(CodeOACI.code_hexa)
            .first()
        )
        return code_libre.code_hexa if code_libre else None


def nombre_codes_libres(db: DatabaseManager) -> int:
    with db.session_scope() as session:
        return session.query(CodeOACI).filter_by(statut_disponibilite="LIBRE").count()
