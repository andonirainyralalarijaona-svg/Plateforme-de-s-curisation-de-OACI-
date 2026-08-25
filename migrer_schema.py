"""
MIGRATION UNIQUE — ajout des colonnes de sécurité manquantes
================================================================
À exécuter UNE FOIS si votre base contient déjà les tables `utilisateur`
et/ou `session` créées par une version antérieure des scripts (avant
l'ajout du verrouillage de compte, du hachage bcrypt, et de la persistance
de session par cookie). Cette migration N'EFFACE AUCUNE DONNÉE : elle
ajoute uniquement les colonnes manquantes.

Usage : python migrer_schema.py
"""

import sys
from sqlalchemy import text

from db_config import charger_configuration, ConfigurationError
from database import DatabaseManager


# table -> liste de (nom_colonne, définition SQL)
COLONNES_A_AJOUTER = {
    "utilisateur": [
        ("derniere_connexion", "TIMESTAMP"),
        ("tentatives_echouees", "INTEGER NOT NULL DEFAULT 0"),
        ("verrouille_jusqu_a", "TIMESTAMP"),
        ("doit_changer_mot_de_passe", "BOOLEAN NOT NULL DEFAULT FALSE"),
    ],
    "session": [
        ("jeton_session", "VARCHAR(64) UNIQUE"),
    ],
}


def colonne_existe(connexion, table: str, colonne: str) -> bool:
    resultat = connexion.execute(
        text(
            "SELECT 1 FROM information_schema.columns "
            "WHERE table_name = :table AND column_name = :colonne"
        ),
        {"table": table, "colonne": colonne},
    )
    return resultat.first() is not None


def main():
    try:
        db_config, _, _ = charger_configuration()
    except ConfigurationError as e:
        print(f"✗ Erreur de configuration : {e}")
        sys.exit(1)

    db = DatabaseManager(db_config)
    if not db.verifier_connexion():
        print(f"✗ Connexion impossible à {db_config.url_affichable()}")
        sys.exit(1)

    print(f"→ Connecté à {db_config.url_affichable()}")

    with db.engine.begin() as connexion:
        for nom_table, colonnes in COLONNES_A_AJOUTER.items():
            table_existe = connexion.execute(
                text("SELECT 1 FROM information_schema.tables WHERE table_name = :table"),
                {"table": nom_table},
            ).first()

            if not table_existe:
                print(f"ℹ La table '{nom_table}' n'existe pas encore — elle sera créée au lancement de l'application.")
                continue

            print(f"→ Table '{nom_table}' :")
            for nom_colonne, definition in colonnes:
                if colonne_existe(connexion, nom_table, nom_colonne):
                    print(f"  = '{nom_colonne}' existe déjà, ignorée.")
                else:
                    connexion.execute(text(f"ALTER TABLE {nom_table} ADD COLUMN {nom_colonne} {definition}"))
                    print(f"  + '{nom_colonne}' ajoutée.")

    print("\n✅ Migration terminée. Vos données existantes sont intactes.")
    print("   Vous pouvez maintenant relancer : streamlit run app.py")


if __name__ == "__main__":
    main()
