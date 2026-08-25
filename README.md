# Système OACI Madagascar — version sécurisée

## Installation

```bash
pip install -r requirements.txt
cp .env.example .env
# Éditez .env : renseignez OACI_DB_USER et OACI_DB_PASSWORD au minimum
```

## Lancement

```bash
# Interface web (recommandé)
streamlit run app.py

# Ou en ligne de commande, séparément :
python gestion_oaci.py
python gestion_utilisateurs.py
```

Au tout premier lancement, aucun utilisateur n'existe : l'application (web ou
console) propose de créer les comptes par défaut avec des mots de passe
temporaires générés aléatoirement, affichés **une seule fois**. Notez-les
immédiatement — un changement de mot de passe sera exigé à la première
connexion.

## Fichiers

| Fichier | Rôle |
|---|---|
| `db_config.py` | configuration (lecture depuis l'environnement, aucun secret en dur) |
| `security.py` | hachage bcrypt, politique de mot de passe, validation des entrées |
| `models.py` | schéma de données unique, partagé par les deux programmes |
| `database.py` | connexion / pool / sessions |
| `auth_service.py` | authentification, verrouillage de compte, permissions |
| `gestion_utilisateurs.py` | **Programme 1** — gestion des comptes (CLI, accès administrateur requis) |
| `gestion_oaci.py` | **Programme 2** — avions, codes OACI, statistiques, export (CLI) |
| `adapters/` | logique des deux programmes exposée sans `input()`/`print()`, pour l'interface web |
| `ui/styles.py` | palette de couleurs et typographie de l'interface |
| `app.py` | **interface Streamlit** — orchestre les deux programmes, ne contient aucune règle métier propre |

## Ce qui a changé par rapport à vos deux scripts d'origine

- Mots de passe : SHA-256 nu → **bcrypt salé**.
- Identifiants de base de données : codés en dur / saisis en clair → **variables d'environnement**.
- Connexion : aucun verrouillage → **verrouillage de compte après échecs répétés**.
- `gestion.py` original : aucune authentification requise pour créer un admin → **connexion administrateur obligatoire**.
- Comptes par défaut `admin/admin123` etc. (publics) → **mots de passe temporaires aléatoires, changement obligatoire à la 1ère connexion**.
- Entrées utilisateur (immatriculation, code OACI, email, nom d'utilisateur) → **validées par expression régulière** avant toute écriture.
- Erreurs techniques → **plus jamais affichées brutalement** à l'utilisateur final (mode développeur disponible séparément).
- Journal d'audit renforcé (adresse IP, succès/échec, horodatage systématique).

## Limites connues / à valider avec vous

- L'export écrit un fichier temporaire côté serveur avant proposition au téléchargement (`tempfile.gettempdir()`) : normal en local ou sur un serveur classique ; à surveiller si vous déployez sur une plateforme au système de fichiers éphémère.
- Le niveau `sslmode=prefer` par défaut pour PostgreSQL est un compromis ; passez `OACI_DB_SSLMODE=require` en production si votre réseau n'est pas fiable.
- Aucune notion de session HTTP expirée après inactivité n'est implémentée côté Streamlit (au-delà de la fermeture du navigateur) — dites-moi si vous voulez un timeout applicatif en plus du verrouillage de compte.
