"""
APPLICATION WEB — SYSTÈME OACI MADAGASCAR
============================================
Couche d'orchestration Streamlit. N'exécute AUCUNE logique métier propre :
appelle uniquement les services et modules partagés (OACIService, AuthService,
adapters/*) qui encapsulent déjà les règles définies dans gestion_oaci.py et
gestion_utilisateurs.py. Les deux programmes originaux et leurs réécritures
sécurisées ne sont jamais modifiés par ce fichier.
"""
import pandas as pd
import os
import tempfile
from datetime import datetime, timedelta
import streamlit as st
from sqlalchemy import func
from models import JournalActivite, Utilisateur

# --- Pont optionnel st.secrets -> variables d'environnement -----------------
# Permet un déploiement sur Streamlit Cloud (secrets.toml) tout en gardant
# db_config.py strictement basé sur les variables d'environnement.
try:
    for _cle in ("OACI_DB_HOST", "OACI_DB_PORT", "OACI_DB_NAME", "OACI_DB_USER",
                 "OACI_DB_PASSWORD", "OACI_DB_SSLMODE", "OACI_MDP_LONGUEUR_MIN",
                 "OACI_MAX_TENTATIVES", "OACI_VERROUILLAGE_MIN", "OACI_BCRYPT_COST"):
        if _cle in st.secrets and _cle not in os.environ:
            os.environ[_cle] = str(st.secrets[_cle])
except Exception:
    pass  # pas de secrets.toml en local : on utilise .env / variables système

from db_config import charger_configuration, ConfigurationError
from database import DatabaseManager
from auth_service import AuthService
from gestion_oaci import OACIService, initialiser_codes_oaci, initialiser_utilisateurs_defaut
from adapters import utilisateurs_adapter as ua
from adapters import oaci_helpers
from ui.styles import css


# ==============================================================================
# CONFIGURATION DE PAGE
# ==============================================================================

st.set_page_config(page_title="Système OACI — Madagascar", page_icon="✈", layout="wide")
st.markdown(css(), unsafe_allow_html=True)


# ==============================================================================
# INFRASTRUCTURE (connexion, une seule fois par processus serveur)
# ==============================================================================

@st.cache_resource(show_spinner="Connexion au système...")
def obtenir_infrastructure():
    db_config, politique, app_config = charger_configuration()
    db = DatabaseManager(db_config)
    if not db.verifier_connexion():
        raise RuntimeError(f"Connexion impossible à {db_config.url_affichable()}")
    db.creer_tables()
    initialiser_codes_oaci(db, app_config)
    return db, politique, app_config


def ecran_erreur_infrastructure(erreur: Exception):
    st.error(
        "❌ Le système n'a pas pu s'initialiser.\n\n"
        "**Cause probable :** la base de données PostgreSQL n'est pas accessible, "
        "ou la configuration (variables d'environnement) est incomplète.\n\n"
        "**Solution possible :** vérifiez que PostgreSQL est démarré et que le fichier "
        "`.env` (ou les secrets Streamlit) contient `OACI_DB_USER` et `OACI_DB_PASSWORD`."
    )
    with st.expander("Détails techniques (mode développeur)"):
        st.code(str(erreur))


try:
    db, politique, app_config = obtenir_infrastructure()
except (ConfigurationError, RuntimeError) as e:
    ecran_erreur_infrastructure(e)
    st.stop()


# ==============================================================================
# INITIALISATION DES COMPTES PAR DÉFAUT (premier lancement uniquement)
# ==============================================================================

def aucun_utilisateur_existant() -> bool:
    from models import Utilisateur
    with db.session_scope() as session:
        return session.query(Utilisateur).count() == 0


if "identifiants_initiaux" not in st.session_state:
    st.session_state.identifiants_initiaux = None

if st.session_state.identifiants_initiaux:
    st.markdown("## Première initialisation du système")
    st.warning(
        "⚠ Ces identifiants ne s'afficheront plus jamais. Notez-les maintenant "
        "dans un gestionnaire de mots de passe avant de continuer."
    )
    for nom, mdp in st.session_state.identifiants_initiaux:
        st.markdown(f"**{nom}** — <span class='code-technique'>{mdp}</span>", unsafe_allow_html=True)
    st.caption("Un changement de mot de passe sera exigé à la première connexion de chaque compte.")
    if st.button("J'ai noté ces identifiants — aller à la connexion", type="primary"):
        st.session_state.identifiants_initiaux = None
        st.rerun()
    st.stop()

if aucun_utilisateur_existant():
    st.markdown("## Première initialisation du système")
    st.info(
        "Aucun utilisateur n'existe encore dans la base. Cliquez ci-dessous pour créer "
        "les comptes par défaut (administrateur, agent, lecteur) avec des mots de passe "
        "temporaires générés aléatoirement."
    )
    if st.button("Initialiser les comptes par défaut", type="primary"):
        identifiants = initialiser_utilisateurs_defaut(db, politique)
        st.session_state.identifiants_initiaux = identifiants
        st.rerun()
    st.stop()


# ==============================================================================
# AUTHENTIFICATION
# ==============================================================================

# On instancie AuthService à chaque exécution (très léger).
auth = AuthService(db, politique)

# Restauration robuste de la session à partir du nom d'utilisateur
if "username_connecte" in st.session_state:
    with db.session_scope() as session:
        # On recherche l'utilisateur actif par son nom (plus fiable que l'ID)
        user = session.query(Utilisateur).filter_by(
            nom_utilisateur=st.session_state.username_connecte, 
            actif=True
        ).first()
        
        if user:
            auth.utilisateur_actuel = user
            auth._id_utilisateur_actuel = user.id_utilisateur
            session.expunge(auth.utilisateur_actuel)
        else:
            # Le compte a été désactivé ou supprimé entre-temps
            st.session_state.pop("username_connecte", None)

def ecran_connexion():
    st.markdown(
        f"<div style='text-align:center; margin-top:3rem;'>"
        f"<h1 style='margin-bottom:0;'>✈ Système OACI</h1>"
        f"<p style='color:var(--text-secondary);'>{app_config.organisme}</p>"
        f"</div>",
        unsafe_allow_html=True,
    )
    _, col_centre, _ = st.columns([1, 1.1, 1])
    with col_centre:
        with st.container(border=True):
            with st.form("form_connexion"):
                nom = st.text_input("Nom d'utilisateur")
                mdp = st.text_input("Mot de passe", type="password")
                connecter = st.form_submit_button("Se connecter", type="primary", use_container_width=True)

            if connecter:
                if not nom or not mdp:
                    st.error("Veuillez renseigner votre nom d'utilisateur et votre mot de passe.")
                else:
                    succes, message = auth.connecter(nom, mdp, adresse_ip="interface-web")
                    if succes:
                        st.session_state.username_connecte = nom.strip().lower()
                        st.rerun()
                    else:
                        st.error(f"❌ {message}")
    st.stop()


if not auth.est_authentifie():
    ecran_connexion()


# ==============================================================================
# CHANGEMENT DE MOT DE PASSE OBLIGATOIRE
# ==============================================================================

if auth.utilisateur_actuel.doit_changer_mot_de_passe:
    st.markdown("## Changement de mot de passe requis")
    st.info("Pour des raisons de sécurité, vous devez définir un nouveau mot de passe avant de continuer.")
    _, col_centre, _ = st.columns([1, 1.1, 1])
    with col_centre:
        with st.container(border=True):
            with st.form("form_changement_mdp_oblig"):
                mdp_actuel = st.text_input("Mot de passe actuel (temporaire)", type="password")
                nouveau = st.text_input(
                    "Nouveau mot de passe", type="password",
                    help=f"Au moins {politique.longueur_min_mdp} caractères, majuscule, minuscule, chiffre, caractère spécial."
                )
                confirmation = st.text_input("Confirmer le nouveau mot de passe", type="password")
                valider = st.form_submit_button("Valider", type="primary", use_container_width=True)

            if valider:
                succes, message = ua.changer_son_mot_de_passe(
                    db, politique, auth,
                    mot_de_passe_actuel=mdp_actuel, nouveau_mot_de_passe=nouveau, confirmation=confirmation,
                )
                if succes:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(f"❌ {message}")
    st.stop()


# ==============================================================================
# EN-TÊTE APPLICATIF
# ==============================================================================

user = auth.utilisateur_actuel
st.markdown(
    f"""
    <div class="app-header">
        <div>
            <h1>✈ Système OACI — Madagascar</h1>
            <div class="organisme">{app_config.organisme}</div>
        </div>
        <div class="session-info">
            Connecté : <strong>{user.nom_complet}</strong>
            <span class="role-badge">{user.role}</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown(f"**{user.nom_complet}**")
    st.caption(f"{user.nom_utilisateur} · {user.role}")
    st.divider()
    if st.button("Changer mon mot de passe", use_container_width=True):
        st.session_state.afficher_changement_mdp = True
    if st.button("Se déconnecter", use_container_width=True):
        auth.deconnecter(adresse_ip="interface-web")
        st.session_state.pop("username_connecte", None)  # On retire juste le nom d'utilisateur
        st.rerun()

    if st.session_state.get("afficher_changement_mdp"):
        st.divider()
        with st.form("form_changement_mdp_volontaire"):
            st.caption("Changer mon mot de passe")
            mdp_actuel = st.text_input("Mot de passe actuel", type="password", key="mdp_actuel_sidebar")
            nouveau = st.text_input("Nouveau mot de passe", type="password", key="mdp_nouveau_sidebar")
            confirmation = st.text_input("Confirmer", type="password", key="mdp_confirm_sidebar")
            valider = st.form_submit_button("Valider")
        if valider:
            succes, message = ua.changer_son_mot_de_passe(
                db, politique, auth,
                mot_de_passe_actuel=mdp_actuel, nouveau_mot_de_passe=nouveau, confirmation=confirmation,
            )
            if succes:
                st.success(message)
                st.session_state.afficher_changement_mdp = False
            else:
                st.error(message)


# ==============================================================================
# NAVIGATION PRINCIPALE
# ==============================================================================

service = OACIService(db, auth)

onglets_labels = []
if auth.a_permission("ecrire"):
    onglets_labels.append("Enregistrer un avion")
onglets_labels.append("Rechercher")
onglets_labels.append("Statistiques")
if auth.a_permission("exporter"):
    onglets_labels.append("Export")
if auth.a_permission("admin"):
    onglets_labels.append("Utilisateurs")
    onglets_labels.append("Audit & Logs")

onglets = st.tabs(onglets_labels)
onglets_par_nom = dict(zip(onglets_labels, onglets))


# --- Onglet : Enregistrer un avion ------------------------------------------
if "Enregistrer un avion" in onglets_par_nom:
    with onglets_par_nom["Enregistrer un avion"]:
        st.subheader("Enregistrement d'un nouvel avion")

        codes_libres = oaci_helpers.nombre_codes_libres(db)
        if codes_libres == 0:
            st.warning("⚠ Aucun code OACI disponible. Aucun nouvel avion ne peut être enregistré.")
        else:
            st.caption(f"{codes_libres} code(s) OACI disponible(s)")
            suggestion = oaci_helpers.code_oaci_suggere(db) or ""

            with st.form("form_nouvel_avion", clear_on_submit=True):
                col1, col2 = st.columns(2)
                with col1:
                    immatriculation = st.text_input(
                        "Immatriculation *", placeholder=f"{app_config.prefixe_immat}-MAB"
                    ).strip().upper()
                    constructeur = st.text_input("Constructeur *", placeholder="Cessna")
                    modele = st.text_input("Modèle *", placeholder="172")
                    numero_serie = st.text_input("Numéro de série")
                with col2:
                    proprietaire = st.text_input("Propriétaire *")
                    exploitant = st.text_input("Exploitant (si différent du propriétaire)")
                    base_operation = st.text_input("Base d'opération", placeholder="FMMI")
                    type_transpondeur = st.selectbox(
                        "Type de transpondeur", ["Mode A", "Mode S", "ADS-B"]
                    )

                code_oaci = st.text_input(
                    "Code OACI", value=suggestion,
                    help="Suggestion automatique du prochain code libre. Modifiable si nécessaire."
                ).strip().upper()
                remarques = st.text_area("Remarques", height=80)

                st.caption("* Champs obligatoires")
                soumis = st.form_submit_button("Enregistrer l'avion", type="primary")

            if soumis:
                donnees = {
                    "immatriculation": immatriculation, "constructeur": constructeur, "modele": modele,
                    "numero_serie": numero_serie, "type_transpondeur": type_transpondeur,
                    "proprietaire": proprietaire, "exploitant": exploitant, "base_operation": base_operation,
                    "code_oaci": code_oaci, "remarques": remarques,
                }
                with st.spinner("Enregistrement en cours..."):
                    succes, message = service.enregistrer_avion(donnees)
                if succes:
                    st.success(f"✅ {message}")
                else:
                    st.error(f"❌ {message}")


# --- Onglet : Rechercher -----------------------------------------------------
with onglets_par_nom["Rechercher"]:
    st.subheader("Recherche d'avions")

    col_critere, col_valeur, col_bouton = st.columns([1, 2, 1])
    with col_critere:
        critere_libelle = st.selectbox("Rechercher par", ["Immatriculation", "Propriétaire", "Statut"])
    with col_valeur:
        valeur_recherche = st.text_input("Valeur recherchée", label_visibility="visible")
    with col_bouton:
        st.markdown("<div style='height:1.85rem'></div>", unsafe_allow_html=True)
        lancer_recherche = st.button("Rechercher", type="primary", use_container_width=True)

    map_critere = {"Immatriculation": "immatriculation", "Propriétaire": "proprietaire", "Statut": "statut"}

    if lancer_recherche:
        if not valeur_recherche.strip():
            st.warning("Saisissez une valeur à rechercher.")
        else:
            resultats = service.rechercher_avions(map_critere[critere_libelle], valeur_recherche)
            st.caption(f"{len(resultats)} résultat(s) trouvé(s)")
            if resultats:
                st.dataframe(
                    resultats,
                    use_container_width=True,
                    column_config={
                        "immatriculation": "Immatriculation", "constructeur": "Constructeur",
                        "modele": "Modèle", "type_transpondeur": "Transpondeur",
                        "proprietaire": "Propriétaire", "statut": "Statut", "code_oaci": "Code OACI",
                    },
                )
            else:
                st.info("Aucun avion ne correspond à ce critère.")


# --- Onglet : Statistiques ---------------------------------------------------
with onglets_par_nom["Statistiques"]:
    st.subheader("Vue d'ensemble")
    stats = service.obtenir_stats()

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Codes totaux", stats["total"])
    col2.metric("Attribués", stats["utilises"])
    col3.metric("Libres", stats["libres"])
    col4.metric("Taux d'occupation", f"{stats['occupation']:.1f}%")

    col_gauche, col_droite = st.columns(2)
    with col_gauche:
        st.markdown("**Avions par statut**")
        if stats["statuts"]:
            st.dataframe({"Statut": list(stats["statuts"].keys()), "Nombre": list(stats["statuts"].values())},
                         use_container_width=True, hide_index=True)
        else:
            st.caption("Aucune donnée.")
    with col_droite:
        st.markdown("**Modèles les plus fréquents**")
        if stats["types"]:
            st.dataframe({"Modèle": list(stats["types"].keys()), "Nombre": list(stats["types"].values())},
                         use_container_width=True, hide_index=True)
        else:
            st.caption("Aucune donnée.")


# --- Onglet : Export ----------------------------------------------------------
if "Export" in onglets_par_nom:
    with onglets_par_nom["Export"]:
        st.subheader("Export des données")
        st.caption("Génère un fichier des avions actuellement attribués.")

        format_choisi = st.radio("Format", ["CSV", "Excel"], horizontal=True)
        if st.button("Générer l'export", type="primary"):
            with st.spinner("Génération du fichier..."):
                succes, resultat = service.exporter_donnees(
                    "csv" if format_choisi == "CSV" else "excel",
                    dossier_sortie=tempfile.gettempdir(),
                )
            if succes:
                chemin_fichier = resultat
                with open(chemin_fichier, "rb") as f:
                    contenu = f.read()
                st.success("✅ Export généré.")
                st.download_button(
                    "Télécharger le fichier",
                    data=contenu,
                    file_name=os.path.basename(chemin_fichier),
                    mime="text/csv" if format_choisi == "CSV" else
                         "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.error(f"❌ {resultat}")


# --- Onglet : Utilisateurs (admin) --------------------------------------------
if "Utilisateurs" in onglets_par_nom:
    with onglets_par_nom["Utilisateurs"]:
        st.subheader("Gestion des utilisateurs")

        liste = ua.lister_utilisateurs(db)
        st.dataframe(
            [
                {
                    "Utilisateur": u.nom_utilisateur, "Nom complet": u.nom_complet, "Rôle": u.role,
                    "Actif": "Oui" if u.actif else "Non",
                    "Verrouillé": "Oui" if u.verrouille else "Non",
                    "Doit changer mdp": "Oui" if u.doit_changer_mot_de_passe else "Non",
                }
                for u in liste
            ],
            use_container_width=True, hide_index=True,
        )

        with st.expander("➕ Créer un utilisateur"):
            with st.form("form_creer_utilisateur", clear_on_submit=True):
                col1, col2 = st.columns(2)
                with col1:
                    n_utilisateur = st.text_input("Nom d'utilisateur")
                    n_complet = st.text_input("Nom complet")
                    n_email = st.text_input("E-mail (optionnel)")
                with col2:
                    role_choisi = st.selectbox("Rôle", ["lecteur", "agent", "administrateur"])
                    n_mdp = st.text_input("Mot de passe initial", type="password")
                    n_mdp_confirm = st.text_input("Confirmer le mot de passe", type="password")
                st.caption(
                    f"Le mot de passe doit contenir au moins {politique.longueur_min_mdp} caractères, "
                    "une majuscule, une minuscule, un chiffre et un caractère spécial."
                )
                creer = st.form_submit_button("Créer l'utilisateur", type="primary")

            if creer:
                succes, message = ua.creer_utilisateur(
                    db, politique, auth,
                    nom_utilisateur=n_utilisateur, nom_complet=n_complet, email=n_email,
                    role=role_choisi, mot_de_passe=n_mdp, mot_de_passe_confirmation=n_mdp_confirm,
                )
                (st.success if succes else st.error)(f"{'✅' if succes else '❌'} {message}")

        with st.expander("🔓 Activer / désactiver un compte"):
            noms = [u.nom_utilisateur for u in liste]
            if noms:
                cible = st.selectbox("Utilisateur", noms, key="select_activation")
                etat_actuel = next(u.actif for u in liste if u.nom_utilisateur == cible)
                action_libelle = "Désactiver ce compte" if etat_actuel else "Réactiver ce compte"

                if etat_actuel:
                    st.caption("⚠ Action de désactivation : l'utilisateur ne pourra plus se connecter.")

                declencher = st.button(
                    action_libelle,
                    type="secondary" if etat_actuel else "primary",
                    use_container_width=True,
                )
                if declencher:
                    succes, message = ua.basculer_activation(db, auth, cible, activer=not etat_actuel)
                    (st.success if succes else st.error)(f"{'✅' if succes else '❌'} {message}")

        with st.expander("🔑 Déverrouiller un compte"):
            noms_verrouilles = [u.nom_utilisateur for u in liste if u.verrouille]
            if not noms_verrouilles:
                st.caption("Aucun compte verrouillé actuellement.")
            else:
                cible = st.selectbox("Compte verrouillé", noms_verrouilles, key="select_deverrouillage")
                if st.button("Déverrouiller"):
                    succes, message = ua.deverrouiller_compte(db, auth, cible)
                    (st.success if succes else st.error)(f"{'✅' if succes else '❌'} {message}")

        with st.expander("♻️ Réinitialiser un mot de passe"):
            noms = [u.nom_utilisateur for u in liste]
            if noms:
                cible = st.selectbox("Utilisateur", noms, key="select_reinit")
                if st.button("Générer un nouveau mot de passe temporaire"):
                    succes, resultat = ua.reinitialiser_mot_de_passe(db, politique, auth, cible)
                    if succes:
                        st.success(f"✅ Mot de passe temporaire pour '{cible}' :")
                        st.markdown(f"<span class='code-technique'>{resultat}</span>", unsafe_allow_html=True)
                        st.caption(
                            "⚠ Communiquez-le par un canal sûr. L'utilisateur devra le changer "
                            "à sa prochaine connexion."
                        )
                    else:
                        st.error(f"❌ {resultat}")
# --- Onglet : Audit & Logs (admin uniquement) --------------------------------
if "Audit & Logs" in onglets_par_nom:
    with onglets_par_nom["Audit & Logs"]:
        st.subheader("Journal d'audit et traçabilité")
        st.caption("Historique de toutes les actions sensibles effectuées dans le système.")

        # 1. Filtres de recherche
        col1, col2, col3 = st.columns(3)
        with col1:
            liste_users = ua.lister_utilisateurs(db)
            noms_users = ["Tous"] + [u.nom_utilisateur for u in liste_users]
            filtre_utilisateur = st.selectbox("Utilisateur", noms_users)

        with col2:
            filtre_action = st.selectbox(
                "Type d'action",
                ["Toutes", "LOGIN_SUCCES", "LOGIN_ECHEC", "AJOUT", "EXPORT", "LOGOUT", "CREATION_UTILISATEUR"]
            )

        with col3:
            limite = st.slider("Nombre de lignes à afficher", 10, 500, 50)

        # 2. Requête et extraction des données (CORRECTION ULTIME)
        df_logs = []
        
        with db.session_scope() as session:
            # On sélectionne explicitement les colonnes, y compris le nom d'utilisateur via une jointure.
            # Cela évite TOUT chargement paresseux (lazy loading) et l'erreur DetachedInstanceError.
            query = session.query(
                JournalActivite.date_heure,
                JournalActivite.action,
                JournalActivite.entite_concernee,
                JournalActivite.details,
                JournalActivite.adresse_ip,
                JournalActivite.succes,
                Utilisateur.nom_utilisateur.label('nom_utilisateur') # Le nom est récupéré directement
            ).outerjoin(Utilisateur, JournalActivite.id_utilisateur == Utilisateur.id_utilisateur)

            if filtre_utilisateur != "Tous":
                query = query.filter(Utilisateur.nom_utilisateur == filtre_utilisateur)
            if filtre_action != "Toutes":
                query = query.filter(JournalActivite.action == filtre_action)

            query = query.order_by(JournalActivite.date_heure.desc()).limit(limite)
            logs = query.all()

            # On construit la liste TANT QUE la session est ouverte, en utilisant les données plates.
            for log in logs:
                df_logs.append({
                    "Date/Heure": log.date_heure.strftime("%Y-%m-%d %H:%M:%S") if log.date_heure else "N/A",
                    "Utilisateur": log.nom_utilisateur or "Système",  # Plus de log.utilisateur !
                    "Action": log.action,
                    "Entité": log.entite_concernee,
                    "Détails": log.details,
                    "IP": log.adresse_ip or "N/A",
                    "Résultat": "✅ Succès" if log.succes else "❌ Échec"
                })

        # 3. Affichage des résultats (HORS du bloc with, en utilisant df_logs)
        if df_logs:
            st.dataframe(df_logs, use_container_width=True, hide_index=True)

            # Bouton d'export des logs
            csv = pd.DataFrame(df_logs).to_csv(index=False, encoding="utf-8-sig").encode('utf-8')
            st.download_button(
                "📥 Exporter les logs en CSV",
                csv,
                f"audit_oaci_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                "text/csv",
                use_container_width=True
            )
        else:
            st.info("Aucun log ne correspond aux critères de filtrage.")

        # 4. Statistiques rapides (24 dernières heures)
        st.divider()
        st.subheader("📊 Statistiques d'activité (24 dernières heures)")
        with db.session_scope() as session:
            hier = datetime.now() - timedelta(days=1)

            total_actions = session.query(func.count(JournalActivite.id_journal)).filter(
                JournalActivite.date_heure >= hier
            ).scalar() or 0

            connexions = session.query(func.count(JournalActivite.id_journal)).filter(
                JournalActivite.date_heure >= hier, JournalActivite.action == "LOGIN_SUCCES"
            ).scalar() or 0

            echecs = session.query(func.count(JournalActivite.id_journal)).filter(
                JournalActivite.date_heure >= hier, JournalActivite.action == "LOGIN_ECHEC"
            ).scalar() or 0

            ajouts = session.query(func.count(JournalActivite.id_journal)).filter(
                JournalActivite.date_heure >= hier, JournalActivite.action == "AJOUT"
            ).scalar() or 0

        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        col_m1.metric("Total actions", total_actions)
        col_m2.metric("Connexions réussies", connexions)
        col_m3.metric("Échecs de connexion", echecs, delta_color="inverse")
        col_m4.metric("Avions ajoutés", ajouts)