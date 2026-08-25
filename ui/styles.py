"""
SYSTÈME DE DESIGN — SYSTÈME OACI MADAGASCAR
==============================================
Palette fonctionnelle (chaque couleur a un rôle unique, pas de décoration
gratuite) et échelle typographique cohérente. Injecté en CSS au sommet
de app.py.

Choix assumés :
  - Un seul accent (bleu aviation, proche du bleu OACI officiel) — jamais
    mélangé avec les couleurs d'état (succès/alerte/erreur).
  - Police utilitaire à chasse fixe (JetBrains Mono) réservée aux
    identifiants techniques (immatriculations, codes hexadécimaux) pour
    les distinguer visuellement du texte courant — pas une décoration,
    une aide à la lecture des données.
  - Pas de dégradé, pas de glassmorphism, coins peu arrondis (look
    utilitaire plutôt que "produit grand public").
"""

TOKENS = {
    "background_primary": "#F4F5F7",
    "background_secondary": "#EAECEF",
    "surface": "#FFFFFF",
    "surface_elevated": "#FFFFFF",
    "text_primary": "#16212E",
    "text_secondary": "#5B6B7C",
    "border": "#D8DDE3",
    "accent": "#1D4E89",
    "accent_hover": "#163C69",
    "success": "#1E7145",
    "success_bg": "#E7F3EC",
    "warning": "#8A5A0B",
    "warning_bg": "#FBF0DD",
    "error": "#B3261E",
    "error_bg": "#FBEAE9",
    "info": "#2B6CB0",
    "info_bg": "#E8F0FA",
    "focus": "#1D4E89",
}


def css() -> str:
    t = TOKENS
    return f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;600&display=swap');

:root {{
    --bg-primary: {t['background_primary']};
    --bg-secondary: {t['background_secondary']};
    --surface: {t['surface']};
    --text-primary: {t['text_primary']};
    --text-secondary: {t['text_secondary']};
    --border: {t['border']};
    --accent: {t['accent']};
    --accent-hover: {t['accent_hover']};
    --success: {t['success']};
    --success-bg: {t['success_bg']};
    --warning: {t['warning']};
    --warning-bg: {t['warning_bg']};
    --error: {t['error']};
    --error-bg: {t['error_bg']};
    --info: {t['info']};
    --info-bg: {t['info_bg']};
}}

html, body, [class*="css"] {{
    font-family: 'Inter', -apple-system, sans-serif;
    color: var(--text-primary);
}}

.stApp {{
    background-color: var(--bg-primary);
}}

/* Identifiants techniques : immatriculations, codes hexa, en chasse fixe */
.code-technique {{
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600;
    letter-spacing: 0.02em;
    background: var(--bg-secondary);
    padding: 1px 6px;
    border-radius: 4px;
    color: var(--text-primary);
}}

/* En-tête applicatif */
.app-header {{
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    padding: 0.75rem 0 1rem 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 1.25rem;
}}
.app-header h1 {{
    font-size: 1.35rem;
    font-weight: 700;
    margin: 0;
    color: var(--text-primary);
}}
.app-header .organisme {{
    font-size: 0.85rem;
    color: var(--text-secondary);
    margin-top: 2px;
}}
.app-header .session-info {{
    text-align: right;
    font-size: 0.85rem;
    color: var(--text-secondary);
    line-height: 1.4;
}}
.app-header .session-info .role-badge {{
    display: inline-block;
    font-size: 0.72rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.03em;
    color: var(--accent);
    background: var(--info-bg);
    padding: 2px 8px;
    border-radius: 4px;
    margin-left: 6px;
}}

/* Boutons primaires : accent unique, pas de gros boutons */
.stButton > button[kind="primary"] {{
    background-color: var(--accent);
    border-color: var(--accent);
}}
.stButton > button[kind="primary"]:hover {{
    background-color: var(--accent-hover);
    border-color: var(--accent-hover);
}}

/* Cartes de métrique sobres */
[data-testid="stMetric"] {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 0.85rem 1rem;
}}

hr {{
    border-color: var(--border);
}}

/* Focus clavier visible (accessibilité) */
*:focus-visible {{
    outline: 2px solid var(--focus);
    outline-offset: 1px;
}}
</style>
"""
