"""Human-readable detection rule catalog and MITRE ATT&CK references."""

RULES = {
    "AUTH-001": {
        "title": "Fuerza bruta por origen",
        "severity": "Alta",
        "technique": "T1110.001",
        "technique_name": "Password Guessing",
        "description": "Muchos intentos fallidos de autenticación desde la misma dirección IP en una ventana temporal.",
        "recommendation": "Revisar intentos de acceso, cuentas objetivo y MFA; aplicar límites de autenticación y bloquear el origen solamente tras validarlo.",
    },
    "AUTH-002": {
        "title": "Fuerza bruta contra una cuenta",
        "severity": "Alta",
        "technique": "T1110.001",
        "technique_name": "Password Guessing",
        "description": "Múltiples fallos del mismo origen contra una cuenta concreta.",
        "recommendation": "Confirmar los intentos con el propietario de la cuenta, revisar accesos recientes y verificar MFA.",
    },
    "AUTH-003": {
        "title": "Posible password spraying",
        "severity": "Alta",
        "technique": "T1110.003",
        "technique_name": "Password Spraying",
        "description": "Un origen intenta autenticarse sin éxito en varias cuentas distintas con pocos intentos por cuenta.",
        "recommendation": "Investigar el origen, comprobar las cuentas afectadas y revisar controles de acceso, MFA y limitación de intentos.",
    },
    "AUTH-004": {
        "title": "Acceso correcto tras varios fallos",
        "severity": "Crítica",
        "technique": "T1078",
        "technique_name": "Valid Accounts",
        "description": "Un mismo origen logra autenticarse en una cuenta después de varios intentos fallidos. No confirma compromiso.",
        "recommendation": "Verificar con el usuario si reconoce el inicio de sesión; revisar MFA, dispositivo, sesión y actividad posterior.",
    },
    "AUTH-005": {
        "title": "Inicio de sesión fuera de horario",
        "severity": "Baja",
        "technique": "T1078",
        "technique_name": "Valid Accounts (solo hipótesis contextual)",
        "description": "Inicio de sesión correcto entre las 00:00 y las 05:59 (zona horaria seleccionada). Señal contextual débil.",
        "recommendation": "Comprobar turnos, viajes, automatizaciones y comportamiento habitual antes de tratarlo como amenaza.",
    },
}

MITRE_BASE = "https://attack.mitre.org/techniques/"


def technique_url(technique: str) -> str:
    # Official MITRE URL convention uses a slash for sub-technique IDs.
    if "." in technique:
        main, sub = technique.split(".", 1)
        return f"{MITRE_BASE}{main}/{sub}/"
    return f"{MITRE_BASE}{technique}/"
