"""
config_manager.py — Manejo seguro de API keys locales
Guarda las credenciales encriptadas en ~/.config/osint-ai/config.json
"""

import json
import os
import base64
from pathlib import Path
from cryptography.fernet import Fernet
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich import print as rprint

console = Console()

CONFIG_DIR  = Path.home() / ".config" / "osint-ai"
CONFIG_FILE = CONFIG_DIR / "config.json"
KEY_FILE    = CONFIG_DIR / ".key"

PROVIDERS = {
    "1": {
        "name":    "Claude (Anthropic)",
        "id":      "claude",
        "env":     "ANTHROPIC_API_KEY",
        "url":     "https://console.anthropic.com/",
        "prefix":  "sk-ant-",
        "model":   "claude-sonnet-4-6",
    },
    "2": {
        "name":    "GPT-4 (OpenAI)",
        "id":      "openai",
        "env":     "OPENAI_API_KEY",
        "url":     "https://platform.openai.com/api-keys",
        "prefix":  "sk-",
        "model":   "gpt-4o",
    },
    "3": {
        "name":    "Grok (xAI)",
        "id":      "grok",
        "env":     "XAI_API_KEY",
        "url":     "https://console.x.ai/",
        "prefix":  "xai-",
        "model":   "grok-3",
    },
    "4": {
        "name":    "Gemini (Google)",
        "id":      "gemini",
        "env":     "GEMINI_API_KEY",
        "url":     "https://aistudio.google.com/app/apikey",
        "prefix":  "AIza",
        "model":   "gemini-2.0-flash",
    },
}


# ── Encriptación ──────────────────────────────────────────────────────────────

def _get_or_create_fernet() -> Fernet:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    if KEY_FILE.exists():
        key = KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        KEY_FILE.write_bytes(key)
        KEY_FILE.chmod(0o600)
    return Fernet(key)


def _encrypt(text: str) -> str:
    f = _get_or_create_fernet()
    return f.encrypt(text.encode()).decode()


def _decrypt(token: str) -> str:
    f = _get_or_create_fernet()
    return f.decrypt(token.encode()).decode()


# ── Persistencia ──────────────────────────────────────────────────────────────

def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}


def _save_config(cfg: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))
    CONFIG_FILE.chmod(0o600)


# ── UI de selección ───────────────────────────────────────────────────────────

def _show_provider_menu(current_id: str | None = None):
    console.print("\n[bold red]  Proveedor de IA[/bold red]\n")
    for key, p in PROVIDERS.items():
        marker = " [green]← actual[/green]" if p["id"] == current_id else ""
        console.print(f"  [bold cyan]{key}[/bold cyan]  {p['name']}{marker}")
    console.print()


def _pick_provider(current_id: str | None = None) -> dict:
    _show_provider_menu(current_id)
    while True:
        choice = Prompt.ask("[bold]Elegí un proveedor[/bold]", choices=list(PROVIDERS.keys()))
        return PROVIDERS[choice]


def _input_api_key(provider: dict) -> str:
    console.print(f"\n[dim]Conseguí tu key en: {provider['url']}[/dim]")
    while True:
        key = Prompt.ask(f"[bold]API Key de {provider['name']}[/bold]", password=True)
        key = key.strip()
        if not key:
            console.print("[red]La key no puede estar vacía.[/red]")
            continue
        if not key.startswith(provider["prefix"]):
            console.print(f"[yellow]⚠ La key debería empezar con '{provider['prefix']}'. ¿Es correcta?[/yellow]")
            if not Confirm.ask("¿Continuar igual?", default=False):
                continue
        return key


# ── API pública ───────────────────────────────────────────────────────────────

def setup_interactive(force: bool = False) -> dict:
    """
    Muestra el menú de configuración al arrancar.
    - Si no hay config guardada → la pide obligatoriamente.
    - Si ya hay config → muestra la actual y pregunta si quiere cambiarla.
    Devuelve {"provider": {...}, "api_key": "..."}.
    """
    cfg = _load_config()
    has_config = bool(cfg.get("provider_id") and cfg.get("api_key_enc"))

    if has_config and not force:
        current = next((p for p in PROVIDERS.values() if p["id"] == cfg["provider_id"]), None)
        name = current["name"] if current else cfg["provider_id"]

        console.print(Panel(
            f"[green]✓ Config actual:[/green] [bold]{name}[/bold]\n"
            f"[dim]API key: {'*' * 12 + cfg.get('api_key_enc','')[-4:]}[/dim]",
            title="[bold red]OSINT AI — Configuración[/bold red]",
            border_style="red"
        ))

        if not Confirm.ask("¿Querés cambiar la configuración?", default=False):
            try:
                api_key = _decrypt(cfg["api_key_enc"])
                provider = next(p for p in PROVIDERS.values() if p["id"] == cfg["provider_id"])
                return {"provider": provider, "api_key": api_key}
            except Exception:
                console.print("[red]Error leyendo la config guardada. Reconfigurando...[/red]")

    # Primera vez o quiere cambiar
    console.print(Panel(
        "Configurá tu proveedor de IA.\n[dim]La key se guarda encriptada en tu PC y nunca sale de ella.[/dim]",
        title="[bold red]OSINT AI — Setup[/bold red]",
        border_style="red"
    ))

    provider = _pick_provider(current_id=cfg.get("provider_id"))
    api_key  = _input_api_key(provider)

    _save_config({
        "provider_id":  provider["id"],
        "api_key_enc":  _encrypt(api_key),
    })

    console.print(f"\n[green]✓ Guardado correctamente.[/green] Config en: [dim]{CONFIG_FILE}[/dim]\n")
    return {"provider": provider, "api_key": api_key}


def get_saved_config() -> dict | None:
    """Carga config silenciosamente (sin UI). Devuelve None si no hay nada."""
    cfg = _load_config()
    if not cfg.get("provider_id") or not cfg.get("api_key_enc"):
        return None
    try:
        provider = next((p for p in PROVIDERS.values() if p["id"] == cfg["provider_id"]), None)
        if not provider:
            return None
        return {"provider": provider, "api_key": _decrypt(cfg["api_key_enc"])}
    except Exception:
        return None
