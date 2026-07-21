#!/usr/bin/env python3
"""
OSINT Person Finder AI — by BlackSec
CLI de reconocimiento OSINT con análisis por IA (Claude, GPT-4, Grok, Gemini).
"""

import argparse
import asyncio
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

from config_manager import setup_interactive

console = Console()

BANNER = """[bold red]
  ██████╗ ███████╗██╗███╗   ██╗████████╗     █████╗ ██╗
 ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ██╔══██╗██║
 ██║   ██║███████╗██║██╔██╗ ██║   ██║       ███████║██║
 ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██╔══██║██║
 ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║  ██║██║
  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═╝╚═╝[/bold red]
[dim]  OSINT Person Finder — by BlackSec[/dim]
"""

SHERLOCK_PLATFORMS = [
    ("GitHub",      "https://github.com/{}"),
    ("GitLab",      "https://gitlab.com/{}"),
    ("Twitter/X",   "https://twitter.com/{}"),
    ("Instagram",   "https://www.instagram.com/{}"),
    ("Reddit",      "https://www.reddit.com/user/{}"),
    ("TikTok",      "https://www.tiktok.com/@{}"),
    ("YouTube",     "https://www.youtube.com/@{}"),
    ("LinkedIn",    "https://www.linkedin.com/in/{}"),
    ("Pinterest",   "https://www.pinterest.com/{}"),
    ("Twitch",      "https://www.twitch.tv/{}"),
    ("Steam",       "https://steamcommunity.com/id/{}"),
    ("HackerNews",  "https://news.ycombinator.com/user?id={}"),
    ("DevTo",       "https://dev.to/{}"),
    ("Medium",      "https://medium.com/@{}"),
    ("Keybase",     "https://keybase.io/{}"),
    ("Pastebin",    "https://pastebin.com/u/{}"),
    ("Gravatar",    "https://en.gravatar.com/{}"),
    ("DockerHub",   "https://hub.docker.com/u/{}"),
    ("npm",         "https://www.npmjs.com/~{}"),
    ("PyPI",        "https://pypi.org/user/{}"),
]

# Alto: exponen bio, foto o datos verificables
# Medio: solo confirman existencia del username
# Bajo: propensas a falsos positivos (páginas que devuelven 200 sin usuario real)
PLATFORM_CONFIDENCE = {
    "GitHub":     "Alto",
    "GitLab":     "Alto",
    "Twitter/X":  "Alto",
    "Instagram":  "Alto",
    "Reddit":     "Alto",
    "LinkedIn":   "Alto",
    "Medium":     "Alto",
    "DevTo":      "Alto",
    "Keybase":    "Alto",
    "YouTube":    "Medio",
    "TikTok":     "Medio",
    "Twitch":     "Medio",
    "Steam":      "Medio",
    "Pinterest":  "Medio",
    "DockerHub":  "Medio",
    "HackerNews": "Bajo",
    "PyPI":       "Bajo",
    "npm":        "Bajo",
    "Gravatar":   "Bajo",
    "Pastebin":   "Bajo",
}

# ── Hooks APIs de pago (implementar después) ──────────────────────────────────

class PaidAPIHooks:
    @staticmethod
    async def shodan(query: str, api_key: str) -> dict:
        # TODO: https://api.shodan.io/shodan/host/search?key={api_key}&query={query}
        return {"status": "not_implemented", "service": "shodan"}

    @staticmethod
    async def hunter_io(email: str, api_key: str) -> dict:
        # TODO: https://api.hunter.io/v2/email-verifier?email={email}&api_key={api_key}
        return {"status": "not_implemented", "service": "hunter_io"}

    @staticmethod
    async def intelx(query: str, api_key: str) -> dict:
        return {"status": "not_implemented", "service": "intelx"}

    @staticmethod
    async def dehashed(query: str, api_key: str) -> dict:
        return {"status": "not_implemented", "service": "dehashed"}


# ── Búsquedas ─────────────────────────────────────────────────────────────────

async def check_username(username: str, client: httpx.AsyncClient) -> list[dict]:
    results = []

    async def check_one(name: str, url_tpl: str):
        url = url_tpl.format(username)
        try:
            r = await client.get(url, timeout=8.0, follow_redirects=True)
            found = r.status_code == 200
            fp_status = "FOUND"

            if found:
                if name == "PyPI":
                    # PyPI devuelve 200 aunque el usuario no tenga paquetes publicados
                    if 'href="/project/' not in r.text:
                        fp_status = "POSIBLE FP"
                elif name == "HackerNews":
                    # La página HN devuelve 200 para usuarios inexistentes; verificar con Algolia
                    try:
                        hn = await client.get(
                            f"https://hn.algolia.com/api/v1/search?tags=author_{username}&hitsPerPage=1",
                            timeout=5.0)
                        if hn.status_code == 200 and hn.json().get("nbHits", 0) == 0:
                            fp_status = "POSIBLE FP"
                    except Exception:
                        pass
                elif name == "npm":
                    # npm puede devolver 200 para usuarios sin paquetes publicados
                    try:
                        npm_r = await client.get(
                            f"https://registry.npmjs.org/-/v1/search?text=author:{username}&size=1",
                            timeout=5.0)
                        if npm_r.status_code == 200 and npm_r.json().get("total", 0) == 0:
                            fp_status = "POSIBLE FP"
                    except Exception:
                        pass
                elif name == "Steam":
                    # Steam devuelve 200 con este texto exacto cuando el perfil no existe
                    if "The specified profile could not be found" in r.text:
                        fp_status = "POSIBLE FP"
                elif name == "Twitch":
                    # Canales inexistentes devuelven <title>Twitch</title> genérico (sin nombre
                    # de canal); no usar el meta og:title porque Twitch lo emite con comillas
                    # simples (<meta property='og:title' content='Twitch'>).
                    if "<title>Twitch</title>" in r.text:
                        fp_status = "POSIBLE FP"

            confidence = PLATFORM_CONFIDENCE.get(name, "Medio") if found else None
            results.append({
                "platform": name, "url": url,
                "found": found, "status_code": r.status_code,
                "confidence": confidence, "fp_status": fp_status,
            })
        except Exception:
            results.append({
                "platform": name, "url": url,
                "found": False, "status_code": None,
                "confidence": None, "fp_status": "NOT FOUND",
            })

    await asyncio.gather(*[check_one(n, u) for n, u in SHERLOCK_PLATFORMS])
    return sorted(results, key=lambda x: x["found"], reverse=True)


def generate_username_variants(username: str) -> list[str]:
    return [f"{username}_", f"_{username}", f"{username}01", f"{username}1337"]


async def check_username_variants(username: str, client: httpx.AsyncClient) -> dict[str, list[dict]]:
    variants = generate_username_variants(username)
    results = await asyncio.gather(*[check_username(v, client) for v in variants])
    return dict(zip(variants, results))


async def check_github_profile(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://api.github.com/users/{username}", timeout=10.0,
                             headers={"Accept": "application/vnd.github.v3+json"})
        if r.status_code == 200:
            d = r.json()
            return {
                "found": True, "name": d.get("name"), "bio": d.get("bio"),
                "location": d.get("location"), "email": d.get("email"),
                "company": d.get("company"), "blog": d.get("blog"),
                "public_repos": d.get("public_repos"), "followers": d.get("followers"),
                "following": d.get("following"), "created_at": d.get("created_at"),
                "twitter_username": d.get("twitter_username"),
                "url": f"https://github.com/{username}",
            }
    except Exception:
        pass
    return {"found": False}


async def check_github_repos(username: str, client: httpx.AsyncClient) -> list[dict]:
    try:
        r = await client.get(f"https://api.github.com/users/{username}/repos?sort=updated&per_page=10", timeout=10.0)
        if r.status_code == 200:
            return [{"name": x["name"], "description": x.get("description"),
                     "language": x.get("language"), "stars": x.get("stargazers_count"),
                     "url": x["html_url"], "topics": x.get("topics", [])}
                    for x in r.json() if not x.get("fork")]
    except Exception:
        pass
    return []


async def check_hackernews(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://hn.algolia.com/api/v1/search?tags=author_{username}&hitsPerPage=5", timeout=10.0)
        if r.status_code == 200:
            d = r.json()
            hits = d.get("hits", [])
            if hits:
                return {"found": True, "total_posts": d.get("nbHits", 0),
                        "recent_posts": [{"title": h.get("title") or h.get("comment_text","")[:100],
                                          "url": h.get("url") or f"https://news.ycombinator.com/item?id={h.get('objectID')}",
                                          "points": h.get("points", 0),
                                          "created_at": h.get("created_at")} for h in hits[:3]]}
    except Exception:
        pass
    return {"found": False}


async def check_npm_profile(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://registry.npmjs.org/-/v1/search?text=author:{username}&size=5", timeout=10.0)
        if r.status_code == 200:
            d = r.json()
            objs = d.get("objects", [])
            if objs:
                return {"found": True, "total": d.get("total", 0),
                        "packages": [{"name": o["package"]["name"],
                                      "description": o["package"].get("description",""),
                                      "version": o["package"].get("version",""),
                                      "date": o["package"].get("date")} for o in objs[:5]]}
    except Exception:
        pass
    return {"found": False}


async def check_reddit_account(username: str, client: httpx.AsyncClient) -> dict:
    try:
        r = await client.get(f"https://www.reddit.com/user/{username}/about.json", timeout=8.0)
        if r.status_code == 200:
            d = r.json().get("data", {})
            created = d.get("created_utc")
            if d and created:
                return {
                    "found": True,
                    "created_utc": created,
                    "created_iso": datetime.fromtimestamp(created, tz=timezone.utc).isoformat(),
                    "url": f"https://www.reddit.com/user/{username}",
                }
    except Exception:
        pass
    return {"found": False}


def build_activity_timeline(findings: dict, reddit_account: dict) -> list[dict]:
    entries = []

    gh = findings.get("github", {})
    if gh.get("found") and gh.get("created_at"):
        entries.append({"platform": "GitHub", "date": gh["created_at"],
                         "label": "Cuenta creada", "url": gh.get("url", "")})

    if reddit_account.get("found") and reddit_account.get("created_iso"):
        entries.append({"platform": "Reddit", "date": reddit_account["created_iso"],
                         "label": "Cuenta creada", "url": reddit_account.get("url", "")})

    username = findings.get("target", {}).get("username") or ""

    npm_dates = [p["date"] for p in findings.get("npm", {}).get("packages", []) if p.get("date")]
    if npm_dates:
        entries.append({"platform": "npm", "date": max(npm_dates),
                         "label": "Último paquete publicado",
                         "url": f"https://www.npmjs.com/~{username}"})

    hn_dates = [p["created_at"] for p in findings.get("hackernews", {}).get("recent_posts", [])
                if p.get("created_at")]
    if hn_dates:
        entries.append({"platform": "HackerNews", "date": min(hn_dates),
                         "label": "Primer post indexado (no es fecha de creación de cuenta)",
                         "url": f"https://news.ycombinator.com/user?id={username}"})

    def _parse(e):
        try:
            return datetime.fromisoformat(e["date"].replace("Z", "+00:00"))
        except Exception:
            return None

    parsed = [(e, _parse(e)) for e in entries]
    valid = [(e, d) for e, d in parsed if d is not None]
    return [e for e, _ in sorted(valid, key=lambda pair: pair[1])]


async def generate_google_dorks(name, username, email) -> list[str]:
    dorks = []
    if name:
        parts = name.strip().split()
        dorks += [
            f'"{name}" site:linkedin.com',
            f'"{name}" filetype:pdf resume OR CV',
            f'"{name}" site:github.com',
            f'"{name}" email OR contact',
        ]
        if len(parts) >= 2:
            first, last = parts[0], parts[-1]
            dorks += [
                f'"{first}" "{last}" site:linkedin.com/in',
                f'"{first}" "{last}" email OR phone OR contact',
                f'"{last}" "{first}" CV OR resume filetype:pdf',
                f'"{first}.{last}" OR "{last}.{first}" site:github.com OR site:gitlab.com',
                f'intext:"{first}" intext:"{last}" site:facebook.com',
                f'"{first} {last}" site:twitter.com OR site:x.com',
            ]
    if username:
        dorks += [
            f'"{username}" site:reddit.com',
            f'"{username}" site:twitter.com OR site:x.com',
            f'intitle:"{username}" profile',
            f'"{username}" site:github.com OR site:gitlab.com',
        ]
    if email:
        domain = email.split("@")[-1] if "@" in email else ""
        dorks += [
            f'"{email}"',
            f'"{email}" password OR breach OR leak',
            f'"{email}" site:{domain}' if domain else "",
            f'intext:"{email}" filetype:sql OR filetype:csv OR filetype:txt',
        ]
    return [d for d in dorks if d]


async def check_email_breaches(email: str, client: httpx.AsyncClient) -> dict:
    """Verifica el email contra HIBP v3 y XposedOrNot (fallback gratuito sin API key)."""
    # Intento con HIBP v3 (funciona si el servidor no bloquea por falta de key)
    try:
        r = await client.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
            headers={"User-Agent": "OSINT-Person-Finder-CLI"},
            timeout=10.0)
        if r.status_code == 200:
            breaches = r.json()
            return {
                "source": "HIBP",
                "found": True,
                "breach_count": len(breaches),
                "breaches": [{"name": b["Name"], "date": b.get("BreachDate", "?"),
                              "data": b.get("DataClasses", [])[:3]} for b in breaches[:5]],
            }
        elif r.status_code == 404:
            return {"source": "HIBP", "found": False, "breach_count": 0}
    except Exception:
        pass

    # Fallback: XposedOrNot — API pública, sin API key requerida
    try:
        r2 = await client.get(
            f"https://api.xposedornot.com/v1/check-email/{email}",
            timeout=10.0)
        if r2.status_code == 200:
            data = r2.json()
            breach_list = data.get("breaches", [])
            if isinstance(breach_list, list) and breach_list:
                return {
                    "source": "XposedOrNot",
                    "found": True,
                    "breach_count": len(breach_list),
                    "breaches": [{"name": b, "date": "?", "data": []} for b in breach_list[:5]],
                }
        return {"source": "XposedOrNot", "found": False, "breach_count": 0}
    except Exception as e:
        return {"error": str(e), "found": False, "breach_count": 0}


# ── Análisis IA — multi-proveedor ─────────────────────────────────────────────

async def analyze_with_ai(findings: dict, provider: dict, api_key: str, client: httpx.AsyncClient) -> str:
    prompt = f"""Eres un analista OSINT experto en red team. Analiza los siguientes hallazgos
y generá un perfil completo.

HALLAZGOS:
{json.dumps(findings, indent=2, ensure_ascii=False)}

Generá un análisis con:
1. **RESUMEN EJECUTIVO** — quién es esta persona según la evidencia
2. **HUELLA DIGITAL** — plataformas confirmadas y qué revelan
3. **DATOS TÉCNICOS** — skills, tecnologías, proyectos
4. **PATRONES DE COMPORTAMIENTO** — horarios, intereses, actividad
5. **VECTORES DE ATAQUE** — para red team: spear phishing, pretextos, info sensible expuesta
6. **LAGUNAS** — qué no encontramos y cómo buscarlo
7. **PRÓXIMOS PASOS OSINT** — recomendaciones concretas

Basate solo en los datos. Respondé en español argentino, técnico y directo."""

    pid = provider["id"]

    try:
        if pid == "claude":
            r = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "Content-Type": "application/json"},
                json={"model": provider["model"], "max_tokens": 2000,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=60.0)
            if r.status_code == 200:
                return r.json()["content"][0]["text"]
            return f"[Error Claude {r.status_code}]: {r.text[:200]}"

        elif pid == "openai":
            r = await client.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": provider["model"], "max_tokens": 2000,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=60.0)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            return f"[Error OpenAI {r.status_code}]: {r.text[:200]}"

        elif pid == "grok":
            r = await client.post(
                "https://api.x.ai/v1/chat/completions",
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"model": provider["model"], "max_tokens": 2000,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=60.0)
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"]
            return f"[Error Grok {r.status_code}]: {r.text[:200]}"

        elif pid == "gemini":
            r = await client.post(
                f"https://generativelanguage.googleapis.com/v1beta/models/{provider['model']}:generateContent?key={api_key}",
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": prompt}]}]},
                timeout=60.0)
            if r.status_code == 200:
                return r.json()["candidates"][0]["content"]["parts"][0]["text"]
            return f"[Error Gemini {r.status_code}]: {r.text[:200]}"

    except Exception as e:
        return f"[Error conectando con {provider['name']}]: {e}"

    return "[Proveedor no soportado]"


# ── Output ────────────────────────────────────────────────────────────────────

def _username_row_style(r: dict) -> tuple[str, str]:
    if r["found"]:
        fp = r.get("fp_status", "FOUND")
        if fp == "POSIBLE FP":
            return "[yellow]⚠ POSIBLE FP[/yellow]", "[yellow]—[/yellow]"
        conf_val = r.get("confidence", "Medio")
        color = {"Alto": "green", "Medio": "yellow", "Bajo": "red"}.get(conf_val, "white")
        return "[bold green]✓ FOUND[/bold green]", f"[{color}]{conf_val}[/{color}]"
    return "[dim]✗ not found[/dim]", "[dim]—[/dim]"


def print_username_results(results: list[dict]):
    table = Table(title="🔍 Username Lookup", border_style="red", show_lines=True)
    table.add_column("Plataforma", style="bold cyan", width=15)
    table.add_column("Estado", width=16)
    table.add_column("Confianza", width=10)
    table.add_column("URL", style="dim")
    for r in results:
        status, conf_str = _username_row_style(r)
        table.add_row(r["platform"], status, conf_str, r["url"] if r["found"] else "—")
    console.print(table)


def print_username_variants(username: str, variant_results: dict[str, list[dict]]):
    any_found = any(r["found"] for results in variant_results.values() for r in results)
    console.print(f"\n[bold red]🔗 Variantes de @{username}[/bold red]")
    for variant, results in variant_results.items():
        hits = [r for r in results if r["found"]]
        if not hits:
            console.print(f"  [dim]@{variant}: sin coincidencias[/dim]")
            continue
        table = Table(title=f"@{variant}", border_style="magenta", show_lines=True)
        table.add_column("Plataforma", style="bold cyan", width=15)
        table.add_column("Estado", width=16)
        table.add_column("Confianza", width=10)
        table.add_column("URL", style="dim")
        for r in hits:
            status, conf_str = _username_row_style(r)
            table.add_row(r["platform"], status, conf_str, r["url"])
        console.print(table)
    if not any_found:
        console.print("  [dim]Ninguna variante encontrada.[/dim]")


def print_email_breaches(result: dict, email: str):
    if result.get("error"):
        console.print(f"[yellow]⚠ Brechas: no se pudo verificar ({result['error'][:60]})[/yellow]")
        return
    if result.get("found"):
        count = result["breach_count"]
        source = result.get("source", "desconocida")
        console.print(f"\n[bold red]⚠ ALERTA:[/bold red] [red]{email}[/red] aparece en "
                      f"[bold red]{count}[/bold red] brecha(s) conocida(s) — fuente: {source}")
        breaches = result.get("breaches", [])
        if breaches:
            tbl = Table(title="💀 Brechas Detectadas", border_style="red")
            tbl.add_column("Brecha", style="bold red")
            tbl.add_column("Fecha", style="dim")
            tbl.add_column("Datos Expuestos", style="yellow")
            for b in breaches:
                name_b = b.get("name", "?") if isinstance(b, dict) else str(b)
                date_b = b.get("date", "?") if isinstance(b, dict) else "?"
                data_b = b.get("data", []) if isinstance(b, dict) else []
                data_str = ", ".join(data_b[:3]) if isinstance(data_b, list) else str(data_b)
                tbl.add_row(name_b, date_b, data_str or "—")
            console.print(tbl)
    else:
        source = result.get("source", "desconocida")
        console.print(f"[green]✓[/green] [dim]{email}[/dim] no aparece en brechas conocidas "
                      f"[dim](fuente: {source})[/dim]")


def print_github_info(profile: dict, repos: list):
    if not profile.get("found"):
        return
    t = Text()
    for label, key in [("Nombre","name"),("Bio","bio"),("Ubicación","location"),
                       ("Email","email"),("Empresa","company"),("Blog","blog"),
                       ("Repos","public_repos"),("Followers","followers"),
                       ("Twitter","twitter_username"),("Creado","created_at")]:
        val = profile.get(key)
        if val:
            t.append(f"  {label}: ", style="bold yellow")
            t.append(f"{val}\n", style="white")
    console.print(Panel(t, title="[bold red]GitHub Profile[/bold red]", border_style="red"))
    if repos:
        tbl = Table(title="📦 Repos Públicos", border_style="yellow")
        tbl.add_column("Repo", style="cyan")
        tbl.add_column("Lang", style="green")
        tbl.add_column("⭐", justify="right")
        tbl.add_column("Descripción", style="dim")
        for r in repos[:8]:
            tbl.add_row(r["name"], r.get("language") or "—", str(r.get("stars",0)), (r.get("description") or "")[:60])
        console.print(tbl)


def print_activity_timeline(timeline: list[dict]):
    if not timeline:
        return
    tbl = Table(title="🕒 Línea de Tiempo de Actividad", border_style="red", show_lines=True)
    tbl.add_column("Fecha", style="bold yellow", width=22)
    tbl.add_column("Plataforma", style="bold cyan", width=12)
    tbl.add_column("Evento", style="white")
    for e in timeline:
        tbl.add_row(e["date"], e["platform"], e["label"])
    console.print(Panel(tbl, border_style="red"))


def print_dorks(dorks: list[str]):
    console.print(Panel("\n".join(f"[cyan]•[/cyan] {d}" for d in dorks),
                        title="[bold yellow]🔎 Google Dorks[/bold yellow]", border_style="yellow"))


def print_ai_analysis(analysis: str, provider_name: str):
    console.print(Panel(analysis,
                        title=f"[bold red]🧠 Análisis IA — {provider_name}[/bold red]",
                        border_style="red", padding=(1, 2)))


def save_results(findings: dict, analysis: str, path: str):
    p = Path(path)
    if p.suffix == ".json":
        p.write_text(json.dumps({"timestamp": datetime.now().isoformat(),
                                  "findings": findings, "ai_analysis": analysis},
                                 indent=2, ensure_ascii=False))
    else:
        p.write_text(f"OSINT REPORT — {datetime.now().isoformat()}\n{'='*60}\n\n"
                     f"HALLAZGOS:\n{json.dumps(findings, indent=2, ensure_ascii=False)}\n\n"
                     f"ANÁLISIS IA:\n{analysis}")
    console.print(f"\n[green]✓ Guardado en:[/green] [bold]{path}[/bold]")


def _md_lite_to_html(text: str) -> str:
    if not text:
        return "<p><em>Análisis IA no ejecutado (--no-ai).</em></p>"
    escaped = html.escape(text)
    escaped = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", escaped)
    paragraphs = escaped.split("\n\n")
    return "".join(f"<p>{p.replace(chr(10), '<br>')}</p>" for p in paragraphs if p.strip())


_REPORT_CSS = """
  body { background:#0d0d0d; color:#e6e6e6; font-family:ui-monospace,"Segoe UI",sans-serif;
         margin:0; padding:2rem; line-height:1.5; }
  h1 { color:#ff4d4d; border-bottom:2px solid #ff4d4d; padding-bottom:.5rem; }
  h2 { color:#ff4d4d; margin-top:2.5rem; }
  .card { background:#1a1a1a; border:1px solid #333; border-radius:8px; padding:1.25rem; margin:1rem 0; }
  .meta span { display:inline-block; margin-right:1.5rem; color:#ccc; }
  .meta b { color:#fff; }
  table { border-collapse:collapse; width:100%; margin-top:.75rem; }
  th, td { text-align:left; padding:.5rem .75rem; border-bottom:1px solid #333; }
  th { color:#ff4d4d; text-transform:uppercase; font-size:.8rem; }
  tr:hover { background:#151515; }
  a { color:#7ab8ff; }
  .badge { padding:.15rem .5rem; border-radius:4px; font-size:.8rem; font-weight:bold; }
  .found { background:#173a1f; color:#4ade80; }
  .fp { background:#3a3417; color:#eab308; }
  .notfound { background:#222; color:#777; }
  .conf-alto { color:#4ade80; }
  .conf-medio { color:#eab308; }
  .conf-bajo { color:#ef4444; }
  ul.dorks { list-style:none; padding:0; }
  ul.dorks li { padding:.35rem 0; border-bottom:1px solid #222; color:#ccc; }
  .analysis p { color:#ddd; }
"""


def _report_target_html(target: dict) -> str:
    parts = []
    for label, key in [("Nombre", "name"), ("Username", "username"),
                        ("Email", "email"), ("Teléfono", "phone")]:
        val = target.get(key)
        if val:
            parts.append(f"<span><b>{label}:</b> {html.escape(str(val))}</span>")
    return "".join(parts)


def _report_username_table_html(results: list[dict]) -> str:
    if not results:
        return "<p><em>Sin resultados.</em></p>"
    rows = []
    for r in results:
        if r["found"]:
            fp = r.get("fp_status", "FOUND")
            if fp == "POSIBLE FP":
                status = '<span class="badge fp">⚠ POSIBLE FP</span>'
                conf = "—"
            else:
                status = '<span class="badge found">✓ FOUND</span>'
                conf_val = r.get("confidence", "Medio")
                conf = f'<span class="conf-{conf_val.lower()}">{html.escape(conf_val)}</span>'
        else:
            status = '<span class="badge notfound">✗ not found</span>'
            conf = "—"
        url = html.escape(r["url"]) if r["found"] else "—"
        url_cell = f'<a href="{url}">{url}</a>' if r["found"] else "—"
        rows.append(f"<tr><td>{html.escape(r['platform'])}</td><td>{status}</td>"
                    f"<td>{conf}</td><td>{url_cell}</td></tr>")
    return ("<table><tr><th>Plataforma</th><th>Estado</th><th>Confianza</th><th>URL</th></tr>"
            + "".join(rows) + "</table>")


def _report_variants_html(variant_results: dict[str, list[dict]]) -> str:
    if not variant_results:
        return ""
    sections = []
    for variant, results in variant_results.items():
        hits = [r for r in results if r["found"]]
        if not hits:
            sections.append(f"<p><b>@{html.escape(variant)}:</b> sin coincidencias</p>")
            continue
        sections.append(f"<h3>@{html.escape(variant)}</h3>" + _report_username_table_html(hits))
    return "<h2>🔗 Variantes de Username</h2><div class='card'>" + "".join(sections) + "</div>"


def _report_dorks_html(dorks: list[str]) -> str:
    if not dorks:
        return ""
    items = "".join(f"<li>{html.escape(d)}</li>" for d in dorks)
    return f"<h2>🔎 Google Dorks</h2><div class='card'><ul class='dorks'>{items}</ul></div>"


def generate_html_report(findings: dict, analysis: str) -> str:
    target = findings.get("target", {})
    title = html.escape(target.get("username") or target.get("name") or target.get("email") or "OSINT Report")
    generated = datetime.now().isoformat(timespec="seconds")

    variants_html = _report_variants_html(findings.get("username_variants", {}))
    dorks_html = _report_dorks_html(findings.get("google_dorks", []))

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<title>OSINT Report — {title}</title>
<style>{_REPORT_CSS}</style>
</head>
<body>
  <h1>🔍 OSINT Person Finder — Reporte</h1>
  <div class="card meta">
    {_report_target_html(target)}
    <span><b>Generado:</b> {html.escape(generated)}</span>
  </div>

  <h2>Username Lookup</h2>
  <div class="card">{_report_username_table_html(findings.get("username_lookup", []))}</div>

  {variants_html}

  {dorks_html}

  <h2>🧠 Análisis IA</h2>
  <div class="card analysis">{_md_lite_to_html(analysis)}</div>
</body>
</html>
"""


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(args):
    console.print(BANNER)

    # Config interactiva al arrancar
    cfg = setup_interactive()
    provider = cfg["provider"]
    api_key  = cfg["api_key"]

    console.print(f"\n[dim]Usando: [bold]{provider['name']}[/bold] — {provider['model']}[/dim]\n")

    if not any([args.name, args.username, args.email, args.phone]):
        console.print("[red]Error:[/red] Necesitás al menos un input. Usá --help.")
        sys.exit(1)

    findings = {
        "target": {"name": args.name, "username": args.username,
                   "email": args.email, "phone": args.phone},
        "username_lookup": [], "username_variants": {}, "github": {}, "github_repos": [],
        "hackernews": {}, "npm": {}, "google_dorks": [],
        "email_breaches": {}, "reddit_account": {}, "activity_timeline": [],
    }

    headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

    async with httpx.AsyncClient(headers=headers) as client:
        with Progress(SpinnerColumn(style="red"), TextColumn("[bold red]{task.description}"),
                      console=console) as prog:

            if args.username:
                t = prog.add_task(f"Buscando @{args.username} en plataformas...", total=None)
                findings["username_lookup"] = await check_username(args.username, client)
                prog.remove_task(t)
                print_username_results(findings["username_lookup"])

                if any(r["found"] and r.get("fp_status") != "POSIBLE FP"
                       for r in findings["username_lookup"]):
                    t = prog.add_task(f"Correlacionando variantes de @{args.username}...", total=None)
                    findings["username_variants"] = await check_username_variants(args.username, client)
                    prog.remove_task(t)
                    print_username_variants(args.username, findings["username_variants"])

                t = prog.add_task("Analizando GitHub...", total=None)
                findings["github"]       = await check_github_profile(args.username, client)
                findings["github_repos"] = await check_github_repos(args.username, client)
                prog.remove_task(t)
                print_github_info(findings["github"], findings["github_repos"])

                t = prog.add_task("Buscando en HackerNews...", total=None)
                findings["hackernews"] = await check_hackernews(args.username, client)
                prog.remove_task(t)
                if findings["hackernews"].get("found"):
                    console.print(f"[green]✓ HackerNews:[/green] {findings['hackernews']['total_posts']} posts")

                t = prog.add_task("Buscando en npm...", total=None)
                findings["npm"] = await check_npm_profile(args.username, client)
                prog.remove_task(t)
                if findings["npm"].get("found"):
                    console.print(f"[green]✓ npm:[/green] {findings['npm']['total']} paquetes")

                t = prog.add_task(f"Correlacionando línea de tiempo para @{args.username}...", total=None)
                findings["reddit_account"] = await check_reddit_account(args.username, client)
                findings["activity_timeline"] = build_activity_timeline(findings, findings["reddit_account"])
                prog.remove_task(t)
                print_activity_timeline(findings["activity_timeline"])

            t = prog.add_task("Generando Google Dorks...", total=None)
            findings["google_dorks"] = await generate_google_dorks(args.name, args.username, args.email)
            prog.remove_task(t)
            print_dorks(findings["google_dorks"])

            if args.email:
                t = prog.add_task(f"Verificando brechas para {args.email}...", total=None)
                findings["email_breaches"] = await check_email_breaches(args.email, client)
                prog.remove_task(t)
                print_email_breaches(findings["email_breaches"], args.email)

            if not args.no_ai:
                t = prog.add_task(f"Analizando con {provider['name']}...", total=None)
                analysis = await analyze_with_ai(findings, provider, api_key, client)
                prog.remove_task(t)
                print_ai_analysis(analysis, provider["name"])
            else:
                analysis = ""

        if args.save:
            save_results(findings, analysis, args.save)

        if args.report:
            reports_dir = Path(__file__).resolve().parent / "reports"
            reports_dir.mkdir(exist_ok=True)
            filename = Path(args.report).name
            if not filename.lower().endswith(".html"):
                filename += ".html"
            report_path = reports_dir / filename
            report_path.write_text(generate_html_report(findings, analysis), encoding="utf-8")
            console.print(f"\n[green]✓ Reporte HTML guardado en:[/green] [bold]{report_path.resolve()}[/bold]")


def main():
    parser = argparse.ArgumentParser(
        description="[BlackSec] OSINT Person Finder AI — Reconocimiento multi-vector con análisis IA",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
FLAGS:
  -u USERNAME   ★ FLAG MÁS POTENTE — busca el username en 20+ plataformas (GitHub, Reddit,
                  Instagram, Steam, npm, PyPI y más), enriquece con GitHub API + HackerNews
                  + npm, aplica scoring de confianza (Alto/Medio/Bajo) y detecta falsos positivos.
  -n NOMBRE     Genera Google Dorks para el nombre. Con dos palabras (nombre + apellido)
                  genera dorks cruzados adicionales más precisos (nombre.apellido, etc.).
  -e EMAIL      Genera Google Dorks por email + verifica en brechas de datos (HIBP / XposedOrNot)
                  sin necesidad de API key. Muestra brechas conocidas con datos expuestos.
  -p TELÉFONO   Incluye el teléfono en el contexto del análisis IA.
  --save FILE   Exporta todos los hallazgos en formato JSON o TXT.
  --report NAME Genera un reporte HTML autocontenido (dark theme) con tabla de username lookup,
                  variantes, Google Dorks y análisis IA. Se guarda en reports/NAME.html
                  (se crea la carpeta si no existe; agrega .html si falta).
  --no-ai       Saltear análisis IA (útil para reconocimiento rápido sin API key).

EJEMPLOS:
  # Username lookup completo con scoring de confianza (recomendado como primer paso)
  python osint_finder.py -u johndoe

  # Perfil completo combinando todos los vectores
  python osint_finder.py -n "John Doe" -u johndoe -e john@example.com -p +1234567890

  # Reconocimiento rápido sin IA, guardar reporte JSON
  python osint_finder.py -u johndoe --save reporte.json --no-ai

  # Generar reporte HTML autocontenido (se guarda en reports/scan_johndoe.html)
  python osint_finder.py -u johndoe --report scan_johndoe.html

  # Investigar email: dorks + verificación en brechas conocidas
  python osint_finder.py -e victim@company.com --no-ai

  # Dorks para nombre completo con separación apellido/nombre
  python osint_finder.py -n "Jane Smith" --save output.txt
        """)
    parser.add_argument("-n", "--name",     help="Nombre completo")
    parser.add_argument("-u", "--username", help="Username / handle")
    parser.add_argument("-e", "--email",    help="Email")
    parser.add_argument("-p", "--phone",    help="Teléfono")
    parser.add_argument("--save",           help="Guardar resultados (.json o .txt)", metavar="ARCHIVO")
    parser.add_argument("--report",         help="Generar reporte HTML (guardado en reports/)", metavar="NOMBRE")
    parser.add_argument("--no-ai",          action="store_true", help="Saltar análisis IA")
    args = parser.parse_args()

    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠ Interrumpido.[/yellow]")


if __name__ == "__main__":
    main()
