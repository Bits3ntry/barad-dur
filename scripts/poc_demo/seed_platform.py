#!/usr/bin/env python3
"""Seed the POC estate on the live platform, through its own API.

    python scripts/poc_demo/seed_platform.py            # seed (idempotent-ish)
    python scripts/poc_demo/seed_platform.py --dry-run  # print the plan only

What it creates, in the order the demo reads it:

    project  juice-shop (producto)  →  componentes web/api  →  repositorios
             versiones 1.0.0 / 0.9.0  →  deployments de PRODUCCIÓN
    scope    juice-shop.demo declarado + grant de deep recon aprobado
    asset    juice-shop.demo archivado bajo el proyecto, sirviendo el
             deployment de producción (dueño + vínculo, sin inventar observaciones)
             api.juice-shop.demo declarado y sin escanear (el contraste)
    ciclo    "Contexto externo" (pentest_external) con cuatro hallazgos escritos
             como afirmaciones, con su request/response de prueba

The scans (SBOM + CVEs + SAST) come from Shauron, not from here: the point of
the demo is that the platform does not invent data. Run this first, then the two
`shauron scan` commands the runbook prints.

Everything is addressed by slug, so re-running does not duplicate: an existing
project/asset/cycle is reused and its ids are printed again.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Where the lab lives. Overridable so a colleague who clones this repo does not have to
# own the same folder layout: `POC_DIR=/srv/poc bash scripts/poc_demo/seed_platform.py`.
POC_DIR = Path(os.path.expanduser(
    os.environ.get("POC_DIR", "~/HUB/Workspace/Councilbox/CYB/poc-juice-shop")))
REPOS = POC_DIR / "repos.json"

API = os.environ.get("BARAD_URL", "http://127.0.0.1:8090")
KEY = os.environ.get("SHAURON_BARAD_KEY", "")
PROJECT = "juice-shop"
ASSET = "juice-shop.demo"
SECOND_ASSET = "api.juice-shop.demo"
OWNER = os.environ.get("POC_OWNER", "bitsentry.tech@gmail.com")


def call(method: str, path: str, payload=None, *, base: str = API) -> dict:
    body = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"{base}{path}", data=body, method=method,
        headers={"X-API-Key": KEY, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", "replace")
        raise SystemExit(f"{method} {path} → {error.code}: {detail}") from None


def get(path: str) -> dict:
    return call("GET", path)


def dry(message: str) -> None:
    print(f"  · {message}")


def find_project(slug: str):
    for row in get("/api/v1/projects")["data"]:
        if row["slug"] == slug:
            return row
    return None


def find_asset(value: str):
    for row in get("/api/v1/assets?limit=200&q=" + urllib.parse.quote(value))["data"]:
        if row["value"].lower() == value.lower():
            return row
    return None


def project_inventory(slug: str) -> dict:
    return get(f"/api/v1/projects/{slug}/inventory")["data"]


def component_id(inventory: dict, slug: str) -> str | None:
    for row in inventory["components"]:
        if row["slug"] == slug:
            return row["id"]
    return None


def deployment_id(slug: str, component: str, environment: str) -> str | None:
    data = project_inventory(slug)
    for row in data.get("deployments", []):
        if row.get("environment") == environment and row.get("component") == component:
            return row.get("id")
    return None


def seed(dry_run: bool) -> dict:
    if not KEY:
        raise SystemExit("SHAURON_BARAD_KEY is not set; source .env first")
    repos = json.loads(REPOS.read_text())
    state: dict = {"project": PROJECT, "asset": ASSET}

    # ── project ────────────────────────────────────────────────────────────
    project = find_project(PROJECT)
    if project:
        dry(f"project {PROJECT} exists ({project['id']})")
        project_id = project["id"]
    elif dry_run:
        dry(f"would create project {PROJECT}")
        project_id = "dry"
    else:
        project_id = call("POST", "/api/v1/projects", {
            "name": "Juice Shop", "slug": PROJECT,
            "group": "Comercio electrónico",
            "description": ("Tienda online. Frontend Node/Express, API Django. "
                            "Producción en un solo entorno, sin pipeline de parches."),
            "owner": OWNER, "actor": OWNER})["data"]["id"]
        dry(f"project {PROJECT} created")
    state["project_id"] = project_id

    # ── components ─────────────────────────────────────────────────────────
    components = {
        "juice-shop-web": {"kind": "web",
                           "description": "Escaparate y API de producto (Node 14 / Express 4)"},
        "juice-shop-api": {"kind": "backend",
                           "description": "Pedidos, perfiles y precios (Django 2.2 / Python 3.8)"},
    }
    inventory = project_inventory(PROJECT) if project else {"components": []}
    existing = {row["slug"] for row in inventory["components"]}
    ids: dict[str, str] = {}
    for slug, spec in components.items():
        if slug in existing:
            ids[slug] = component_id(inventory, slug) or ""
            dry(f"component {slug} exists")
            continue
        if dry_run:
            dry(f"would create component {slug}")
            continue
        ids[slug] = call("POST", f"/api/v1/projects/{PROJECT}/components", {
            "name": slug, "kind": spec["kind"], "description": spec["description"],
            "actor": OWNER})["data"]["id"]
        dry(f"component {slug} created ({spec['kind']})")
    state["components"] = ids

    # ── repositories: the remote is what a scan resolves to a component ────
    remotes = {
        "juice-shop-web": "https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git",
        "juice-shop-api": "https://gitea.juice-shop.demo/juice-shop/juice-shop-api.git",
    }
    for slug, remote in remotes.items():
        if dry_run:
            dry(f"would link {remote} → {slug}")
            continue
        call("POST", f"/api/v1/projects/{PROJECT}/repositories", {
            "remote_url": remote, "name": slug, "provider": "gitea",
            "component_id": ids.get(slug) or None, "relation": "builds",
            "actor": OWNER})
        dry(f"repository {slug} linked")

    # ── versions + production deployments ──────────────────────────────────
    versions = {"juice-shop-web": "1.0.0", "juice-shop-api": "0.9.0"}
    inventory = project_inventory(PROJECT) if project else {"deployments": []}
    for slug, version in versions.items():
        have = [row for row in inventory.get("deployments", [])
                if row.get("component") == slug and row.get("environment") == "production"]
        if have:
            dry(f"deployment {slug}@production exists ({have[0].get('version_label')})")
            continue
        if dry_run:
            dry(f"would deploy {slug} {version} to production")
            continue
        call("POST", f"/api/v1/projects/{PROJECT}/deployments", {
            "component_id": ids[slug], "environment": "production",
            "version_label": version,
            "name": f"{slug} · producción",
            "exposure": "public", "requires_auth": False, "actor": OWNER})
        dry(f"deployment {slug} {version} → production")

    # ── the address: declared, then granted, then owned ────────────────────
    for value, reason in (
            (ASSET, "POC: escaparate de Juice Shop"),
            (SECOND_ASSET, "POC: API de pedidos (declarada, todavía sin escanear)")):
        if not dry_run:
            call("POST", "/api/v1/scope/targets", {
                "target_type": "domain", "value": value, "reason": reason,
                "owner": OWNER,
                "capabilities": ["passive_discovery", "active_verification"],
                "actor": OWNER})
        dry(f"{'scope target' if not dry_run else 'would declare'} {value}"
            + (" (never scanned)" if value == SECOND_ASSET else ""))

    grants = get("/api/v1/authorization/grants").get("data") or []
    live = [grant for grant in grants
            if grant.get("status") == "active"
            and any((t.get("value") or "").lower() == ASSET
                    for t in grant.get("targets") or [])]
    if live:
        dry(f"grant for {ASSET} exists (level {live[0].get('level')})")
        state["grant_id"] = live[0]["id"]
    elif dry_run:
        dry(f"would issue a deep-recon grant for {ASSET}")
    else:
        grant = call("POST", "/api/v1/authorization/grants", {
            "principal": "collector", "level": "redteam",
            "targets": [{"type": "domain", "value": ASSET}],
            "issued_by": OWNER,
            "justification": ("POC: reconocimiento profundo sobre el escaparate. "
                              "Ventana de 72 h, sin pruebas intrusivas."),
            "hours": 72})["data"]
        state["grant_id"] = grant.get("id")
        dry(f"grant {grant.get('level')} issued for {ASSET}")

    # ── ownership + the link that makes the deployment answerable ──────────
    asset = find_asset(ASSET)
    if asset is None:
        if not dry_run:
            raise SystemExit(f"asset {ASSET} was not created by the scope declaration")
        dry(f"would file {ASSET} under {PROJECT} and link the production deployment")
    elif not dry_run:
        prod = deployment_id(PROJECT, "juice-shop-web", "production")
        call("POST", f"/api/v1/assets/{asset['id']}/catalog", {
            "project": PROJECT, "deployment_id": prod, "relation": "serves",
            "actor": OWNER})
        dry(f"asset {ASSET} filed under {PROJECT} (serves juice-shop-web@production)")
        state["asset_id"] = asset["id"]

    # ── the external report: claims, not confirmations ─────────────────────
    cycles = get("/api/v1/cycles").get("data") or []
    external = next((row for row in cycles
                     if row["name"] == "2026-Q4 · contexto externo"), None)
    if external:
        dry(f"cycle contexto externo exists ({external['id']})")
        state["external_cycle"] = external["id"]
    elif dry_run:
        dry("would create the external-context cycle with four claims")
    else:
        external = call("POST", "/api/v1/cycles", {
            "name": "2026-Q4 · contexto externo",
            "description": ("Informe de pentest externo recibido en PDF. Se registra "
                            "como lo que es: afirmaciones de un tercero, con su "
                            "petición y su respuesta."),
            "owner": OWNER, "kind": "pentest_external",
            "starts_on": "2026-11-02", "ends_on": "2026-11-13",
            "charter": {"objectives": ["Cerrar el escaparate antes de campaña"],
                        "success_criteria": ["Ningún HIGH sin decisión humana"]},
            "selection": {"projects": [PROJECT]},
            "actor": OWNER})["data"]
        state["external_cycle"] = external["id"]
        dry(f"cycle contexto externo created ({external['id']})")

    claims = [
        {
            "title": "Inyección SQL en la búsqueda de productos",
            "kind": "vulnerability", "severity": "HIGH", "cwe": "CWE-89",
            "project": PROJECT, "version_id": None,
            "endpoint": "https://juice-shop.demo/rest/products/search?q=",
            "http_method": "GET", "auth_required": False,
            "impact": ("El término de búsqueda se concatena en la sentencia: un "
                       "UNION devuelve la tabla de usuarios, incluidos los hashes."),
            "reproduction": ("GET /rest/products/search?q=') UNION SELECT email,"
                             "password,1 FROM users-- -"),
            "expected_result": "Sólo productos que coinciden con el término.",
            "observed_result": ("La respuesta incluye 41 filas con email y hash de la "
                                "tabla de usuarios."),
            "proof_request": ("GET /rest/products/search?q=%27)%20UNION%20SELECT%20"
                              "email,password,1%20FROM%20users--%20- HTTP/1.1\n"
                              "Host: juice-shop.demo"),
            "proof_response": ("HTTP/1.1 200 OK\ncontent-type: application/json\n\n"
                               "[{\"name\":\"admin@juice-sh.op\",\"price\":"
                               "\"0192023a7bbd73250516f069df18b500\"}]"),
            "evidence_level": "observed", "actor": "pentest@redlab.example",
        },
        {
            "title": "IDOR en la cesta: una cesta ajena se lee con el propio token",
            "kind": "vulnerability", "severity": "HIGH", "cwe": "CWE-639",
            "project": PROJECT,
            "endpoint": "https://juice-shop.demo/rest/basket/1",
            "http_method": "GET", "auth_required": True,
            "impact": ("El id de la cesta no se comprueba contra el usuario del token: "
                       "cualquier sesión lee cualquier cesta."),
            "reproduction": ("Con la sesión de un usuario normal, pedir /rest/basket/N "
                             "para N de otro usuario."),
            "expected_result": "Sólo la cesta del usuario autenticado.",
            "observed_result": "Cesta de otro usuario con sus líneas y su importe.",
            "evidence_level": "observed", "actor": "pentest@redlab.example",
        },
        {
            "title": "Backoffice expuesto sin autenticación en /administration",
            "kind": "misconfiguration", "severity": "MEDIUM", "cwe": "CWE-306",
            "project": PROJECT,
            "endpoint": "https://juice-shop.demo/administration",
            "http_method": "GET", "auth_required": False,
            "impact": ("El panel de administración se sirve en el mismo host público "
                       "y sólo se protege en el cliente."),
            "reproduction": "Abrir /administration sin sesión.",
            "expected_result": "401 o redirección al login.",
            "observed_result": "200 con el panel completo y los enlaces a /api/Users.",
            "evidence_level": "observed", "actor": "pentest@redlab.example",
        },
        {
            "title": "Clave de firma JWT en el bundle del cliente",
            "kind": "secret", "severity": "CRITICAL", "cwe": "CWE-798",
            "project": PROJECT,
            "endpoint": "https://juice-shop.demo/main.js",
            "http_method": "GET", "auth_required": False,
            "impact": ("La clave con la que se firman los tokens viaja en el bundle: "
                       "cualquiera emite un token de administrador."),
            "reproduction": ("Descargar main.js y buscar 'signing-key'. Firmar un token "
                             "con role=admin."),
            "expected_result": "La clave nunca sale del servidor.",
            "observed_result": "La cadena está en main.js, en claro.",
            "proof_request": ("GET /main.js HTTP/1.1\nHost: juice-shop.demo"),
            "proof_response": ("HTTP/1.1 200 OK\n\nconst JWT_SECRET = "
                               "'juice-shop-prod-signing-key-2019'"),
            "evidence_level": "observed", "actor": "pentest@redlab.example",
        },
    ]
    if not dry_run:
        for claim in claims:
            result = call("POST", f"/api/v1/cycles/{state['external_cycle']}/findings", claim)
            dry(f"claim recorded: {claim['title'][:52]}… "
                f"({'new' if result.get('created') else 'already known'})")
        current = get(f"/api/v1/cycles/{state['external_cycle']}")["data"]
        if current.get("state") == "planning":
            call("POST", f"/api/v1/cycles/{state['external_cycle']}/activate?actor={OWNER}")
            dry("cycle activated (the reference is frozen)")

    return state


def main() -> int:
    global API
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--platform", default=API)
    args = parser.parse_args()
    API = args.platform.rstrip("/")
    print(f"platform {API}")
    state = seed(args.dry_run)
    if not args.dry_run:
        state["platform"] = API
        out = REPOS.parent / "state.json"
        out.write_text(json.dumps(state, indent=2) + "\n")
        print(json.dumps(state, indent=2))
        print(f"\nstate: {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
