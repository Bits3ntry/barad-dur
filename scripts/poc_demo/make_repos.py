#!/usr/bin/env python3
"""Build the two lab repositories the POC demo scans.

They are deliberately vulnerable *at the dependency level* (pinned versions that
carry CVEs) and at the source level (patterns the SAST ruleset reports with a
CWE). Nothing here is meant to be run: the demo scans the tree, it never starts
the app.

    python scripts/poc_demo/make_repos.py --dest ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop

Two repositories, two runtimes, two versions each where it matters:

    juice-shop-web   1.0.0 (producción)  →  1.2.0 (la versión "nueva" de la demo)
    juice-shop-api   0.9.0 (producción)

Both are real git repositories with a synthetic remote, because the platform
resolves a scan to a component through the repository's remote URL and needs a
40-char commit sha of the tree it scans.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path

WEB_FILES = {
    "package.json": """{
  "name": "juice-shop-web",
  "version": "1.0.0",
  "private": true,
  "description": "Juice Shop storefront (lab build, deliberately out of date)",
  "main": "server.js",
  "engines": { "node": "14.21.3" },
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "axios": "0.21.1",
    "ejs": "3.1.6",
    "express": "4.17.0",
    "jsonwebtoken": "8.5.1",
    "lodash": "4.17.15",
    "minimist": "1.2.0",
    "moment": "2.24.0",
    "multer": "1.4.2",
    "mysql": "2.18.1",
    "sanitize-html": "1.27.0"
  }
}
""",
    "Dockerfile": """FROM node:14-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
""",
    "server.js": """'use strict'
const express = require('express')
const jwt = require('jsonwebtoken')
const { exec } = require('child_process')
const products = require('./routes/products')
const users = require('./routes/users')
const upload = require('./routes/upload')

const app = express()
// Hardcoded signing key: rotated by hand in 2019 and never since.
const JWT_SECRET = 'juice-shop-prod-signing-key-2019'
const ADMIN_PASSWORD = 'admin123'

app.use(express.json())
app.use('/products', products)
app.use('/users', users)
app.use('/upload', upload)

app.post('/login', (req, res) => {
  const { user, password } = req.body
  if (password === ADMIN_PASSWORD) {
    const token = jwt.sign({ user, role: 'admin' }, JWT_SECRET)
    return res.json({ token })
  }
  res.status(401).json({ error: 'invalid credentials' })
})

app.get('/ping', (req, res) => {
  // Ping utility for the ops page.
  exec('ping -c 1 ' + req.query.host, (err, stdout) => {
    if (err) return res.status(500).send(String(err))
    res.type('text/plain').send(stdout)
  })
})

app.listen(3000, () => console.log('juice-shop-web on 3000'))
""",
    "routes/products.js": """'use strict'
const express = require('express')
const mysql = require('mysql')
const db = mysql.createConnection({ host: 'db', user: 'shop', password: 'shop' })
const router = express.Router()

router.get('/search', (req, res) => {
  const term = req.query.q || ''
  // The term is concatenated into the statement.
  const sql = "SELECT id, name, price FROM products WHERE name LIKE '%" + term + "%'"
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json(rows)
  })
})

router.get('/:id', (req, res) => {
  db.query('SELECT * FROM products WHERE id = ?', [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message })
    res.json(rows)
  })
})

module.exports = router
""",
    "routes/users.js": """'use strict'
const express = require('express')
const fs = require('fs')
const router = express.Router()

router.get('/export', (req, res) => {
  // Reads whatever path the caller names, under the export directory.
  const file = fs.readFileSync('/var/exports/' + req.query.name)
  res.type('text/csv').send(file)
})

router.post('/import', (req, res) => {
  // Evaluates the uploaded rule set so support can add promotions without a deploy.
  const rules = eval(req.body.rules)
  res.json({ ok: true, applied: Object.keys(rules).length })
})

module.exports = router
""",
    "routes/upload.js": """'use strict'
const express = require('express')
const multer = require('multer')
const path = require('path')
const fs = require('fs')
const router = express.Router()

const upload = multer({ dest: '/var/uploads' })

router.post('/', upload.single('receipt'), (req, res) => {
  res.json({ stored: req.file.filename })
})

router.get('/:name', (req, res) => {
  const target = path.join('/var/uploads', req.params.name)
  res.send(fs.readFileSync(target))
})

module.exports = router
""",
    ".env.example": """DB_PASSWORD=shop
JWT_SECRET=change-me
SENDGRID_KEY=SG.2f8b1c9d4e6a7b3c5d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d
""",
    "README.md": """# juice-shop-web

Storefront and product API for Juice Shop. Node 14, Express 4.

Lab build: the dependency set is frozen at the versions that ran in 2019 so the
CTEM demo has something real to find. Do not deploy.
""",
}

WEB_V2_PACKAGE = """{
  "name": "juice-shop-web",
  "version": "1.2.0",
  "private": true,
  "description": "Juice Shop storefront",
  "main": "server.js",
  "engines": { "node": "20.11.1" },
  "scripts": { "start": "node server.js" },
  "dependencies": {
    "axios": "1.7.9",
    "ejs": "3.1.10",
    "express": "4.21.2",
    "jsonwebtoken": "9.0.2",
    "lodash": "4.17.21",
    "minimist": "1.2.8",
    "moment": "2.30.1",
    "multer": "1.4.5-lts.1",
    "mysql": "2.18.1",
    "sanitize-html": "2.13.1"
  }
}
"""

WEB_V2_DOCKERFILE = """FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
"""

API_FILES = {
    "requirements.txt": """Django==2.2.0
djangorestframework==3.9.0
Flask==1.0.2
Jinja2==2.11.2
Pillow==8.1.0
PyYAML==5.1
cryptography==3.3.1
gunicorn==19.9.0
paramiko==2.4.1
requests==2.19.1
urllib3==1.24.1
Werkzeug==0.14.1
""",
    "Dockerfile": """FROM python:3.8-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "shop.wsgi:application", "-b", "0.0.0.0:8000"]
""",
    "shop/settings.py": """import os

DEBUG = True
SECRET_KEY = "django-insecure-juice-shop-2f8b1c9d4e6a7b3c"
ALLOWED_HOSTS = ["*"]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "shop",
        "USER": "shop",
        "PASSWORD": "shop-db-password-2019",
        "HOST": os.environ.get("DB_HOST", "db"),
    }
}
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
""",
    "shop/views.py": """import logging
import pickle
import subprocess

import yaml
from django.db import connection
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

log = logging.getLogger(__name__)


@csrf_exempt
def order_lookup(request):
    \"\"\"Find an order by its reference. The reference is interpolated.\"\"\"
    reference = request.GET.get("ref", "")
    with connection.cursor() as cursor:
        cursor.execute(
            "SELECT id, total, status FROM orders WHERE reference = '%s'" % reference
        )
        rows = cursor.fetchall()
    return HttpResponse(str(rows))


@csrf_exempt
def import_profile(request):
    \"\"\"Support uploads a pickled profile exported from the old CRM.\"\"\"
    profile = pickle.loads(request.body)
    return HttpResponse(str(profile.get("name")))


@csrf_exempt
def import_pricing(request):
    \"\"\"Pricing rules arrive as YAML from the merchandising team.\"\"\"
    rules = yaml.load(request.body)
    return HttpResponse(str(len(rules)))


def export_report(request):
    \"\"\"Build the nightly PDF with the local converter.\"\"\"
    name = request.GET.get("name", "daily")
    output = subprocess.check_output("/usr/bin/wkhtmltopdf %s /tmp/%s.pdf" % (name, name),
                                     shell=True)
    return HttpResponse(output)
""",
    "shop/serializers.py": """from rest_framework import serializers


class CardSerializer(serializers.Serializer):
    # The PAN is stored in clear so the fraud vendor can read it.
    pan = serializers.CharField(max_length=19)
    holder = serializers.CharField(max_length=120)
    cvv = serializers.CharField(max_length=4)
""",
    "README.md": """# juice-shop-api

Orders, profiles and pricing for Juice Shop. Django 2.2 on Python 3.8.

Lab build: pinned to the 2019 requirements set for the CTEM demo. Do not deploy.
""",
}


def _run(argv: list[str], cwd: Path) -> str:
    result = subprocess.run(argv, cwd=str(cwd), capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"{' '.join(argv)} failed in {cwd}:\n{result.stderr}")
    return result.stdout.strip()


def _write_files(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)


def _lockfile(root: Path) -> None:
    """Ask npm for the lockfile the pinned versions resolve to.

    Trivy inventories a Node tree from the lockfile; without it the repository
    has no package components at all and the scan is legitimately empty. Falls
    back to a hand-written minimal lock when npm cannot reach the registry, and
    says which one it used.
    """
    try:
        _run(["npm", "install", "--package-lock-only", "--ignore-scripts",
              "--no-audit", "--no-fund"], root)
        print("  lock: package-lock.json (npm)")
        return
    except SystemExit as error:
        print(f"  lock: npm failed, writing a minimal lock ({str(error)[:120]})")
    package = json.loads((root / "package.json").read_text())
    lock = {
        "name": package["name"],
        "version": package["version"],
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": package["name"], "version": package["version"],
                 "dependencies": package["dependencies"]},
        },
    }
    for name, version in package["dependencies"].items():
        entry = {
            "version": version,
            "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
            "integrity": "sha512-lab",
        }
        lock["packages"][f"node_modules/{name}"] = entry
        lock.setdefault("dependencies", {})[name] = {"version": version}
    (root / "package-lock.json").write_text(json.dumps(lock, indent=2) + "\n")


def _commit(root: Path, message: str) -> str:
    _run(["git", "add", "-A"], root)
    _run(["git", "-c", "user.name=Juice Shop CI", "-c", "user.email=ci@juice-shop.demo",
          "commit", "-q", "-m", message], root)
    return _run(["git", "rev-parse", "HEAD"], root)


def _init(root: Path, remote: str) -> None:
    root.mkdir(parents=True, exist_ok=True)
    if (root / ".git").is_dir():
        shutil.rmtree(root / ".git")
    _run(["git", "init", "-q", "-b", "main"], root)
    _run(["git", "remote", "add", "origin", remote], root)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dest", default=os.path.expanduser(
        os.environ.get("POC_DIR", "~/HUB/Workspace/Councilbox/CYB/poc-juice-shop")))
    args = parser.parse_args()
    dest = Path(args.dest).expanduser().resolve()
    dest.mkdir(parents=True, exist_ok=True)

    state: dict[str, dict] = {}

    web = dest / "juice-shop-web"
    print(f"web  {web}")
    _init(web, "https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git")
    _write_files(web, WEB_FILES)
    _lockfile(web)
    # Two commits: v1.0.0 is what production runs, v1.2.0 is the build CI ships.
    v1 = _commit(web, "feat(storefront): 2019 storefront and product API")
    state["web_v1"] = {"path": str(web), "commit": v1, "version": "1.0.0"}
    _write_files(web, {"package.json": WEB_V2_PACKAGE,
                       "Dockerfile": WEB_V2_DOCKERFILE,
                       "server.js": WEB_FILES["server.js"].replace(
                           "juice-shop-prod-signing-key-2019",
                           "juice-shop-prod-signing-key-2026"),
                       "routes/products.js": WEB_FILES["routes/products.js"].replace(
                           '"SELECT id, name, price FROM products WHERE name LIKE \'%" + term + "%\'"',
                           '"SELECT id, name, price FROM products WHERE name LIKE ?"')
                       .replace("db.query(sql, (err, rows)", "db.query(sql, ['%' + term + '%'], (err, rows)")})
    (web / "package-lock.json").unlink()
    _lockfile(web)
    v2 = _commit(web, "chore(deps): update runtime and dependencies for 1.2.0")
    state["web_v2"] = {"path": str(web), "commit": v2, "version": "1.2.0"}

    api = dest / "juice-shop-api"
    print(f"api  {api}")
    _init(api, "https://gitea.juice-shop.demo/juice-shop/juice-shop-api.git")
    _write_files(api, API_FILES)
    v3 = _commit(api, "feat(orders): orders, profiles and pricing")
    state["api"] = {"path": str(api), "commit": v3, "version": "0.9.0"}

    (dest / "repos.json").write_text(json.dumps(state, indent=2) + "\n")
    print(json.dumps(state, indent=2))
    print(f"\nstate: {dest / 'repos.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
