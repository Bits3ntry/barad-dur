# Comandos reales, sin envoltorios

Para la demo conviene tipear el CLI, no un script: el público ve el comando, el contrato
y el resultado en la misma pantalla. Los `scripts/poc_demo/*.sh` quedan como plan B.

**Preparación (una vez por terminal):**

```bash
cd ~/HUB/Workspace/Councilbox/CYB/Barad-d-r
set -a; source .env; set +a
export SHAURON_PLATFORM=http://127.0.0.1:8090
# Si el lab no vive en ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop, exportá POC_DIR
# y usá $POC_DIR en los comandos de abajo: los scripts ya lo respetan.
```

`shauron` está en el PATH: `~/.local/bin/shauron` es un wrapper que ejecuta el CLI desde el
repo hermano con el venv de Barad-dûr (no hay nada pip-instalado y no se tocó el árbol de
`shaaron`). Si alguna vez no está, `./.venv/bin/shauron` es exactamente lo mismo.

---

## 1 · La máquina (`0:30`)

```bash
shauron doctor
```

```
shauron    0.1.0
python     3.13.7 (…/Barad-d-r/.venv/bin/python)
engine     trivy: 0.76.1 at ~/.local/bin/trivy (path)
engine     opengrep: 1.33.1 at ~/.local/bin/opengrep (path)
engine     gitleaks: 8.30.1 at ~/.local/bin/gitleaks (path)
barad      reachable (200)
```

**Frase:** "antes de escanear, saber con qué cuenta esta máquina: cada motor con su versión
y de dónde salió, y si la plataforma contesta."

## 2 · El arsenal (`0:20`)

```bash
shauron tools
```

Tabla de herramientas y perfiles que este build declara. No usa red.

**Frase:** "el catálogo es datos, no prosa: por eso puedo decir qué corre y qué no."

## 3 · El plan, en seco (`1:00`)

```bash
shauron plan --profile recon.simple --target juice-shop.demo
```

```
Basic web recon on juice-shop.demo
  stage        tool       state  why
  discover     dns        allow  passive_discovery
  probe        tls        allow  active_verification
  probe        http-head  allow  active_verification
  fingerprint  whatweb    allow  active_verification
  ▸ 4 step(s) ready
```

No toca el host: resuelve pasos, capacidades y veredicto.

**Frase:** "esto es lo que haría. Para que corra, cada paso tiene que caer dentro de una
autorización; si no, acá dice `not_authorized` y con qué grant chocó."

> `web.redteam` (el profundo) es `cloud`: no se puede correr desde la terminal. Se lanza
> desde la consola — `#assets` → `juice-shop.demo` → `red teaming` — y el worker lo toma.

## 4 · El build nuevo (CI/CD en vivo, `1:30`)

```bash
shauron scan \
  --project juice-shop \
  --component juice-shop-web \
  --repository https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git \
  --path ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-web \
  --commit 3c147ec35a0b91f1f199d61b259070de3e544eb4 \
  --version 1.2.0 --action supply-chain
```

```
ticket 949a…  · action supply-chain · tasks ['sbom', 'runtime', 'misconfig', 'secrets']
finished in 41.2s · counts {'findings': 31} · drops 0
```

Y las debilidades de código, con el mismo ticket shape:

```bash
shauron scan \
  --project juice-shop --component juice-shop-web \
  --repository https://gitea.juice-shop.demo/juice-shop/juice-shop-web.git \
  --path ~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/juice-shop-web \
  --commit 3c147ec35a0b91f1f199d61b259070de3e544eb4 \
  --version 1.2.0 --action code
```

**Qué decir mientras corre:** el `--commit` es el sha real de ese árbol (si no coinciden, el
resultado miente), la versión se lee del `package.json` y no se inventa, y son **dos tickets
porque son dos preguntas**: `supply-chain` mira dependencias, runtime y configuración; `code`
mira el código. Un push no dispara todo: dispara lo que cambió.

> `--origin cli` (por defecto) es un push ticket: no pide grant ni toca red. El CI pasa
> `--origin ci` para que la procedencia quede registrada como pipeline.

## 5 · Ver el resultado

- Consola → `Proyectos` → **Juice Shop** → `juice-shop-web` → versión `1.2.0`: SBOM, CVEs
  nuevas y las que siguen abiertas (no todo se arregla subiendo de versión).
- Consola → `Proyectos` → nuevo despliegue: `juice-shop-web` `1.2.0` en `staging`.
  Producción sigue en `1.0.0` — desplegar no es arreglar.

---

## Plan B (si algo no sale en vivo)

```bash
bash scripts/poc_demo/run_scans.sh --new-only   # los dos `shauron scan` de arriba, con logs en ~/poc-juice-shop/logs
bash scripts/poc_demo/run_recon.sh              # lanza el recon profundo y lo sigue paso a paso
bash scripts/poc_demo/poc_build_demo.sh         # reconstruye todo el escenario (~5 min)
```

Los scripts imprimen el comando que ejecutan; si el público pregunta "¿qué corrió?",
el log de cada corrida está en `~/HUB/Workspace/Councilbox/CYB/poc-juice-shop/logs/`.
