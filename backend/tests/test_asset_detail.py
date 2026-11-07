"""Asset detail: the panel has to show what the scanners actually read.

`Observation.value` is a JSON column, so the row arrives as a dict. The reader
used to call `json.loads` on it, which raises on a dict and was swallowed by an
`except` — every technology the scanners found disappeared and the asset page
said "nothing fingerprinted yet" while the table held links, PHP and nginx.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def detail_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/detail.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "detail")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, org.id


def _asset_with(client, headers, rows):
    created = client.post("/api/v1/assets",
                          json={"type": "domain", "value": "councilbox.com"},
                          headers=headers).json()["data"]
    session = session_factory()()
    org = session.query(models.Organization).first()
    for row in rows:
        session.add(models.Observation(org_id=org.id, asset_id=created["id"],
                                       subject="councilbox.com", **row))
    session.commit()
    session.close()
    return created


def test_a_technology_observation_is_read_instead_of_thrown_away(detail_client):
    client, headers, _org = detail_client
    asset = _asset_with(client, headers, [{
        "kind": "technology",
        "value": {"products": [{"name": "php", "version": "8.2.35",
                                "evidence": "httpx tech-detect", "confidence": "exact"},
                               {"name": "wordpress", "version": None,
                                "evidence": "whatweb", "confidence": "range"}]},
        "source": "shauron:httpx",
    }])
    data = client.get(f"/api/v1/assets/{asset['id']}", headers=headers).json()["data"]
    products = {row["name"]: row for row in data["technologies"]}
    assert products["php"]["version"] == "8.2.35"
    assert products["php"]["confidence"] == "exact"
    assert products["php"]["source"] == "shauron:httpx"
    assert products["wordpress"]["version"] is None


def test_ports_merge_what_naabu_saw_with_what_nmap_named(detail_client):
    client, headers, _org = detail_client
    asset = _asset_with(client, headers, [
        {"kind": "port", "port": 22, "value": {"state": "open", "how": "naabu"},
         "source": "shauron:naabu"},
        {"kind": "port", "port": 22,
         "value": {"state": "open", "service": "ssh", "product": "OpenSSH",
                   "version": "8.2p1 Ubuntu 4ubuntu0.13"},
         "source": "shauron:nmap"},
        {"kind": "port", "port": 443,
         "value": {"state": "open", "service": "https", "product": "nginx"},
         "source": "shauron:nmap"},
    ])
    data = client.get(f"/api/v1/assets/{asset['id']}", headers=headers).json()["data"]
    ports = {row["port"]: row for row in data["ports"]}
    assert set(ports) == {22, 443}
    ssh = ports[22]
    assert ssh["service"] == "ssh"
    assert ssh["product"] == "OpenSSH"
    assert ssh["version"] == "8.2p1 Ubuntu 4ubuntu0.13"
    assert ssh["purpose"] == "remote shell"
    assert sorted(ssh["sources"]) == ["shauron:naabu", "shauron:nmap"]
    assert ports[443]["purpose"] == "web over TLS"


def test_the_web_stack_is_read_per_url(detail_client):
    client, headers, _org = detail_client
    asset = _asset_with(client, headers, [{
        "kind": "web_path",
        "value": {"url": "https://councilbox.com", "status": 301, "server": "nginx",
                  "tech": ["Nginx", "PHP:8.2.35", "Polylang", "jQuery/3.7.1"]},
        "source": "shauron:httpx",
    }])
    data = client.get(f"/api/v1/assets/{asset['id']}", headers=headers).json()["data"]
    assert len(data["web"]) == 1
    page = data["web"][0]
    assert page["url"] == "https://councilbox.com"
    assert page["status"] == 301
    assert page["server"] == "nginx"
    stack = {entry["name"]: entry["version"] for entry in page["tech"]}
    assert stack["php"] == "8.2.35"
    assert stack["jquery"] == "3.7.1"
    assert stack["nginx"] is None


def test_products_read_from_one_page_land_in_that_pages_stack(detail_client):
    """whatweb reads a page and says which one; its products belong to it."""
    client, headers, _org = detail_client
    asset = _asset_with(client, headers, [{
        "kind": "technology",
        "value": {"url": "https://councilbox.com",
                  "products": [{"name": "wordpress", "version": "6.8.2",
                                "evidence": "whatweb", "confidence": "range"},
                               {"name": "jquery", "version": "3.7.1",
                                "evidence": "whatweb", "confidence": "range"}]},
        "source": "shauron:whatweb",
    }])
    data = client.get(f"/api/v1/assets/{asset['id']}", headers=headers).json()["data"]
    stack = {row["name"]: row["version"] for row in data["web"][0]["tech"]}
    assert stack == {"wordpress": "6.8.2", "jquery": "3.7.1"}


def test_a_page_and_its_port_are_the_same_row(detail_client):
    """The join a reader would otherwise do by hand: 443 holds the stack."""
    client, headers, _org = detail_client
    asset = _asset_with(client, headers, [
        {"kind": "port", "port": 443,
         "value": {"state": "open", "service": "http", "product": "nginx"},
         "source": "shauron:nmap"},
        {"kind": "web_path",
         "value": {"url": "https://councilbox.com", "status": 301, "server": "nginx",
                   "tech": ["PHP:8.2.35", "Polylang"]},
         "source": "shauron:httpx"},
        {"kind": "certificate", "port": 443,
         "value": {"issuer": {"organizationName": "Let's Encrypt"},
                   "days_left": 43, "cipher": "TLS_AES_256_GCM_SHA384"},
         "source": "shauron:native"},
        {"kind": "port", "port": 22,
         "value": {"state": "open", "service": "ssh", "product": "OpenSSH",
                   "version": "8.2p1"},
         "source": "shauron:nmap"},
    ])
    data = client.get(f"/api/v1/assets/{asset['id']}", headers=headers).json()["data"]
    services = {row["port"]: row for row in data["services"]}
    assert set(services) == {22, 443}
    web = services[443]
    assert web["service"] == "http"
    assert web["product"] == "nginx"
    assert web["purpose"] == "web over TLS"
    assert web["tls"]["issuer"] == "Let's Encrypt"
    assert web["tls"]["days_left"] == 43
    stack = {entry["name"]: entry["version"] for entry in web["web"][0]["tech"]}
    assert stack["php"] == "8.2.35"
    assert "shauron:httpx" in web["sources"]
    # A port with nothing behind it stays a single line.
    assert services[22]["web"] == []
    assert services[22]["tls"] is None
    assert services[22]["purpose"] == "remote shell"


def test_a_page_read_from_an_odd_port_lands_on_that_port(detail_client):
    client, headers, _org = detail_client
    asset = _asset_with(client, headers, [{
        "kind": "web_path",
        "value": {"url": "https://councilbox.com:8443/admin", "status": 200,
                  "server": "nginx", "tech": []},
        "source": "shauron:httpx",
    }])
    data = client.get(f"/api/v1/assets/{asset['id']}", headers=headers).json()["data"]
    services = {row["port"]: row for row in data["services"]}
    assert 8443 in services
    assert services[8443]["web"][0]["url"].endswith("/admin")
    assert services[8443]["purpose"] == "web over TLS (alternate)"
