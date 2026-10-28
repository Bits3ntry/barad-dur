"""Tests for title normalisation and derived enrichment."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.importer.finding_enrichment import (  # noqa: E402
    enrich, normalize_title, parse_labels,
)


def row(summary, description="", key="CY-1", **extra):
    return {"Clave": key, "Resumen": summary, "Descripción": description, **extra}


class TitleTests(unittest.TestCase):
    def test_strips_jira_key_ticket_code_and_severity_bracket(self):
        r = row("CY-44 - CBX-Q324-8 [MEDIUM] - Permissive Cross-Domain Policy with Untrusted Domains",
                "see CVE-2012-2292")
        self.assertEqual(normalize_title(r),
                         "Permissive Cross-Domain Policy with Untrusted Domains (CVE-2012-2292)")

    def test_strips_vuln_id_and_trailing_spanish_severity(self):
        r = row("CY-55 - VULN-058 - Configuración de seguridad incorrecta [INSS] (Media)")
        self.assertEqual(normalize_title(r), "Configuración de seguridad incorrecta")

    def test_strips_nested_epic_and_audit_brackets(self):
        r = row("CY-69 - CY-68 [FORENSIC&SECURITY] - VULN-01 - Unauthenticated Local File Inclusion [CRITICO - 10.0]")
        self.assertEqual(normalize_title(r), "Unauthenticated Local File Inclusion")

    def test_strips_leading_audit_number(self):
        r = row("CY-79 - 002 - Evasión del esquema de autorización")
        self.assertEqual(normalize_title(r), "Evasión del esquema de autorización")

    def test_falls_back_to_key_when_nothing_remains(self):
        r = row("[MEDIUM] - 001 -", key="CY-999")
        self.assertEqual(normalize_title(r), "CY-999")

    def test_title_is_bounded(self):
        self.assertLessEqual(len(normalize_title(row("A" * 900))), 500)


class ClassTests(unittest.TestCase):
    def test_sqli_detected_with_cwe_89(self):
        e = enrich(row("SQL Injection no autenticada en companyDrafts"))
        self.assertEqual((e["class"], e["cwe"]), ("sqli", 89))

    def test_declared_cwe_in_text_wins(self):
        e = enrich(row("SSRF no autenticado (CWE-918)"))
        self.assertEqual(e["cwe"], 918)

    def test_unknown_class_leaves_context_empty(self):
        e = enrich(row("Revisar configuración del cluster de pruebas"))
        self.assertIsNone(e["class"])
        self.assertIsNone(e["impact"])
        self.assertIsNone(e["mitigation"])

    def test_weak_crypto_class_from_tls_wording(self):
        e = enrich(row("Fallos criptográficos: uso del protocolo TLS 1.0"))
        self.assertEqual(e["class"], "weak_crypto")
        self.assertEqual(e["cwe"], 326)


class LabelAndProvenanceTests(unittest.TestCase):
    DESC = ("* *Id Vulnerabilidad*: GISS-ISSM-WEB-3 * *Descripción*: Faltan cabeceras. "
            "* *Impacto*: Permite clickjacking. * *Recomendaciones*: Publicar CSP y HSTS.")

    def test_parses_labelled_blocks(self):
        labels = parse_labels(self.DESC)
        self.assertEqual(labels["Id Vulnerabilidad"], "GISS-ISSM-WEB-3")
        self.assertEqual(labels["Impacto"], "Permite clickjacking.")
        self.assertEqual(labels["Recomendaciones"], "Publicar CSP y HSTS.")

    def test_auditor_text_wins_and_is_marked_as_such(self):
        e = enrich(row("CY-55 - VULN-058 - Configuración de seguridad incorrecta [INSS] (Media)", self.DESC))
        self.assertEqual(e["impact"], "Permite clickjacking.")
        self.assertEqual(e["mitigation"], "Publicar CSP y HSTS.")
        self.assertEqual((e["impact_source"], e["mitigation_source"]), ("auditor", "auditor"))

    def test_derived_context_is_flagged_as_derived(self):
        e = enrich(row("Path traversal"))
        self.assertEqual(e["impact_source"], "derived")
        self.assertEqual(e["mitigation_source"], "derived")

    def test_references_links_back_to_jira(self):
        e = enrich(row("SQLI", key="CY-89"))
        self.assertEqual(e["references"], "https://councilbox.atlassian.net/browse/CY-89")

    def test_long_description_does_not_override_a_clear_title(self):
        noisy = ("Referencias: https://owasp.org/file-upload y https://cwe.mitre.org. "
                 "Esta sección menciona file upload y SSRF como ejemplos genéricos.")
        e = enrich(row("Exposure of Administrative Routes", noisy))
        self.assertIsNone(e["class"], "description keywords must not classify the finding")
        self.assertIsNone(e["cwe"])

    def test_cve_is_not_duplicated_in_the_title(self):
        e = enrich(row("CVE-2026-64638 councilbox.com"))
        self.assertEqual(e["title"], "CVE-2026-64638 councilbox.com")

    def test_description_alone_never_classifies(self):
        e = enrich(row("Hallazgo sin clasificar", "Ataque de tipo SQL injection en el buscador."))
        self.assertIsNone(e["class"], "a vague title must stay unclassified rather than guessed")


if __name__ == "__main__":
    unittest.main()
