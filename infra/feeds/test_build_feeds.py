"""Tests hors ligne de build_feeds.py :  python3 -m unittest infra/feeds/test_build_feeds.py"""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location("build_feeds", Path(__file__).with_name("build_feeds.py"))
bf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bf)


class ParseTests(unittest.TestCase):
    def test_domains(self):
        body = "! commentaire\n||piege-banque.com^\n0.0.0.0 faux-colis.net\nhttps://www.arnaque.fr/x\nlaposte.fr\n"
        self.assertEqual(bf.parse("domains", body), {"piege-banque.com", "faux-colis.net", "arnaque.fr"})

    def test_ips_urls_hashes(self):
        self.assertEqual(bf.parse("ips", "# x\n203.0.113.5\t7\n"), {"203.0.113.5"})
        self.assertEqual(bf.parse("urls", "HTTP://Evil.example.com/a/\n"), {"evil.example.com/a"})
        self.assertEqual(bf.parse("hashes", "A" * 64 + "\n"), {"a" * 64})


class MainTests(unittest.TestCase):
    def test_licence_excluded_and_outputs(self):
        def fake_fetch(url):
            if "openphish" in url:
                raise AssertionError("OpenPhish ne doit pas être téléchargé")
            if "phishing-filter" in url:
                return "||piege-banque.com^\n"
            if "urlhaus" in url:
                return "http://evil.example.com/p\n"
            if "feodo" in url or "ipsum" in url:
                return "203.0.113.5\n"
            return "b" * 64 + "\n"
        with tempfile.TemporaryDirectory() as d, mock.patch.object(bf, "fetch", fake_fetch), mock.patch.object(bf, "OUT", Path(d)):
            self.assertEqual(bf.main(), 0)
            m = json.loads((Path(d) / "manifest.json").read_text())
            self.assertEqual(m["sources"]["openphish-community"], "ignorée (licence)")
            self.assertTrue(m["sources"]["urlhaus-online"].startswith("ignorée (export anonyme fermé"))
            self.assertEqual((Path(d) / "domains.txt").read_text(), "piege-banque.com")

    def test_all_fail_publishes_nothing(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.object(bf, "fetch", side_effect=OSError("réseau")), mock.patch.object(bf, "OUT", Path(d) / "out"):
            self.assertEqual(bf.main(), 1)
            self.assertFalse((Path(d) / "out").exists())


if __name__ == "__main__":
    unittest.main()
