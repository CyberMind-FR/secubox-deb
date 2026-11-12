# SPDX-License-Identifier: LicenseRef-CMSD-1.0
# Copyright (c) 2026 CyberMind — Gérald Kerma <devel@cybermind.fr>
# Source-Disclosed License — All rights reserved except as expressly granted.
# See LICENCE-CMSD-1.0.md for terms.
"""Companion 2.0 : Origines.java compilée et exécutée hors Android (javac + java).

JUnit n'est pas dans le cache Gradle du poste : plutôt que de le télécharger, ce test compile
la classe pure avec un petit pilote et vérifie son comportement réel, cas par cas.
"""
import shutil
import subprocess
from pathlib import Path

import pytest

SOURCE = (Path(__file__).resolve().parents[1] / "android" / "app" / "src" / "main" / "java"
          / "in" / "secubox" / "companion" / "Origines.java")

PILOTE = """\
package in.secubox.companion;

public final class Pilote {
    public static void main(String[] a) {
        for (int i = 0; i < a.length; i++) {
            String r;
            switch (a[i]) {
                case "o": r = String.valueOf(Origines.origineHttps(a[++i])); break;
                case "s": r = Origines.schema(a[++i]); break;
                default: r = String.valueOf(Origines.memeOrigine(a[++i], a[++i]));
            }
            System.out.println(r);
        }
    }
}
"""

NUL = "null"

ORIGINES = [
    ("https://admin.gk12.secubox.in", "https://admin.gk12.secubox.in"),
    ("https://admin.gk12.secubox.in/", "https://admin.gk12.secubox.in"),
    ("https://ADMIN.Gk12.SecuBox.IN", "https://admin.gk12.secubox.in"),
    ("HTTPS://admin.gk12.secubox.in", "https://admin.gk12.secubox.in"),
    ("https://admin.gk12.secubox.in:443", "https://admin.gk12.secubox.in"),
    ("https://admin.gk12.secubox.in:8443", "https://admin.gk12.secubox.in:8443"),
    ("https://192.168.1.1", "https://192.168.1.1"),
    ("https://[fd00::1]:8443", "https://[fd00::1]:8443"),
    ("http://admin.gk12.secubox.in", NUL),
    ("https://a\\.b", NUL),
    ("https://a.b:abc", NUL),
    ("https://a.b:", NUL),
    ("https://a.b:0", NUL),
    ("https://a.b:70000", NUL),
    ("https://a_b.c", NUL),
    ("https://user@a.b", NUL),
    ("https://user:pw@a.b", NUL),
    ("https://a.b/admin", NUL),
    ("https://a.b/?x=1", NUL),
    ("https://a.b/#f", NUL),
    ("https://localhost", NUL),
    ("https://LOCALHOST:443", NUL),
    ("https://localhost.", NUL),
    ("https://box.localhost", NUL),
    ("https://", NUL),
    ("", NUL),
    ("intent://a.b#Intent;scheme=https;end", NUL),
    ("javascript:alert(1)", NUL),
    ("file:///data/data/in.secubox.companion", NUL),
    ("content://in.secubox.companion.fileprovider/x", NUL),
    ("data:text/html,<b>x</b>", NUL),
]

BOX = "https://admin.gk12.secubox.in"
MEMES = [
    (BOX, "https://admin.gk12.secubox.in/", "true"),
    (BOX, "https://ADMIN.gk12.secubox.in/cgi?x=1#y", "true"),
    (BOX, "https://admin.gk12.secubox.in:443/a", "true"),
    ("https://admin.gk12.secubox.in:8443", "https://admin.gk12.secubox.in:8443/", "true"),
    ("https://admin.gk12.secubox.in:8443", "https://admin.gk12.secubox.in/", "false"),
    (BOX, "https://admin.gk12.secubox.in:8443/", "false"),
    (BOX, "http://admin.gk12.secubox.in/", "false"),
    (BOX, "http://admin.gk12.secubox.in:443/", "false"),
    (BOX, "https://autre.secubox.in/", "false"),
    (BOX, "https://admin.gk12.secubox.in.evil.example/", "false"),
    (BOX, "https://evil.example/?https://admin.gk12.secubox.in/", "false"),
    (BOX, "https://a\\.b/", "false"),
    (BOX, "intent://admin.gk12.secubox.in/#Intent;scheme=https;end", "false"),
    (BOX, "javascript:location='https://admin.gk12.secubox.in/'", "false"),
    (BOX, "file:///android_asset/x.html", "false"),
    (BOX, "content://in.secubox.companion.fileprovider/x", "false"),
    (BOX, "data:text/html,x", "false"),
    (BOX, "about:blank", "false"),
    (BOX, "", "false"),
]

SCHEMAS = [
    ("https://a.b/", "https"),
    ("HTTP://a.b/", "http"),
    ("intent://x#Intent;end", "intent"),
    ("javascript:alert(1)", "javascript"),
    ("file:///x", "file"),
    ("content://x/y", "content"),
    ("data:text/html,x", "data"),
    ("secubox://associer?box=x", "secubox"),
    ("sans-schema", ""),
    (":vide", ""),
    ("1http://a.b", ""),
]


@pytest.fixture(scope="module")
def executer(tmp_path_factory):
    javac, java = shutil.which("javac"), shutil.which("java")
    if not javac or not java:
        pytest.skip("JDK absente (javac/java)")
    d = tmp_path_factory.mktemp("origines")
    pilote = d / "Pilote.java"
    pilote.write_text(PILOTE, encoding="utf-8")
    sortie = d / "classes"
    subprocess.run([javac, "-encoding", "UTF-8", "-d", str(sortie), str(SOURCE), str(pilote)],
                   check=True, capture_output=True, text=True)

    def lancer(args):
        r = subprocess.run([java, "-cp", str(sortie), "in.secubox.companion.Pilote", *args],
                           check=True, capture_output=True, text=True, encoding="utf-8")
        return r.stdout.split("\n")[:-1]

    return lancer


def test_origine_https(executer):
    args = [x for brut, _ in ORIGINES for x in ("o", brut)]
    obtenu = executer(args)
    attendu = [a for _, a in ORIGINES]
    assert list(zip([b for b, _ in ORIGINES], obtenu)) == list(zip([b for b, _ in ORIGINES], attendu))


def test_meme_origine(executer):
    args = [x for o, u, _ in MEMES for x in ("m", o, u)]
    obtenu = executer(args)
    assert [(o, u, r) for (o, u, _), r in zip(MEMES, obtenu)] == MEMES


def test_schema(executer):
    args = [x for u, _ in SCHEMAS for x in ("s", u)]
    obtenu = executer(args)
    assert list(zip([u for u, _ in SCHEMAS], obtenu)) == SCHEMAS
