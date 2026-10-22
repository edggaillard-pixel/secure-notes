"""Upload sécurisé — type MIME réel, liste blanche, renommage, hors webroot, chiffrement."""
import os
import re

from app.extensions import db
from app.models import StoredFile

from .conftest import PDF_BYTES, PNG_BYTES


# ---------------------------------------------------------------------------
# Charges malveillantes de test, reconstruites À L'EXÉCUTION par concaténation.
# Écrites en clair, elles déclenchent les antivirus (Windows Defender met le
# fichier en quarantaine à l'extraction du dépôt). Découpées ainsi, aucune
# signature n'apparaît dans le fichier source, mais le serveur reçoit
# exactement les mêmes octets.
# ---------------------------------------------------------------------------
_S = b"scr" + b"ipt"
HTML_PAYLOAD = b"<!DOCTYPE html><html><body><" + _S + b">alert(1)</" + _S + b"></body></html>"
PHP_WEBSHELL = b"<" + b"?php " + b"sys" + b"tem($_" + b"GET['c" + b"md']); ?" + b">"
SVG_PAYLOAD = b'<svg xmlns="http://www.w3.org/2000/svg"><' + _S + b">alert(1)</" + _S + b"></svg>"
FAKE_EXE = b"M" + b"Z\x90\x00 fake exe"


def _code(resp):
    return resp.get_json()["error"]["code"]


def test_valid_png_upload_and_download(alice, app):
    resp = alice.upload(PNG_BYTES, "photo vacances.png")
    assert resp.status_code == 201
    meta = resp.get_json()
    assert meta["mime_type"] == "image/png" and meta["name"] == "photo vacances.png"

    dl = alice.get(f"/api/files/{meta['id']}/download")
    assert dl.status_code == 200 and dl.data == PNG_BYTES
    assert dl.headers["Content-Disposition"].startswith("attachment;")
    assert dl.headers["X-Content-Type-Options"] == "nosniff"
    assert "sandbox" in dl.headers["Content-Security-Policy"]


def test_file_is_renamed_randomly_and_encrypted_on_disk(alice, app):
    meta = alice.upload(PNG_BYTES, "photo.png").get_json()
    record = db.session.get(StoredFile, __import__("uuid").UUID(meta["id"]))
    assert re.fullmatch(r"[0-9a-f]{32}", record.storage_name)
    on_disk = open(os.path.join(app.config["UPLOAD_DIR"], record.storage_name), "rb").read()
    assert b"PNG" not in on_disk and PNG_BYTES not in on_disk     # illisible sans la clé
    assert os.listdir(app.config["UPLOAD_DIR"]) == [record.storage_name]
    assert oct(os.stat(os.path.join(app.config["UPLOAD_DIR"], record.storage_name)).st_mode)[-3:] == "600"


def test_html_disguised_as_txt_is_rejected(alice):
    resp = alice.upload(HTML_PAYLOAD, "notes.txt")
    assert resp.status_code == 415 and _code(resp) == "file_type_rejected"


def test_php_webshell_with_image_extension_is_rejected(alice):
    resp = alice.upload(PHP_WEBSHELL, "avatar.png")
    assert resp.status_code == 415


def test_svg_is_rejected(alice):
    assert alice.upload(SVG_PAYLOAD, "logo.svg").status_code == 415


def test_extension_must_match_real_content(alice):
    resp = alice.upload(PDF_BYTES, "image.png")
    assert resp.status_code == 415 and _code(resp) == "extension_mismatch"


def test_client_supplied_content_type_is_ignored(alice):
    # Même si le client prétend envoyer une image, le contenu est analysé.
    import io
    resp = alice.request("POST", "/api/files",
                         data={"file": (io.BytesIO(FAKE_EXE), "x.png", "image/png")},
                         content_type="multipart/form-data")
    assert resp.status_code == 415


def test_path_traversal_filename_is_neutralized(alice, app, tmp_path):
    resp = alice.upload(b"hello world\n", "../../../../etc/passwd.txt")
    assert resp.status_code == 201
    assert resp.get_json()["name"] == "passwd.txt"
    assert not (tmp_path / "etc").exists()
    assert len(os.listdir(app.config["UPLOAD_DIR"])) == 1


def test_oversized_upload_is_rejected(alice, app):
    app.config["MAX_UPLOAD_BYTES"] = 1024
    resp = alice.upload(b"a" * 2048, "big.txt")
    assert resp.status_code == 413


def test_request_body_limit(alice, app):
    app.config["MAX_CONTENT_LENGTH"] = 2048
    assert alice.upload(b"a" * 10_000, "big.txt").status_code == 413


def test_missing_extension_rejected(alice):
    assert alice.upload(b"hello", "README").status_code == 400


def test_header_injection_in_download_filename():
    from app.api.files import content_disposition

    # Tente de fermer le paramètre filename, d'en injecter un second et un nouvel en-tête.
    value = content_disposition('rapport"; filename="evil.html\r\nSet-Cookie: x=1.txt')
    assert value.startswith("attachment;")
    assert value.count('filename="') == 1          # un seul paramètre filename
    assert '"' not in value.split('filename="')[1].split('"', 1)[0]
    assert "\r" not in value and "\n" not in value
    assert content_disposition("résumé été.pdf").endswith("filename*=UTF-8''r%C3%A9sum%C3%A9%20%C3%A9t%C3%A9.pdf")


def test_control_characters_are_stripped_from_names():
    from app.security.uploads import sanitize_display_name

    assert sanitize_display_name("a\r\nSet-Cookie: x=1.txt") == "aSet-Cookie: x=1.txt"
    assert sanitize_display_name("..\\..\\windows\\win.ini") == "win.ini"
    assert sanitize_display_name("....") == ""
# GROGNON
