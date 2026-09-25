"""Independent PDF consumer for the shipping renderer's acceptance fixture."""

import hashlib
import json
import sys
import unicodedata
from pathlib import Path

from pypdf import PdfReader


def normalized(value):
    return " ".join(unicodedata.normalize("NFKC", value).split())


pdf_path, expected_path = map(Path, sys.argv[1:3])
expected = json.loads(expected_path.read_text())
reader = PdfReader(pdf_path, strict=True)
assert len(reader.pages) > 2, "Expected a real multi-page report"
texts = [normalized(page.extract_text()) for page in reader.pages]
complete_text = " ".join(texts)
for text in expected["required_text"]:
    assert normalized(text) in complete_text, f"PDF lost required content: {text}"
if "populations" in expected:
    cover = complete_text.split("Scope & methodology", 1)[0]
    for text in expected["populations"]["cover_text"]:
        assert normalized(text) in cover, f"Cover population mismatch: {text}"
    action = cover.split("Action plan", 1)[1]
    for text in expected["populations"]["forbidden_actions"]:
        assert normalized(text) not in action, f"Non-actionable population entered action plan: {text}"
    for text in expected["populations"]["required_actions"]:
        assert normalized(text) in action, f"Current module action lost: {text}"

destinations = reader.named_destinations
links = [(index, annotation.get_object().get("/Dest"))
         for index, page in enumerate(reader.pages)
         for annotation in page.get("/Annots", [])
         if annotation.get_object().get("/Subtype") == "/Link"
         and annotation.get_object().get("/Dest")]
# Chromium emits one annotation per wrapped line of link text, so a single HTML link
# can occupy multiple rectangles. Every intended identity still needs its own destination.
assert len(links) >= expected["link_count"], "PDF lost internal annotations"
cross_page = 0
for source_page, name in links:
    assert name in destinations, f"Unresolved PDF destination: {name}"
    destination_page = reader.get_destination_page_number(destinations[name])
    assert 0 <= destination_page < len(texts), f"Destination outside PDF: {name}"
    if source_page != destination_page:
        cross_page += 1
for finding in expected["linked_findings"]:
    anchor = "/finding-" + finding["id"].encode("utf-8").hex()
    assert anchor in destinations, f"Missing intended finding: {finding['id']}"
    assert any(name == anchor for _, name in links), f"No PDF link for {finding['id']}"
    page = reader.get_destination_page_number(destinations[anchor])
    for text in finding["detail"]:
        assert normalized(text) in texts[page], f"Destination lacks usable member detail: {finding['id']}: {text}"
assert cross_page > 0, "No cross-page internal navigation was exercised"
print(json.dumps({"pdf": str(pdf_path), "sha256": hashlib.sha256(pdf_path.read_bytes()).hexdigest(),
                  "pages": len(reader.pages), "internal_links": len(links), "cross_page_links": cross_page,
                  "finding_destinations": len(expected["linked_findings"])}))
