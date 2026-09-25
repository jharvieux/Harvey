"""Independent PDF consumer for the shipping renderer's acceptance fixture."""

import hashlib
import json
import sys
import tempfile
import unicodedata
from pathlib import Path

from pypdf import PdfReader


def normalized(value):
    return " ".join(unicodedata.normalize("NFKC", value).split())


def rendered_populations(page):
    # Read painted text positions and glyph advances from the pinned pypdf layout
    # extractor. Adjacent prose can repeat correct counts beside an incorrect chart.
    with tempfile.TemporaryDirectory() as directory:
        page.extract_text(extraction_mode="layout", layout_mode_debug_path=Path(directory))
        fragments = json.loads((Path(directory) / "tjs.json").read_text())
    runs = []
    for fragment in fragments:
        if not fragment["txt"].strip() or fragment["rotated"]:
            continue
        x, baseline, height = fragment["tx"], fragment["ty"], fragment["font_height"]
        if not fragment["flip_vertical"]:
            baseline = -baseline
        width = fragment["displaced_tx"] - x
        # Chromium may emit a ligature and its suffix as separate text operations
        # sharing one origin. Their glyph advances still form one visible label.
        if runs and (runs[-1]["x"], runs[-1]["baseline"], runs[-1]["height"]) == (x, baseline, height):
            runs[-1]["text"] += fragment["txt"]
            runs[-1]["width"] += width
        else:
            runs.append({"text": fragment["txt"], "x": x, "baseline": baseline,
                         "height": height, "width": width})
    for run in runs:
        run["text"] = normalized(run["text"])
    center = lambda run: run["x"] + run["width"] / 2

    def value_above(label):
        pairs = []
        for label_run in (run for run in runs if run["text"] == label):
            for number in runs:
                if (number["text"].isdigit() and number["height"] >= 1.5 * label_run["height"]
                        and 0 < label_run["baseline"] - number["baseline"] < 3 * label_run["height"]
                        and abs(center(number) - center(label_run)) < 0.35 * label_run["height"]):
                    pairs.append({"value": int(number["text"]), "number_region": number,
                                  "label_region": label_run})
        assert len(pairs) == 1, f"Expected one rendered numeral above {label!r}; found {pairs}"
        return pairs[0]

    return {"donut": value_above("findings"),
            "confirmed_m1": {label: value_above(label) for label in ["Critical", "High", "Medium", "Low"]}}


pdf_path, expected_path = map(Path, sys.argv[1:3])
expected = json.loads(expected_path.read_text())
reader = PdfReader(pdf_path, strict=True)
assert len(reader.pages) > 2, "Expected a real multi-page report"
texts = [normalized(page.extract_text()) for page in reader.pages]
complete_text = " ".join(texts)
observed_populations = None
for text in expected["required_text"]:
    assert normalized(text) in complete_text, f"PDF lost required content: {text}"
if "populations" in expected:
    observed_populations = rendered_populations(reader.pages[0])
    assert observed_populations["donut"]["value"] == expected["populations"]["chart_total"], (
        f"Rendered donut count mismatch: {observed_populations['donut']} != {expected['populations']['chart_total']}")
    severity_counts = {label: region["value"] for label, region in observed_populations["confirmed_m1"].items()}
    assert severity_counts == expected["populations"]["confirmed_m1_counts"], (
        f"Rendered M1 severity panel mismatch: {severity_counts} != {expected['populations']['confirmed_m1_counts']}")
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
                  "finding_destinations": len(expected["linked_findings"]),
                  **({"rendered_populations": observed_populations} if observed_populations else {})}))
