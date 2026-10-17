"""Shape of a card in Het Fotoboek (/leden/fotos), edited by FOCUS.

One card is one event with a cover image and links to its photo albums. The
frontend counterpart is ``PhotoEvent`` in
``dodekafrontend/src/pages/leden/fotos/fotos.tsx``; keep the two in sync.
"""

import re
from datetime import date
from typing import Any

EVENT_TYPES = frozenset({"Wedstrijd", "Gezelligheid", "Training", "Reis", "Overig"})

MAX_NAME_LENGTH = 200
MAX_LINKS = 20
MAX_LINK_LABEL_LENGTH = 50
MAX_URL_LENGTH = 2000

ALLOWED_FIELDS = frozenset({"name", "date", "type", "seizoen", "image", "links"})
SEASON_PATTERN = re.compile(r"^\d{2}/\d{2}$")


def is_web_url(value: str) -> bool:
    return value.startswith(("https://", "http://")) and len(value) <= MAX_URL_LENGTH


def validate_foto_card(item: dict[str, Any]) -> list[str]:
    """Return the problems with a card's fields; an empty list means valid.

    ``item`` is the card without its ``id`` (the collection handler owns ids).
    """
    problems: list[str] = []

    unknown = set(item) - ALLOWED_FIELDS
    if unknown:
        problems.append(f"unknown fields: {', '.join(sorted(unknown))}")

    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        problems.append("name is required")
    elif len(name) > MAX_NAME_LENGTH:
        problems.append(f"name is longer than {MAX_NAME_LENGTH} characters")

    raw_date = item.get("date")
    try:
        if not isinstance(raw_date, str):
            raise ValueError
        date.fromisoformat(raw_date)
    except ValueError:
        problems.append("date must be YYYY-MM-DD")

    if item.get("type") not in EVENT_TYPES:
        problems.append(f"type must be one of {', '.join(sorted(EVENT_TYPES))}")

    seizoen = item.get("seizoen")
    if seizoen is not None and (
        not isinstance(seizoen, str) or not SEASON_PATTERN.match(seizoen)
    ):
        problems.append("seizoen must look like 25/26")

    # Images are resized in the browser and stored inline as a data URL; the
    # collection's max item size keeps them small.
    image = item.get("image")
    if image is not None and (
        not isinstance(image, str)
        or not (image.startswith("data:image/") or is_web_url(image))
    ):
        problems.append("image must be an image data URL or a web URL")

    links = item.get("links", [])
    if not isinstance(links, list) or len(links) > MAX_LINKS:
        problems.append(f"links must be a list of at most {MAX_LINKS} links")
    else:
        for link in links:
            if (
                not isinstance(link, dict)
                or set(link) != {"label", "url"}
                or not isinstance(link["label"], str)
                or not link["label"].strip()
                or len(link["label"]) > MAX_LINK_LABEL_LENGTH
                or not isinstance(link["url"], str)
                or not is_web_url(link["url"])
            ):
                problems.append("each link needs a short label and a web url")
                break

    return problems
