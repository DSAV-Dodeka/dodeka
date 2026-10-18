"""Shape of a card in Het Fotoboek (/leden/fotos), edited by FOCUS.

One card is one event with a cover image and links to its photo albums. The
frontend counterpart is ``PhotoEvent`` in
``dodekafrontend/src/pages/leden/fotos/fotos.tsx``; keep the two in sync.
"""

import re
from datetime import date
from typing import Any

EVENT_TYPES = frozenset({"Wedstrijd", "Gezelligheid", "Training", "Reis", "Overig"})

MAX_TYPES = 3
MAX_NAME_LENGTH = 200
MAX_LINKS = 20
MAX_LINK_LABEL_LENGTH = 50
MAX_URL_LENGTH = 2000

ALLOWED_FIELDS = frozenset(
    {"name", "date", "end_date", "types", "in_progress", "seizoen", "image", "links"}
)
SEASON_PATTERN = re.compile(r"^\d{2}/\d{2}$")


def parse_iso_date(value: Any) -> date | None:
    """The date for a ``YYYY-MM-DD`` string; None if it isn't one."""
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def is_web_url(value: str) -> bool:
    return value.startswith(("https://", "http://")) and len(value) <= MAX_URL_LENGTH


def check_name(item: dict[str, Any]) -> list[str]:
    name = item.get("name")
    if not isinstance(name, str) or not name.strip():
        return ["name is required"]
    if len(name) > MAX_NAME_LENGTH:
        return [f"name is longer than {MAX_NAME_LENGTH} characters"]
    return []


def check_dates(item: dict[str, Any]) -> list[str]:
    """``date`` is the (first) day of the event. ``end_date`` is optional, for
    events spanning several days (e.g. a trainingsweekend), and can't be
    earlier than ``date``."""
    problems: list[str] = []
    start = parse_iso_date(item.get("date"))
    if start is None:
        problems.append("date must be YYYY-MM-DD")
    if "end_date" in item:
        end = parse_iso_date(item["end_date"])
        if end is None:
            problems.append("end_date must be YYYY-MM-DD")
        elif start is not None and end < start:
            problems.append("end_date can't be before date")
    return problems


def check_types(item: dict[str, Any]) -> list[str]:
    """An event can be several kinds at once, e.g. Wedstrijd + Gezelligheid."""
    types = item.get("types")
    if (
        isinstance(types, list)
        and 1 <= len(types) <= MAX_TYPES
        and len(set(types)) == len(types)
        and all(t in EVENT_TYPES for t in types)
    ):
        return []
    return [
        f"types must be 1-{MAX_TYPES} different values from "
        f"{', '.join(sorted(EVENT_TYPES))}"
    ]


def check_flags(item: dict[str, Any]) -> list[str]:
    """``in_progress`` ("Wordt aan gewerkt"): FOCUS is still editing the photos.
    ``seizoen`` overrides the season derived from the date."""
    problems: list[str] = []
    if "in_progress" in item and not isinstance(item["in_progress"], bool):
        problems.append("in_progress must be true or false")
    seizoen = item.get("seizoen")
    if seizoen is not None and (
        not isinstance(seizoen, str) or not SEASON_PATTERN.match(seizoen)
    ):
        problems.append("seizoen must look like 25/26")
    return problems


def check_image(item: dict[str, Any]) -> list[str]:
    """Images are resized in the browser and stored inline as a data URL; the
    collection's max item size keeps them small."""
    image = item.get("image")
    if image is not None and (
        not isinstance(image, str)
        or not (image.startswith("data:image/") or is_web_url(image))
    ):
        return ["image must be an image data URL or a web URL"]
    return []


def is_valid_link(link: Any) -> bool:
    return (
        isinstance(link, dict)
        and set(link) == {"label", "url"}
        and isinstance(link["label"], str)
        and bool(link["label"].strip())
        and len(link["label"]) <= MAX_LINK_LABEL_LENGTH
        and isinstance(link["url"], str)
        and is_web_url(link["url"])
    )


def check_links(item: dict[str, Any]) -> list[str]:
    links = item.get("links", [])
    if not isinstance(links, list) or len(links) > MAX_LINKS:
        return [f"links must be a list of at most {MAX_LINKS} links"]
    if not all(is_valid_link(link) for link in links):
        return ["each link needs a short label and a web url"]
    return []


def validate_foto_card(item: dict[str, Any]) -> list[str]:
    """Return the problems with a card's fields; an empty list means valid.

    ``item`` is the card without the server-owned ``id`` and ``created_at``.
    """
    problems: list[str] = []
    unknown = set(item) - ALLOWED_FIELDS
    if unknown:
        problems.append(f"unknown fields: {', '.join(sorted(unknown))}")
    for check in (
        check_name,
        check_dates,
        check_types,
        check_flags,
        check_image,
        check_links,
    ):
        problems.extend(check(item))
    return problems
