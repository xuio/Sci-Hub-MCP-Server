import logging
import os
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Tuple
from urllib.parse import quote, unquote, urljoin, urlparse

import requests
import urllib3
from bs4 import BeautifulSoup
from scihub import SciHub

try:
    from curl_cffi import requests as curl_requests
except Exception:  # pragma: no cover - optional dependency
    curl_requests = None

# Disable HTTPS certificate verification warnings because some mirrors use broken TLS chains.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_SCIHUB_BASE_URL = "https://sci-hub.ren"
DEFAULT_TIMEOUT_SECONDS = 20.0
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

DOI_PATTERN = re.compile(r"(10\.\d{4,9}/[-._;()/:A-Za-z0-9]+)", re.IGNORECASE)
YEAR_PATTERN = re.compile(r"\b(19|20)\d{2}\b")
ARXIV_NAMESPACES = {
    "atom": "http://www.w3.org/2005/Atom",
    "arxiv": "http://arxiv.org/schemas/atom",
}

LOGGER = logging.getLogger(__name__)
logging.getLogger("scihub").setLevel(logging.ERROR)


def _get_http_client_name() -> str:
    requested = os.getenv("SCIHUB_HTTP_CLIENT", "").strip().lower()
    if requested in {"curl_cffi", "requests"}:
        if requested == "curl_cffi" and curl_requests is None:
            LOGGER.warning(
                "SCIHUB_HTTP_CLIENT=curl_cffi requested but curl_cffi is not installed. Falling back to requests."
            )
            return "requests"
        return requested

    if requested:
        LOGGER.warning("Unknown SCIHUB_HTTP_CLIENT=%r. Falling back to auto selection.", requested)
    return "curl_cffi" if curl_requests is not None else "requests"


def _normalize_mirror(value: str) -> str:
    """Convert mirror URL/host input to host format."""
    raw = (value or "").strip()
    if not raw:
        return ""

    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    host = (parsed.netloc or parsed.path or "").strip().strip("/")
    if not host:
        return ""

    return host.split("/")[0]


def _parse_bool_env(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def _provider_enabled(provider_name: str, default: bool = True) -> bool:
    env_name = f"SCIHUB_ENABLE_{provider_name.upper()}"
    return _parse_bool_env(env_name, default)


def _get_timeout() -> float:
    raw = os.getenv("SCIHUB_TIMEOUT_SECONDS")
    if not raw:
        return DEFAULT_TIMEOUT_SECONDS
    try:
        timeout = float(raw)
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        return timeout
    except ValueError:
        LOGGER.warning("Invalid SCIHUB_TIMEOUT_SECONDS=%r. Falling back to %.1f", raw, DEFAULT_TIMEOUT_SECONDS)
        return DEFAULT_TIMEOUT_SECONDS


def _api_headers() -> Dict[str, str]:
    return {
        "User-Agent": os.getenv("SCIHUB_USER_AGENT", DEFAULT_USER_AGENT),
        "Accept": "application/json,text/plain,*/*",
    }


def _build_session():
    client_name = _get_http_client_name()
    if client_name == "curl_cffi":
        session = curl_requests.Session(impersonate=os.getenv("SCIHUB_IMPERSONATE", "chrome124"))
    else:
        session = requests.Session()

    session.headers.update(
        {
            "User-Agent": os.getenv("SCIHUB_USER_AGENT", DEFAULT_USER_AGENT),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": os.getenv("SCIHUB_REFERER", "https://sci-hub.ren/"),
        }
    )

    cookie_header = os.getenv("SCIHUB_COOKIE", "").strip()
    if cookie_header:
        session.headers["Cookie"] = cookie_header

    proxy = os.getenv("SCIHUB_PROXY", "").strip()
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}

    return session


def _sanitize_filename(name: str) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", name or "paper.pdf").strip("._")
    if not cleaned:
        cleaned = "paper.pdf"
    if not cleaned.lower().endswith(".pdf"):
        cleaned = f"{cleaned}.pdf"
    return cleaned


def _default_download_dir() -> str:
    configured = os.getenv("SCIHUB_DOWNLOAD_DIR", "").strip()
    if configured:
        return os.path.abspath(os.path.expanduser(configured))
    return os.path.join(os.path.expanduser("~"), "Downloads")


def _looks_like_vm_path(path: str) -> bool:
    normalized = path.replace("\\", "/")
    return normalized.startswith("/home/claude/") or normalized.startswith("/sessions/")


def _prepare_output_path(output_path: str, pdf_url: str) -> str:
    requested = (output_path or "").strip()
    parsed = urlparse(pdf_url or "")
    fallback_name = _sanitize_filename(os.path.basename(parsed.path) or "paper.pdf")

    if not requested:
        target = os.path.join(_default_download_dir(), fallback_name)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        return target

    if _looks_like_vm_path(requested):
        target = os.path.join(_default_download_dir(), _sanitize_filename(os.path.basename(requested)))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        return target

    target = os.path.abspath(os.path.expanduser(requested))
    parent = os.path.dirname(target) or "."
    try:
        os.makedirs(parent, exist_ok=True)
        test_path = os.path.join(parent, f".__scihub_write_test_{os.getpid()}")
        with open(test_path, "wb"):
            pass
        os.remove(test_path)
        return target
    except OSError:
        fallback = os.path.join(_default_download_dir(), _sanitize_filename(os.path.basename(target) or fallback_name))
        os.makedirs(os.path.dirname(fallback), exist_ok=True)
        return fallback


def _get_configured_mirrors() -> List[str]:
    """Build prioritized mirror list."""
    primary = _normalize_mirror(os.getenv("SCIHUB_BASE_URL", DEFAULT_SCIHUB_BASE_URL))
    if not primary:
        primary = _normalize_mirror(DEFAULT_SCIHUB_BASE_URL)

    mirrors = [primary]

    extra_raw = os.getenv("SCIHUB_BASE_URLS", "")
    for candidate in [item.strip() for item in extra_raw.split(",") if item.strip()]:
        normalized = _normalize_mirror(candidate)
        if normalized and normalized not in mirrors:
            mirrors.append(normalized)

    include_defaults = _parse_bool_env("SCIHUB_INCLUDE_DEFAULT_MIRRORS", False)
    if include_defaults:
        for candidate in SciHub().available_base_url_list:
            if candidate not in mirrors:
                mirrors.append(candidate)

    return mirrors


def _is_cloudflare_challenge(response) -> bool:
    text = response.text[:20000] if response.text else ""
    if response.headers.get("cf-mitigated", "").lower() == "challenge":
        return True
    if response.status_code in {403, 429, 503} and (
        "Just a moment..." in text
        or "cf-browser-verification" in text
        or "Attention Required!" in text
        or "challenge-platform" in text
    ):
        return True
    return False


def _normalize_pdf_candidate(candidate: str, page_url: str) -> str:
    if not candidate:
        return ""
    src = candidate.strip()
    if src.startswith("//"):
        src = f"https:{src}"
    elif src.startswith("/"):
        src = urljoin(page_url, src)
    elif src.startswith("./") or src.startswith("../"):
        src = urljoin(page_url, src)

    if src.startswith("http://") or src.startswith("https://"):
        return src
    return ""


def _extract_doi_from_text(value: str) -> str:
    text = unquote(value or "")
    match = DOI_PATTERN.search(text)
    if match:
        return match.group(1).rstrip(".,;)")
    return ""


def _normalize_doi(value: str) -> str:
    doi = _extract_doi_from_text(value or "")
    return doi.lower().strip()


def _looks_like_doi(value: str) -> bool:
    raw = (value or "").strip()
    if not raw:
        return False
    return bool(_extract_doi_from_text(raw))


def _extract_doi_from_url(value: str) -> str:
    parsed = urlparse(value or "")
    if parsed.netloc and parsed.netloc.lower() == "doi.org" and parsed.path:
        return _extract_doi_from_text(parsed.path)

    if parsed.path:
        path = unquote(parsed.path).strip("/")
        if path.lower().startswith("pdf/"):
            path = path[4:]
        if path.lower().endswith(".pdf"):
            path = path[:-4]
        doi = _extract_doi_from_text(path)
        if doi:
            return doi

    return _extract_doi_from_text(value or "")


def _extract_pdf_url_from_html(html: str, page_url: str) -> str:
    soup = BeautifulSoup(html or "", "html.parser")
    candidates: List[str] = []

    tag_attr_pairs = [
        ("iframe", "src"),
        ("embed", "src"),
        ("object", "data"),
        ("meta", "content"),
        ("a", "href"),
    ]

    for tag, attr in tag_attr_pairs:
        for element in soup.find_all(tag):
            if tag == "meta":
                name = (element.get("name") or "").lower()
                if name != "citation_pdf_url":
                    continue
            value = element.get(attr)
            if value:
                candidates.append(value)

    # Fallback regex for direct PDF links in inline scripts/content.
    for match in re.findall(r"https?://[^\\\"'\\s<>]+\\.pdf(?:\\?[^\\\"'\\s<>]*)?", html or "", re.IGNORECASE):
        candidates.append(match)

    for candidate in candidates:
        normalized = _normalize_pdf_candidate(candidate, page_url)
        if normalized:
            return normalized

    return ""


def _extract_year(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    match = YEAR_PATTERN.search(text)
    if match:
        return match.group(0)
    return ""


def _is_probably_pdf_response(response) -> bool:
    content_type = (response.headers.get("content-type") or "").lower()
    if "application/pdf" in content_type:
        return True
    if response.status_code >= 400:
        return False

    try:
        first_chunk = next(response.iter_content(chunk_size=16), b"")
    except Exception:
        return False
    return first_chunk.startswith(b"%PDF")


def _validate_pdf_candidate(session, pdf_url: str, timeout: float) -> Tuple[str, str]:
    try:
        response = session.get(pdf_url, timeout=timeout, verify=False, stream=True, allow_redirects=True)
    except Exception as exc:
        return "", f"candidate_request_error:{type(exc).__name__}"

    if _is_cloudflare_challenge(response):
        return "", "candidate_cloudflare_challenge"
    if _is_probably_pdf_response(response):
        return response.url or pdf_url, "ok"
    return "", f"candidate_not_pdf_status_{response.status_code}"


def _download_candidate_to_file(session, pdf_url: str, output_path: str, timeout: float) -> Tuple[bool, str]:
    response = session.get(pdf_url, timeout=timeout, verify=False, stream=True, allow_redirects=True)
    if _is_cloudflare_challenge(response):
        return False, "cloudflare_challenge"
    if response.status_code >= 400:
        return False, f"http_{response.status_code}"

    first_chunk = b""
    with open(output_path, "wb") as handle:
        for chunk in response.iter_content(chunk_size=8192):
            if not chunk:
                continue
            if not first_chunk:
                first_chunk = chunk
            handle.write(chunk)

    if first_chunk and not first_chunk.startswith(b"%PDF"):
        try:
            os.remove(output_path)
        except OSError:
            pass
        return False, "not_pdf_content"
    return True, "ok"


def _try_identifier_with_mirror(session, mirror_host: str, identifier: str, timeout: float) -> Tuple[str, str]:
    endpoints = [
        ("get", f"https://{mirror_host}/{identifier}", None),
        ("post", f"https://{mirror_host}/", {"request": identifier}),
    ]

    last_reason = "no_response"
    for method, url, payload in endpoints:
        try:
            if method == "get":
                response = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
            else:
                response = session.post(url, data=payload, timeout=timeout, verify=False, allow_redirects=True)
        except Exception as exc:
            last_reason = f"request_error:{type(exc).__name__}"
            continue

        if _is_cloudflare_challenge(response):
            last_reason = "cloudflare_challenge"
            continue

        content_type = (response.headers.get("content-type") or "").lower()
        if "application/pdf" in content_type:
            validated_url, reason = _validate_pdf_candidate(session, response.url, timeout)
            if validated_url:
                return validated_url, "ok"
            last_reason = reason
            continue

        pdf_url = _extract_pdf_url_from_html(response.text, response.url)
        if pdf_url:
            validated_url, reason = _validate_pdf_candidate(session, pdf_url, timeout)
            if validated_url:
                return validated_url, "ok"
            last_reason = reason
            continue

        last_reason = f"no_pdf_marker_status_{response.status_code}"

    return "", last_reason


def _resolve_pdf_url(identifier: str) -> Tuple[str, str, List[str]]:
    mirrors = _get_configured_mirrors()
    timeout = _get_timeout()
    session = _build_session()
    errors: List[str] = []

    for mirror in mirrors:
        pdf_url, reason = _try_identifier_with_mirror(session, mirror, identifier, timeout)
        if pdf_url:
            return pdf_url, mirror, errors
        errors.append(f"{mirror}:{reason}")

    return "", "", errors


def _split_author_name(given: str, family: str) -> str:
    full = " ".join(part for part in [given.strip(), family.strip()] if part).strip()
    return full


def _dedupe_authors(authors: List[str]) -> str:
    deduped: List[str] = []
    for author in authors:
        clean = (author or "").strip()
        if clean and clean not in deduped:
            deduped.append(clean)
    return ", ".join(deduped)


def _get_crossref_metadata(doi: str) -> Dict[str, str]:
    try:
        response = requests.get(
            f"https://api.crossref.org/works/{quote(doi, safe='')}",
            timeout=15,
            headers=_api_headers(),
        )
        if response.status_code != 200:
            return {}

        payload = response.json().get("message", {})
        title = payload.get("title", [""])[0] if payload.get("title") else ""

        year = ""
        for field in ("published-print", "published-online", "issued"):
            date_parts = payload.get(field, {}).get("date-parts", [])
            if date_parts and date_parts[0]:
                year = str(date_parts[0][0])
                break

        authors = []
        for item in payload.get("author", []):
            full = _split_author_name(item.get("given") or "", item.get("family") or "")
            if full:
                authors.append(full)

        return {
            "title": title,
            "author": _dedupe_authors(authors),
            "year": year,
        }
    except Exception as exc:
        LOGGER.debug("CrossRef metadata lookup failed for DOI %s: %s", doi, exc)
        return {}


def _build_candidate(
    provider: str,
    pdf_url: str = "",
    landing_url: str = "",
    doi: str = "",
    title: str = "",
    author: str = "",
    year: str = "",
    direct_pdf: bool = False,
) -> Dict[str, Any]:
    return {
        "provider": provider,
        "pdf_url": (pdf_url or "").strip(),
        "landing_url": (landing_url or "").strip(),
        "doi": (doi or "").strip(),
        "title": (title or "").strip(),
        "author": (author or "").strip(),
        "year": (year or "").strip(),
        "direct_pdf": bool(direct_pdf),
    }


def _candidate_primary_url(candidate: Dict[str, Any]) -> str:
    return (candidate.get("pdf_url") or "").strip() or (candidate.get("landing_url") or "").strip()


def _dedupe_candidates(candidates: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for candidate in candidates:
        key = (
            (candidate.get("provider") or "").strip().lower(),
            _candidate_primary_url(candidate).lower(),
            (candidate.get("doi") or "").strip().lower(),
        )
        if key in seen:
            continue
        if not key[1]:
            continue
        seen.add(key)
        deduped.append(candidate)
    return deduped


def _merge_metadata(primary: Dict[str, str], fallback: Dict[str, str]) -> Dict[str, str]:
    merged = {
        "title": (primary.get("title") or "").strip(),
        "author": (primary.get("author") or "").strip(),
        "year": (primary.get("year") or "").strip(),
    }
    for key in ("title", "author", "year"):
        if not merged.get(key):
            merged[key] = (fallback.get(key) or "").strip()
    return merged


def _choose_best_candidate(candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not candidates:
        return {}

    provider_order = {
        "unpaywall": 0,
        "openalex": 1,
        "arxiv": 2,
        "biorxiv": 3,
        "medrxiv": 4,
        "google_scholar": 5,
    }

    def sort_key(item: Dict[str, Any]):
        provider = (item.get("provider") or "").lower()
        return (
            0 if item.get("direct_pdf") else 1,
            provider_order.get(provider, 99),
            0 if item.get("doi") else 1,
        )

    ranked = sorted(candidates, key=sort_key)
    return ranked[0]


def _result_from_candidate(doi: str, candidate: Dict[str, Any], metadata: Dict[str, str]) -> Dict[str, Any]:
    effective_metadata = _merge_metadata(candidate, metadata)
    result = {
        "doi": doi,
        "title": effective_metadata.get("title", ""),
        "author": effective_metadata.get("author", ""),
        "year": effective_metadata.get("year", ""),
        "pdf_url": _candidate_primary_url(candidate),
        "status": "success",
        "source": candidate.get("provider", ""),
        "direct_pdf": bool(candidate.get("direct_pdf")),
    }
    if candidate.get("landing_url"):
        result["landing_url"] = candidate.get("landing_url")
    return result


def _unpaywall_email() -> str:
    return (os.getenv("UNPAYWALL_EMAIL") or os.getenv("SCIHUB_UNPAYWALL_EMAIL") or "").strip()


def _get_unpaywall_candidates(doi: str) -> Tuple[List[Dict[str, Any]], str]:
    if not _provider_enabled("UNPAYWALL", True):
        return [], "disabled"

    email = _unpaywall_email()
    if not email:
        return [], "email_not_configured"

    try:
        response = requests.get(
            f"https://api.unpaywall.org/v2/{quote(doi, safe='')}",
            params={"email": email},
            timeout=15,
            headers=_api_headers(),
        )
        if response.status_code != 200:
            return [], f"http_{response.status_code}"

        payload = response.json()
        title = (payload.get("title") or "").strip()
        year = _extract_year(payload.get("year"))

        authors = []
        for item in payload.get("z_authors", []):
            if isinstance(item, dict):
                full = _split_author_name(item.get("given") or "", item.get("family") or "")
            else:
                full = str(item).strip()
            if full:
                authors.append(full)
        author = _dedupe_authors(authors)

        candidates: List[Dict[str, Any]] = []

        def add_location(location: Dict[str, Any]) -> None:
            if not isinstance(location, dict):
                return
            pdf = (location.get("url_for_pdf") or "").strip()
            landing = (location.get("url") or "").strip()
            if not pdf and not landing:
                return
            candidates.append(
                _build_candidate(
                    provider="unpaywall",
                    pdf_url=pdf or landing,
                    landing_url=landing,
                    doi=doi,
                    title=title,
                    author=author,
                    year=year,
                    direct_pdf=bool(pdf),
                )
            )

        add_location(payload.get("best_oa_location") or {})
        for location in payload.get("oa_locations", []):
            add_location(location)

        return _dedupe_candidates(candidates), "ok"
    except Exception as exc:
        return [], f"request_error:{type(exc).__name__}:{exc}"


def _openalex_work_to_candidates(work: Dict[str, Any]) -> List[Dict[str, Any]]:
    if not isinstance(work, dict):
        return []

    doi = _extract_doi_from_text(work.get("doi") or "")
    title = (work.get("display_name") or "").strip()
    year = _extract_year(work.get("publication_year"))

    authors = []
    for auth in work.get("authorships", []):
        author_obj = auth.get("author", {}) if isinstance(auth, dict) else {}
        display_name = (author_obj.get("display_name") or "").strip()
        if display_name:
            authors.append(display_name)
    author = _dedupe_authors(authors)

    candidates: List[Dict[str, Any]] = []

    def add_candidate(pdf: str, landing: str, direct_pdf: bool) -> None:
        pdf = (pdf or "").strip()
        landing = (landing or "").strip()
        if not pdf and not landing:
            return
        candidates.append(
            _build_candidate(
                provider="openalex",
                pdf_url=pdf or landing,
                landing_url=landing,
                doi=doi,
                title=title,
                author=author,
                year=year,
                direct_pdf=direct_pdf,
            )
        )

    best_oa = work.get("best_oa_location") or {}
    if isinstance(best_oa, dict):
        add_candidate(best_oa.get("pdf_url") or "", best_oa.get("landing_page_url") or "", bool(best_oa.get("pdf_url")))

    for location in work.get("locations", []):
        if not isinstance(location, dict):
            continue
        add_candidate(location.get("pdf_url") or "", location.get("landing_page_url") or "", bool(location.get("pdf_url")))

    open_access = work.get("open_access") or {}
    if isinstance(open_access, dict):
        oa_url = (open_access.get("oa_url") or "").strip()
        if oa_url:
            add_candidate("", oa_url, False)

    return _dedupe_candidates(candidates)


def _get_openalex_candidates_by_doi(doi: str) -> Tuple[List[Dict[str, Any]], str]:
    if not _provider_enabled("OPENALEX", True):
        return [], "disabled"

    try:
        requested_doi = _normalize_doi(doi)
        response = requests.get(
            f"https://api.openalex.org/works/https://doi.org/{quote(doi, safe='')}",
            timeout=15,
            headers=_api_headers(),
        )
        if response.status_code != 200:
            return [], f"http_{response.status_code}"

        work = response.json()
        returned_doi = _normalize_doi(work.get("doi") or "")
        if requested_doi and returned_doi and returned_doi != requested_doi:
            return [], f"doi_mismatch:{returned_doi}"

        candidates = _openalex_work_to_candidates(work)
        if requested_doi:
            filtered = []
            for candidate in candidates:
                candidate_doi = _normalize_doi(candidate.get("doi") or "")
                if not candidate_doi or candidate_doi == requested_doi:
                    filtered.append(candidate)
            candidates = filtered
        return candidates, "ok" if candidates else "no_oa_location"
    except Exception as exc:
        return [], f"request_error:{type(exc).__name__}:{exc}"


def _parse_arxiv_feed(feed_xml: str) -> List[Dict[str, str]]:
    entries: List[Dict[str, str]] = []
    if not (feed_xml or "").strip():
        return entries

    try:
        root = ET.fromstring(feed_xml)
    except ET.ParseError:
        return entries

    for entry in root.findall("atom:entry", ARXIV_NAMESPACES):
        entry_id = (entry.findtext("atom:id", default="", namespaces=ARXIV_NAMESPACES) or "").strip()
        title = " ".join((entry.findtext("atom:title", default="", namespaces=ARXIV_NAMESPACES) or "").split())
        published = (entry.findtext("atom:published", default="", namespaces=ARXIV_NAMESPACES) or "").strip()
        year = _extract_year(published)
        doi = (entry.findtext("arxiv:doi", default="", namespaces=ARXIV_NAMESPACES) or "").strip()

        authors = []
        for author_el in entry.findall("atom:author", ARXIV_NAMESPACES):
            name = (author_el.findtext("atom:name", default="", namespaces=ARXIV_NAMESPACES) or "").strip()
            if name:
                authors.append(name)

        pdf_url = ""
        for link in entry.findall("atom:link", ARXIV_NAMESPACES):
            href = (link.attrib.get("href") or "").strip()
            title_attr = (link.attrib.get("title") or "").strip().lower()
            content_type = (link.attrib.get("type") or "").strip().lower()
            if title_attr == "pdf" or content_type == "application/pdf" or "/pdf/" in href:
                pdf_url = href
                break

        if not pdf_url and "/abs/" in entry_id:
            pdf_url = entry_id.replace("/abs/", "/pdf/")

        entries.append(
            {
                "id": entry_id,
                "title": title,
                "author": _dedupe_authors(authors),
                "year": year,
                "doi": doi,
                "pdf_url": pdf_url,
            }
        )

    return entries


def _search_arxiv(query: str, max_results: int = 5, search_field: str = "all") -> Tuple[List[Dict[str, Any]], str]:
    if not _provider_enabled("ARXIV", True):
        return [], "disabled"

    sanitized_query = (query or "").strip()
    if not sanitized_query:
        return [], "empty_query"

    max_results = max(1, min(int(max_results), 20))
    query_term = sanitized_query
    if " " in query_term and "\"" not in query_term:
        query_term = f"\"{query_term}\""
    search_expr = f"{search_field}:{query_term}" if search_field else query_term

    try:
        response = requests.get(
            "https://export.arxiv.org/api/query",
            params={
                "search_query": search_expr,
                "start": 0,
                "max_results": max_results,
                "sortBy": "relevance",
                "sortOrder": "descending",
            },
            timeout=20,
            headers=_api_headers(),
        )
        if response.status_code != 200:
            return [], f"http_{response.status_code}"

        parsed = _parse_arxiv_feed(response.text)
        candidates = [
            _build_candidate(
                provider="arxiv",
                pdf_url=item.get("pdf_url") or item.get("id") or "",
                landing_url=item.get("id") or "",
                doi=item.get("doi") or "",
                title=item.get("title") or "",
                author=item.get("author") or "",
                year=item.get("year") or "",
                direct_pdf=bool(item.get("pdf_url")),
            )
            for item in parsed
        ]
        return _dedupe_candidates(candidates), "ok" if candidates else "no_results"
    except Exception as exc:
        return [], f"request_error:{type(exc).__name__}:{exc}"


def _arxiv_id_from_doi(doi: str) -> str:
    text = (doi or "").strip()
    match = re.match(r"^10\.48550/arxiv\.(.+)$", text, flags=re.IGNORECASE)
    if not match:
        return ""
    arxiv_id = match.group(1).strip()
    return arxiv_id


def _arxiv_candidate_from_id(arxiv_id: str, doi: str = "", title: str = "") -> Dict[str, Any]:
    normalized_id = (arxiv_id or "").strip()
    if not normalized_id:
        return {}

    abs_url = f"https://arxiv.org/abs/{normalized_id}"
    pdf_url = f"https://arxiv.org/pdf/{normalized_id}.pdf"
    return _build_candidate(
        provider="arxiv",
        pdf_url=pdf_url,
        landing_url=abs_url,
        doi=(doi or "").strip(),
        title=(title or "").strip(),
        author="",
        year="",
        direct_pdf=True,
    )


def _get_rxiv_candidates_by_doi(doi: str) -> Tuple[List[Dict[str, Any]], str]:
    if not _provider_enabled("RXIV", True):
        return [], "disabled"

    candidates: List[Dict[str, Any]] = []
    errors: List[str] = []

    for server in ("biorxiv", "medrxiv"):
        try:
            response = requests.get(
                f"https://api.biorxiv.org/details/{server}/{quote(doi, safe='/')}",
                timeout=15,
                headers=_api_headers(),
            )
            if response.status_code != 200:
                errors.append(f"{server}:http_{response.status_code}")
                continue

            payload = response.json()
            collection = payload.get("collection", [])
            if not collection:
                errors.append(f"{server}:no_results")
                continue

            for item in collection:
                item_doi = (item.get("doi") or doi).strip()
                version = (item.get("version") or "").strip()
                title = (item.get("title") or "").strip()
                author = (item.get("authors") or "").strip()
                year = _extract_year(item.get("date") or "")

                base_url = f"https://www.{server}.org/content/{item_doi}"
                if version:
                    base_url = f"{base_url}v{version}"
                pdf_url = f"{base_url}.full.pdf"

                candidates.append(
                    _build_candidate(
                        provider=server,
                        pdf_url=pdf_url,
                        landing_url=base_url,
                        doi=item_doi,
                        title=title,
                        author=author,
                        year=year,
                        direct_pdf=True,
                    )
                )
        except Exception as exc:
            errors.append(f"{server}:request_error:{type(exc).__name__}:{exc}")

    deduped = _dedupe_candidates(candidates)
    if deduped:
        return deduped, "ok"

    if not errors:
        return [], "no_results"
    return [], ";".join(errors[:6])


def _search_google_scholar(query: str, max_results: int = 5) -> Tuple[List[Dict[str, Any]], str]:
    if not _provider_enabled("GOOGLE_SCHOLAR", True):
        return [], "disabled"

    sanitized_query = (query or "").strip()
    if not sanitized_query:
        return [], "empty_query"

    max_results = max(1, min(int(max_results), 10))

    base_url = (os.getenv("SCHOLAR_BASE_URL") or "https://scholar.google.com/scholar").strip()
    session = _build_session()

    try:
        response = session.get(
            base_url,
            params={"q": sanitized_query, "hl": "en"},
            timeout=min(_get_timeout(), 20),
            verify=False,
            allow_redirects=True,
        )
    except Exception as exc:
        return [], f"request_error:{type(exc).__name__}:{exc}"

    if response.status_code != 200:
        return [], f"http_{response.status_code}"

    body = response.text or ""
    lower_body = body.lower()
    if "unusual traffic from your computer network" in lower_body or "sorry" in lower_body and "not a robot" in lower_body:
        return [], "blocked_or_rate_limited"

    soup = BeautifulSoup(body, "html.parser")
    blocks = soup.select("div.gs_r")
    if not blocks:
        blocks = soup.select("div.gs_ri")

    candidates: List[Dict[str, Any]] = []
    for block in blocks:
        title_node = block.select_one("h3.gs_rt")
        if title_node is None:
            continue

        anchor = title_node.select_one("a")
        title_text = " ".join(title_node.get_text(" ", strip=True).split())
        landing_url = (anchor.get("href") or "").strip() if anchor else ""

        meta_text = ""
        meta_node = block.select_one("div.gs_a")
        if meta_node:
            meta_text = " ".join(meta_node.get_text(" ", strip=True).split())

        authors = ""
        if meta_text:
            authors = meta_text.split("-")[0].strip()

        year = _extract_year(meta_text)

        pdf_url = ""
        pdf_node = block.select_one("div.gs_or_ggsm a")
        if pdf_node and pdf_node.get("href"):
            pdf_url = pdf_node.get("href").strip()

        snippet = ""
        snippet_node = block.select_one("div.gs_rs")
        if snippet_node:
            snippet = snippet_node.get_text(" ", strip=True)

        detected_doi = _extract_doi_from_text(landing_url) or _extract_doi_from_text(f"{title_text} {snippet}")

        candidates.append(
            _build_candidate(
                provider="google_scholar",
                pdf_url=pdf_url or landing_url,
                landing_url=landing_url,
                doi=detected_doi,
                title=title_text,
                author=authors,
                year=year,
                direct_pdf=bool(pdf_url and ".pdf" in pdf_url.lower()),
            )
        )

        if len(candidates) >= max_results:
            break

    return _dedupe_candidates(candidates), "ok" if candidates else "no_results"


def _search_openalex_by_query(query: str, max_results: int = 5) -> Tuple[List[Dict[str, Any]], str]:
    if not _provider_enabled("OPENALEX", True):
        return [], "disabled"

    sanitized_query = (query or "").strip()
    if not sanitized_query:
        return [], "empty_query"

    max_results = max(1, min(int(max_results), 20))

    try:
        response = requests.get(
            "https://api.openalex.org/works",
            params={"search": sanitized_query, "per-page": max_results},
            timeout=20,
            headers=_api_headers(),
        )
        if response.status_code != 200:
            return [], f"http_{response.status_code}"

        payload = response.json()
        candidates: List[Dict[str, Any]] = []
        for work in payload.get("results", []):
            candidates.extend(_openalex_work_to_candidates(work))
        return _dedupe_candidates(candidates), "ok" if candidates else "no_results"
    except Exception as exc:
        return [], f"request_error:{type(exc).__name__}:{exc}"


def _collect_fallback_candidates_for_doi(doi: str, title_hint: str = "") -> Tuple[List[Dict[str, Any]], List[str]]:
    candidates: List[Dict[str, Any]] = []
    errors: List[str] = []

    provider_calls = [
        ("unpaywall", lambda: _get_unpaywall_candidates(doi)),
        ("openalex", lambda: _get_openalex_candidates_by_doi(doi)),
        ("arxiv", lambda: _search_arxiv(doi, max_results=3, search_field="doi")),
        ("rxiv", lambda: _get_rxiv_candidates_by_doi(doi)),
    ]

    requested_doi = _normalize_doi(doi)

    def keep_for_requested_doi(item: Dict[str, Any]) -> bool:
        candidate_doi = _normalize_doi(item.get("doi") or "")
        if not candidate_doi:
            return False
        return candidate_doi == requested_doi

    for provider, callback in provider_calls:
        provider_candidates, reason = callback()
        if provider_candidates:
            candidates.extend([item for item in provider_candidates if keep_for_requested_doi(item)])
        elif reason and reason not in {"disabled", "email_not_configured"}:
            errors.append(f"{provider}:{reason}")

    # Special handling for DataCite arXiv DOI format (10.48550/arXiv.<id>).
    if _provider_enabled("ARXIV", True):
        arxiv_id = _arxiv_id_from_doi(doi)
        if arxiv_id:
            direct = _arxiv_candidate_from_id(arxiv_id, doi=doi, title=title_hint)
            if direct:
                candidates.append(direct)

    scholar_query = doi or title_hint
    if scholar_query:
        scholar_candidates, reason = _search_google_scholar(scholar_query, max_results=3)
        if scholar_candidates:
            candidates.extend([item for item in scholar_candidates if keep_for_requested_doi(item)])
        elif reason and reason not in {"disabled"}:
            errors.append(f"google_scholar:{reason}")

    return _dedupe_candidates(candidates), errors


def create_scihub_instance() -> SciHub:
    """Create a SciHub instance with configured mirrors."""
    sh = SciHub()
    sh.timeout = int(max(_get_timeout(), 1))
    sh.available_base_url_list = _get_configured_mirrors()
    sh.current_base_url_index = 0
    return sh


def search_paper_by_doi(doi: str) -> Dict[str, Any]:
    """Search by DOI using Sci-Hub first and OA fallback providers when needed."""
    normalized_doi = _extract_doi_from_text(doi) or (doi or "").strip()
    metadata = _get_crossref_metadata(normalized_doi) if normalized_doi else {}

    if not normalized_doi:
        return {
            "doi": doi,
            "status": "not_found",
            "error": "Invalid DOI format.",
        }

    pdf_url, mirror, errors = _resolve_pdf_url(normalized_doi)
    if pdf_url:
        return {
            "doi": normalized_doi,
            "pdf_url": pdf_url,
            "status": "success",
            "source": "sci_hub",
            "mirror": mirror,
            "title": metadata.get("title", ""),
            "author": metadata.get("author", ""),
            "year": metadata.get("year", ""),
            "direct_pdf": True,
        }

    fallback_candidates, fallback_errors = _collect_fallback_candidates_for_doi(
        normalized_doi, title_hint=metadata.get("title", "")
    )
    if fallback_candidates:
        chosen = _choose_best_candidate(fallback_candidates)
        result = _result_from_candidate(normalized_doi, chosen, metadata)
        return result

    error_chunks = []
    if errors:
        error_chunks.append("Sci-Hub: " + "; ".join(errors[:6]))
    if fallback_errors:
        error_chunks.append("Fallbacks: " + "; ".join(fallback_errors[:6]))

    detail = " | ".join(error_chunks) if error_chunks else "no_provider_response"

    guidance = [
        "Failed to resolve PDF URL from Sci-Hub and fallback providers.",
        f"Details: {detail}.",
    ]
    if not _unpaywall_email() and _provider_enabled("UNPAYWALL", True):
        guidance.append("Set UNPAYWALL_EMAIL to enable Unpaywall lookups.")
    guidance.append("If Sci-Hub mirrors return Cloudflare challenge pages, set SCIHUB_PROXY or SCIHUB_COOKIE.")

    return {
        "doi": normalized_doi,
        "status": "not_found",
        "error": " ".join(guidance),
    }


def _extract_crossref_items(query: str, rows: int, query_by_title: bool = False) -> List[Dict[str, Any]]:
    try:
        params = {"rows": rows}
        if query_by_title:
            params["query.title"] = query
        else:
            params["query"] = query

        response = requests.get(
            "https://api.crossref.org/works",
            params=params,
            timeout=20,
            headers=_api_headers(),
        )
        if response.status_code != 200:
            return []
        return response.json().get("message", {}).get("items", [])
    except Exception:
        return []


def _crossref_item_to_metadata(item: Dict[str, Any]) -> Dict[str, str]:
    title = ""
    if item.get("title"):
        title = item["title"][0]

    year = ""
    for field in ("published-print", "published-online", "issued"):
        date_parts = item.get(field, {}).get("date-parts", [])
        if date_parts and date_parts[0]:
            year = str(date_parts[0][0])
            break

    authors = []
    for author in item.get("author", []):
        full = _split_author_name(author.get("given") or "", author.get("family") or "")
        if full:
            authors.append(full)

    return {
        "title": title,
        "author": _dedupe_authors(authors),
        "year": year,
    }


def search_paper_by_title(title: str) -> Dict[str, Any]:
    """Search by title using CrossRef DOI discovery and multi-source fallback."""
    query = (title or "").strip()
    if not query:
        return {"title": title, "status": "not_found", "error": "Empty title."}

    # 1) Try a handful of CrossRef DOI candidates first.
    items = _extract_crossref_items(query, rows=5, query_by_title=True)
    seen_dois = set()
    for item in items:
        doi = (item.get("DOI") or "").strip()
        if not doi or doi in seen_dois:
            continue
        seen_dois.add(doi)
        resolved = search_paper_by_doi(doi)
        if resolved.get("status") == "success":
            return resolved

    # 2) OpenAlex query fallback.
    openalex_candidates, _ = _search_openalex_by_query(query, max_results=5)
    for candidate in openalex_candidates:
        doi = (candidate.get("doi") or "").strip()
        if doi and doi not in seen_dois:
            resolved = search_paper_by_doi(doi)
            if resolved.get("status") == "success":
                return resolved
            seen_dois.add(doi)

        if _candidate_primary_url(candidate):
            result = _result_from_candidate(doi, candidate, {"title": query, "author": "", "year": ""})
            if not result.get("doi"):
                result["doi"] = doi
            return result

    # 3) arXiv fallback.
    arxiv_candidates, _ = _search_arxiv(query, max_results=5, search_field="ti")
    for candidate in arxiv_candidates:
        doi = (candidate.get("doi") or "").strip()
        if doi and doi not in seen_dois:
            resolved = search_paper_by_doi(doi)
            if resolved.get("status") == "success":
                return resolved

        if _candidate_primary_url(candidate):
            result = _result_from_candidate(doi, candidate, {"title": query, "author": "", "year": ""})
            if not result.get("doi"):
                result["doi"] = doi
            return result

    # 4) Google Scholar fallback.
    scholar_candidates, _ = _search_google_scholar(query, max_results=5)
    for candidate in scholar_candidates:
        doi = (candidate.get("doi") or "").strip()
        if doi and doi not in seen_dois:
            resolved = search_paper_by_doi(doi)
            if resolved.get("status") == "success":
                return resolved

        if _candidate_primary_url(candidate):
            result = _result_from_candidate(doi, candidate, {"title": query, "author": "", "year": ""})
            if not result.get("doi"):
                result["doi"] = doi
            return result

    return {
        "title": title,
        "status": "not_found",
    }


def _make_paper_key(doi: str, title: str) -> str:
    normalized_doi = (doi or "").strip().lower()
    if normalized_doi:
        return f"doi:{normalized_doi}"
    normalized_title = re.sub(r"\s+", " ", (title or "").strip().lower())
    return f"title:{normalized_title}"


def _append_keyword_candidate(
    papers: List[Dict[str, Any]], seen_keys: set, candidate: Dict[str, Any], fallback_title: str = ""
) -> None:
    doi = (candidate.get("doi") or "").strip()
    title = (candidate.get("title") or fallback_title or "").strip()
    key = _make_paper_key(doi, title)
    if key in seen_keys:
        return

    entry = {
        "doi": doi,
        "title": title,
        "author": (candidate.get("author") or "").strip(),
        "year": (candidate.get("year") or "").strip(),
        "pdf_url": _candidate_primary_url(candidate),
        "status": "success" if _candidate_primary_url(candidate) else "metadata_only",
        "source": (candidate.get("provider") or "").strip(),
        "direct_pdf": bool(candidate.get("direct_pdf")),
    }
    if candidate.get("landing_url"):
        entry["landing_url"] = candidate.get("landing_url")

    papers.append(entry)
    seen_keys.add(key)


def search_papers_by_keyword(keyword: str, num_results: int = 10) -> List[Dict[str, Any]]:
    """Search by keyword via CrossRef + OA providers with Sci-Hub first for DOI resolution."""
    papers: List[Dict[str, Any]] = []
    seen_keys = set()

    query = (keyword or "").strip()
    if not query:
        return papers

    try:
        fetch_rows = min(max(int(num_results) * 4, int(num_results), 20), 100)
        items = _extract_crossref_items(query, rows=fetch_rows, query_by_title=False)

        for item in items:
            doi = (item.get("DOI") or "").strip()
            metadata = _crossref_item_to_metadata(item)

            if doi:
                resolved = search_paper_by_doi(doi)
                key = _make_paper_key(doi, metadata.get("title", ""))
                if key in seen_keys:
                    continue

                if resolved.get("status") == "success":
                    entry = {
                        "doi": doi,
                        "title": resolved.get("title") or metadata.get("title", ""),
                        "author": resolved.get("author") or metadata.get("author", ""),
                        "year": resolved.get("year") or metadata.get("year", ""),
                        "pdf_url": resolved.get("pdf_url", ""),
                        "status": "success",
                        "source": resolved.get("source", ""),
                        "direct_pdf": bool(resolved.get("direct_pdf", False)),
                    }
                    if resolved.get("landing_url"):
                        entry["landing_url"] = resolved.get("landing_url")
                    if resolved.get("mirror"):
                        entry["mirror"] = resolved.get("mirror")
                else:
                    entry = {
                        "doi": doi,
                        "title": metadata.get("title", ""),
                        "author": metadata.get("author", ""),
                        "year": metadata.get("year", ""),
                        "status": "metadata_only",
                        "source": "crossref",
                    }
                    if resolved.get("error"):
                        entry["error"] = resolved.get("error")

                papers.append(entry)
                seen_keys.add(key)
            else:
                title = metadata.get("title", "")
                key = _make_paper_key("", title)
                if key in seen_keys:
                    continue
                papers.append(
                    {
                        "doi": "",
                        "title": title,
                        "author": metadata.get("author", ""),
                        "year": metadata.get("year", ""),
                        "status": "metadata_only",
                        "source": "crossref",
                    }
                )
                seen_keys.add(key)

            if len(papers) >= num_results:
                return papers[:num_results]

        # Supplement with OpenAlex/arXiv/Google Scholar results when needed.
        remaining = num_results - len(papers)
        if remaining > 0:
            openalex_candidates, _ = _search_openalex_by_query(query, max_results=max(remaining * 2, remaining))
            for candidate in openalex_candidates:
                _append_keyword_candidate(papers, seen_keys, candidate, fallback_title=query)
                if len(papers) >= num_results:
                    return papers[:num_results]

        remaining = num_results - len(papers)
        if remaining > 0:
            arxiv_candidates, _ = _search_arxiv(query, max_results=max(remaining * 2, remaining), search_field="all")
            for candidate in arxiv_candidates:
                _append_keyword_candidate(papers, seen_keys, candidate, fallback_title=query)
                if len(papers) >= num_results:
                    return papers[:num_results]

        remaining = num_results - len(papers)
        if remaining > 0:
            scholar_candidates, _ = _search_google_scholar(query, max_results=min(max(remaining * 2, remaining), 10))
            for candidate in scholar_candidates:
                _append_keyword_candidate(papers, seen_keys, candidate, fallback_title=query)
                if len(papers) >= num_results:
                    return papers[:num_results]

    except Exception as exc:
        LOGGER.debug("Keyword search failed for %r: %s", keyword, exc)

    return papers[:num_results]


def _expand_download_candidates(session, raw_candidate: str, timeout: float) -> List[str]:
    candidate = (raw_candidate or "").strip()
    if not candidate:
        return []

    expanded = [candidate]
    parsed = urlparse(candidate)

    # arXiv abstract page -> PDF
    if parsed.netloc.endswith("arxiv.org") and "/abs/" in parsed.path:
        arxiv_pdf = candidate.replace("/abs/", "/pdf/")
        expanded.append(arxiv_pdf)
        if not arxiv_pdf.lower().endswith(".pdf"):
            expanded.append(f"{arxiv_pdf}.pdf")

    # bioRxiv / medRxiv content page -> full PDF
    if (parsed.netloc.endswith("biorxiv.org") or parsed.netloc.endswith("medrxiv.org")) and ".pdf" not in parsed.path.lower():
        expanded.append(f"{candidate.rstrip('/')}.full.pdf")

    # PubMed Central article page -> canonical PDF path
    if parsed.netloc.endswith("pmc.ncbi.nlm.nih.gov") and "/articles/" in parsed.path and "/pdf/" not in parsed.path:
        expanded.append(f"{candidate.rstrip('/')}/pdf/")

    # Generic landing page extraction
    if parsed.scheme in {"http", "https"} and ".pdf" not in parsed.path.lower():
        try:
            response = session.get(candidate, timeout=timeout, verify=False, allow_redirects=True)
            if response.status_code < 400:
                extracted = _extract_pdf_url_from_html(response.text, response.url)
                if extracted:
                    expanded.append(extracted)
        except Exception:
            pass

    # Deduplicate while preserving order.
    deduped: List[str] = []
    for item in expanded:
        clean = (item or "").strip()
        if clean and clean not in deduped:
            deduped.append(clean)
    return deduped


def download_paper(pdf_url: str, output_path: str) -> Dict[str, Any]:
    """Download PDF from direct URL, landing URL, or DOI using provider fallbacks."""
    session = _build_session()
    timeout = _get_timeout()

    raw_input = (pdf_url or "").strip()
    resolved_output_path = _prepare_output_path(output_path, raw_input)
    candidates: List[str] = []

    # Support DOI as input for download.
    if raw_input and _looks_like_doi(raw_input) and not urlparse(raw_input).scheme:
        resolved = search_paper_by_doi(raw_input)
        if resolved.get("pdf_url"):
            candidates.append(resolved.get("pdf_url"))
        if resolved.get("landing_url"):
            candidates.append(resolved.get("landing_url"))

    if raw_input:
        candidates.append(raw_input)
        if "#" in raw_input:
            candidates.append(raw_input.split("#", 1)[0])

    doi = _extract_doi_from_url(raw_input)
    if doi:
        refreshed = search_paper_by_doi(doi)
        refreshed_url = refreshed.get("pdf_url", "")
        if refreshed_url:
            candidates.append(refreshed_url)
            candidates.append(refreshed_url.split("#", 1)[0])
        landing = refreshed.get("landing_url", "")
        if landing:
            candidates.append(landing)

    # Sci-Hub page URL fallback for non-PDF page links.
    parsed = urlparse(raw_input)
    if parsed.netloc and "sci-hub" in parsed.netloc.lower() and ".pdf" not in parsed.path.lower():
        identifier = parsed.path.strip("/")
        if identifier:
            resolved, _mirror, _errors = _resolve_pdf_url(unquote(identifier))
            if resolved:
                candidates.append(resolved)
                candidates.append(resolved.split("#", 1)[0])

    # Expand landing page URLs to probable PDF URLs.
    expanded_candidates: List[str] = []
    for candidate in candidates:
        expanded_candidates.extend(_expand_download_candidates(session, candidate, timeout))

    # Deduplicate while preserving order.
    deduped_candidates: List[str] = []
    for candidate in expanded_candidates:
        normalized = (candidate or "").strip()
        if not normalized:
            continue
        if normalized not in deduped_candidates:
            deduped_candidates.append(normalized)

    errors: List[str] = []
    try:
        for candidate in deduped_candidates:
            try:
                ok, reason = _download_candidate_to_file(session, candidate, resolved_output_path, timeout)
                if ok:
                    return {"success": True, "path": resolved_output_path, "source_url": candidate}
                errors.append(f"{candidate}:{reason}")
            except Exception as exc:
                errors.append(f"{candidate}:{type(exc).__name__}")
    except Exception as exc:
        errors.append(f"global:{type(exc).__name__}:{exc}")

    reason = "; ".join(errors[:8]) if errors else "no_candidate_urls"
    return {
        "success": False,
        "path": resolved_output_path,
        "error": (
            "Unable to download PDF from available URLs. "
            f"Details: {reason}. "
            "If host access is restricted in your runtime, download the returned pdf_url from a machine that can reach it."
        ),
    }
