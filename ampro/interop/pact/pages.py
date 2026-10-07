"""Minimal HTML for the consent step (PACT §5.3).

No scripts, no external resources.  Every value is HTML-escaped; scope
descriptions are shown verbatim (escaped, not interpreted).  Responses carry
anti-framing (``frame-ancestors 'none'`` + ``X-Frame-Options: DENY``),
``no-store`` and ``no-referrer`` headers.
"""
from __future__ import annotations

from html import escape
from urllib.parse import urlsplit

from ampro.server.http import HTTPResponse

_STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;"
    "color:#1b1b1b}h1{font-size:1.25rem}label{display:flex;gap:.5rem;align-items:flex-start;"
    "padding:.5rem 0;border-bottom:1px solid #ddd}code{font-size:.8rem;color:#555}"
    "button{margin:1rem .5rem 0 0;padding:.5rem 1rem;font-size:1rem}.muted{color:#555}"
)


def _origin(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return None


def page_headers(form_targets: tuple[str, ...] = ()) -> dict[str, str]:
    sources = " ".join(["'self'", *sorted({o for o in map(_origin, form_targets) if o})])
    return {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Frame-Options": "DENY",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Content-Security-Policy": (
            "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
            f"base-uri 'none'; form-action {sources}; frame-ancestors 'none'"
        ),
    }


def _document(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{escape(title)}</title><style>{_STYLE}</style></head><body>{body}</body></html>"
    )


def html_page(title: str, body: str, status: int = 200,
              form_targets: tuple[str, ...] = ()) -> HTTPResponse:
    return HTTPResponse(status=status, headers={k.lower(): v for k, v in page_headers(form_targets).items()},
                        body=_document(title, body).encode("utf-8"))


def message_page(title: str, message: str, status: int = 400) -> HTTPResponse:
    return html_page(title, f"<h1>{escape(title)}</h1><p>{escape(message)}</p>", status)


def consent_page(
    *,
    brand_name: str,
    agent_origin: str,
    user_display: str,
    scopes: list[tuple[str, str]],
    action: str,
    session: str,
    form_targets: tuple[str, ...] = (),
) -> HTTPResponse:
    """The consent form: one checkbox per requested scope, checked by default."""
    rows = "".join(
        f'<label><input type="checkbox" name="scope" value="{escape(sid)}" checked>'
        f"<span>{escape(desc)}<br><code>{escape(sid)}</code></span></label>"
        for sid, desc in scopes
    )
    body = (
        f'<form method="post" action="{escape(action)}">'
        f"<h1>Allow an agent to act on your {escape(brand_name)} account?</h1>"
        f'<p class="muted">Signed in as <b>{escape(user_display)}</b><br>'
        f"Personal agent from <b>{escape(agent_origin)}</b></p>"
        f'<input type="hidden" name="session" value="{escape(session)}">'
        f"<p>It will be able to:</p>{rows}"
        '<button type="submit" name="decision" value="allow">Allow</button>'
        '<button type="submit" name="decision" value="deny">Don\'t allow</button>'
        "</form>"
        '<p class="muted">Uncheck anything you don\'t want to share. '
        "The agent never sees your password.</p>"
    )
    return html_page(f"Allow access to {brand_name}", body, 200, (action, *form_targets))


__all__ = ["consent_page", "html_page", "message_page", "page_headers"]
