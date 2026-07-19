"""Flask application: web dashboard + versioned REST API.

One app serves both. The dashboard uses the same session tokens as the API
(stored in an HttpOnly cookie), so there is exactly one auth path.

REST surface (all under /api/v1):
    POST /login                       -> {token, username, role}
    POST /logout
    POST /ingest                      (Scout REST ingest; X-HexBee-Ingest-Key)
    GET  /stats
    GET  /events?...                  (search filters as query params)
    GET  /events/<id>
    POST /events/<id>/tags            {tag}
    GET  /devices
    GET  /incidents?status=
    GET  /incidents/<id>              (includes timeline)
    POST /incidents/<id>/status       {status}
    POST /incidents/<id>/assign       {case_id}
    GET  /cases?status=
    POST /cases                       {title, description}
    GET  /cases/<id>                  (includes timeline)
    POST /cases/<id>/status           {status}
    POST /cases/<id>/notes            {body}
    GET  /cases/<id>/report?format=html|json|csv
    GET  /verify                      (hash-chain verification)
    GET  /audit?limit=
"""

from __future__ import annotations

import hmac
import json
from functools import wraps

from flask import (
    Flask,
    Response,
    g,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

from . import __version__
from .auth import authenticate, resolve_token, revoke_token, role_allows
from .cases import (
    add_note,
    assign_incident,
    create_case,
    event_tags,
    get_case,
    list_cases,
    set_case_status,
    set_incident_status,
    tag_event,
)
from .config import HiveConfig
from .correlate import Correlator
from .db import Database
from .ai import LocalAI, ask as ai_ask, summarize_case
from .evidence_export import chain_anchor, export_case, verify_anchor
from .ingest import process_raw_event
from .integrity import verify_chain
from .ioc import add_ioc, list_hits, list_iocs, remove_ioc
from .maps import PLACEHOLDER_TILE, TileStore, evidence_points
from .reference import ReferenceLibrary, render_markdown_basic
from .normalize import NormalizationError
from .security import (
    LoginRateLimiter,
    apply_security_headers,
    csrf_token,
    csrf_valid,
    new_nonce,
)
from .reports import case_report_data, render_csv, render_html, render_json
from .search import search_events, stats
from .store import EVENT_SELECT, audit, event_to_dict
from .timeline import case_timeline, incident_timeline

COOKIE = "hexbee_token"


def create_app(cfg: HiveConfig, db: Database) -> Flask:
    app = Flask(__name__)
    correlator = Correlator(db, cfg.correlation_window_seconds)
    tiles = TileStore(cfg.maps_dir)
    library = ReferenceLibrary(cfg.reference_dir)
    ai_engine = LocalAI(cfg.ai_url, cfg.ai_model)
    limiter = LoginRateLimiter(cfg.login_max_attempts, cfg.login_lockout_seconds)
    signing_key = cfg.signing_key
    # Reject oversized bodies before they hit handlers (evidence photos capped
    # separately in the field-upload route).
    app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024

    def client_ip() -> str:
        # Behind the documented reverse proxy, honour a single X-Forwarded-For
        # hop; otherwise the socket address.
        fwd = request.headers.get("X-Forwarded-For", "")
        return fwd.split(",")[0].strip() if fwd else (request.remote_addr or "")

    # -- security: headers, CSP nonce, CSRF -------------------------------

    @app.before_request
    def _assign_nonce():
        g.csp_nonce = new_nonce()

    @app.before_request
    def _csrf_protect():
        # State-changing dashboard forms (cookie-authenticated) must carry a
        # valid CSRF token. The JSON API uses bearer tokens in a custom header,
        # which browsers can't attach cross-site, so it is exempt. Login is
        # exempt (no session yet) and guarded by rate limiting.
        if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
            return None
        if request.path.startswith("/api/") or request.path == "/login":
            return None
        token = request.cookies.get(COOKIE, "")
        if not csrf_valid(token, request.form.get("_csrf", ""), signing_key):
            return render_template("error.html", user=None,
                                   message="Invalid or missing CSRF token — reload and retry."), 403
        return None

    @app.after_request
    def _security_headers(resp):
        return apply_security_headers(resp, getattr(g, "csp_nonce", ""), cfg.secure_cookies)

    @app.context_processor
    def _inject_security():
        token = request.cookies.get(COOKIE, "")
        return {"csp_nonce": getattr(g, "csp_nonce", ""),
                "csrf_token": csrf_token(token, signing_key) if token else ""}

    # -- auth plumbing ----------------------------------------------------

    def current_user():
        token = None
        header = request.headers.get("Authorization", "")
        if header.startswith("Bearer "):
            token = header[7:]
        elif COOKIE in request.cookies:
            token = request.cookies[COOKIE]
        return resolve_token(db, token), token

    def require(role: str, api: bool = True):
        def decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                user, token = current_user()
                if user is None:
                    if api:
                        return jsonify(error="authentication required"), 401
                    return redirect(url_for("login_page", next=request.path))
                if not role_allows(user["role"], role):
                    if api:
                        return jsonify(error=f"requires {role} role"), 403
                    return render_template("error.html", user=user,
                                           message=f"This page requires the {role} role."), 403
                g.user = user
                g.token = token
                return fn(*args, **kwargs)
            return wrapper
        return decorator

    # -- REST: auth -------------------------------------------------------

    @app.post("/api/v1/login")
    def api_login():
        body = request.get_json(silent=True) or {}
        username, ip = body.get("username", ""), client_ip()
        if limiter.locked(username, ip):
            audit(db, username or "(blank)", "login_locked", f"ip={ip}")
            return jsonify(error="too many attempts; try again later"), 429
        session = authenticate(db, username, body.get("password", ""),
                               cfg.token_ttl_hours, source_ip=ip)
        if session is None:
            limiter.record_failure(username, ip)
            return jsonify(error="invalid credentials"), 401
        limiter.reset(username, ip)
        return jsonify(session)

    @app.post("/api/v1/logout")
    @require("viewer")
    def api_logout():
        revoke_token(db, g.token)
        return jsonify(ok=True)

    # -- REST: ingest -----------------------------------------------------

    @app.post("/api/v1/ingest")
    def api_ingest():
        if not cfg.ingest_key:
            return jsonify(error="REST ingest disabled (set HEXBEE_INGEST_KEY)"), 403
        # Constant-time compare — no timing oracle on the ingest key.
        if not hmac.compare_digest(
                request.headers.get("X-HexBee-Ingest-Key", ""), cfg.ingest_key):
            return jsonify(error="bad ingest key"), 401
        raw = request.get_json(silent=True)
        if raw is None:
            return jsonify(error="body must be JSON"), 400
        events = raw if isinstance(raw, list) else [raw]
        results, errors = [], []
        for item in events:
            try:
                results.append(process_raw_event(db, correlator, item, source="rest"))
            except NormalizationError as exc:
                errors.append(str(exc))
        status = 200 if results else 400
        return jsonify(stored=len(results), results=results, errors=errors), status

    # -- REST: read/query -------------------------------------------------

    @app.get("/api/v1/stats")
    @require("viewer")
    def api_stats():
        return jsonify(stats(db))

    @app.get("/api/v1/events")
    @require("viewer")
    def api_events():
        q = request.args
        try:
            results = search_events(
                db,
                text=q.get("text"),
                device=q.get("device"),
                event_type=q.get("event_type"),
                incident_id=q.get("incident_id", type=int),
                tag=q.get("tag"),
                since=q.get("since"),
                until=q.get("until"),
                min_severity=q.get("min_severity", type=int),
                limit=q.get("limit", default=200, type=int),
            )
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(events=results)

    @app.get("/api/v1/events/<int:event_id>")
    @require("viewer")
    def api_event(event_id: int):
        row = db.query_one(EVENT_SELECT + " WHERE e.id = ?", (event_id,))
        if row is None:
            return jsonify(error="not found"), 404
        data = event_to_dict(row)
        data["tags"] = event_tags(db, event_id)
        return jsonify(data)

    @app.post("/api/v1/events/<int:event_id>/tags")
    @require("investigator")
    def api_tag_event(event_id: int):
        body = request.get_json(silent=True) or {}
        try:
            tag_event(db, event_id, body.get("tag", ""), g.user["username"])
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(ok=True, tags=event_tags(db, event_id))

    @app.get("/api/v1/devices")
    @require("viewer")
    def api_devices():
        return jsonify(devices=[dict(r) for r in db.query("SELECT * FROM devices ORDER BY name")])

    @app.get("/api/v1/incidents")
    @require("viewer")
    def api_incidents():
        status = request.args.get("status")
        if status:
            rows = db.query("SELECT * FROM incidents WHERE status = ? ORDER BY id DESC", (status,))
        else:
            rows = db.query("SELECT * FROM incidents ORDER BY id DESC")
        return jsonify(incidents=[dict(r) for r in rows])

    @app.get("/api/v1/incidents/<int:incident_id>")
    @require("viewer")
    def api_incident(incident_id: int):
        row = db.query_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if row is None:
            return jsonify(error="not found"), 404
        data = dict(row)
        data["timeline"] = incident_timeline(db, incident_id)
        return jsonify(data)

    @app.post("/api/v1/incidents/<int:incident_id>/status")
    @require("investigator")
    def api_incident_status(incident_id: int):
        body = request.get_json(silent=True) or {}
        try:
            ok = set_incident_status(db, incident_id, body.get("status", ""), g.user["username"])
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return (jsonify(ok=True), 200) if ok else (jsonify(error="not found"), 404)

    @app.post("/api/v1/incidents/<int:incident_id>/assign")
    @require("investigator")
    def api_incident_assign(incident_id: int):
        body = request.get_json(silent=True) or {}
        case_id = body.get("case_id")
        if not isinstance(case_id, int) or get_case(db, case_id) is None:
            return jsonify(error="case_id must reference an existing case"), 400
        ok = assign_incident(db, incident_id, case_id, g.user["username"])
        return (jsonify(ok=True), 200) if ok else (jsonify(error="not found"), 404)

    # -- REST: cases ------------------------------------------------------

    @app.get("/api/v1/cases")
    @require("viewer")
    def api_cases():
        return jsonify(cases=list_cases(db, request.args.get("status")))

    @app.post("/api/v1/cases")
    @require("investigator")
    def api_create_case():
        body = request.get_json(silent=True) or {}
        title = (body.get("title") or "").strip()
        if not title:
            return jsonify(error="title is required"), 400
        case = create_case(db, title, body.get("description", ""), g.user["username"])
        return jsonify(case), 201

    @app.get("/api/v1/cases/<int:case_id>")
    @require("viewer")
    def api_case(case_id: int):
        case = get_case(db, case_id)
        if case is None:
            return jsonify(error="not found"), 404
        case["timeline"] = case_timeline(db, case_id)
        return jsonify(case)

    @app.post("/api/v1/cases/<int:case_id>/status")
    @require("investigator")
    def api_case_status(case_id: int):
        body = request.get_json(silent=True) or {}
        try:
            ok = set_case_status(db, case_id, body.get("status", ""), g.user["username"])
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        return (jsonify(ok=True), 200) if ok else (jsonify(error="not found"), 404)

    @app.post("/api/v1/cases/<int:case_id>/notes")
    @require("investigator")
    def api_case_note(case_id: int):
        body = request.get_json(silent=True) or {}
        text = (body.get("body") or "").strip()
        if not text:
            return jsonify(error="body is required"), 400
        if get_case(db, case_id) is None:
            return jsonify(error="not found"), 404
        note_id = add_note(db, case_id, g.user["username"], text)
        return jsonify(ok=True, note_id=note_id), 201

    @app.get("/api/v1/cases/<int:case_id>/report")
    @require("viewer")
    def api_case_report(case_id: int):
        data = case_report_data(db, case_id)
        if data is None:
            return jsonify(error="not found"), 404
        fmt = request.args.get("format", "json")
        audit(db, g.user["username"], "report_generated", f"case {case_id} ({fmt})")
        number = data["case"]["case_number"]
        if fmt == "html":
            return Response(render_html(data), mimetype="text/html")
        if fmt == "csv":
            resp = Response(render_csv(data), mimetype="text/csv")
            resp.headers["Content-Disposition"] = f"attachment; filename={number}.csv"
            return resp
        if fmt == "json":
            return Response(render_json(data), mimetype="application/json")
        return jsonify(error="format must be html, json, or csv"), 400

    # -- REST: IOCs -------------------------------------------------------

    @app.get("/api/v1/iocs")
    @require("viewer")
    def api_iocs():
        return jsonify(iocs=list_iocs(db))

    @app.post("/api/v1/iocs")
    @require("investigator")
    def api_add_ioc():
        body = request.get_json(silent=True) or {}
        try:
            ioc_id = add_ioc(db, body.get("kind", ""), body.get("value", ""),
                             body.get("note", ""), g.user["username"])
        except ValueError as exc:
            return jsonify(error=str(exc)), 400
        except Exception:
            return jsonify(error="IOC already exists"), 409
        return jsonify(ok=True, ioc_id=ioc_id), 201

    @app.delete("/api/v1/iocs/<int:ioc_id>")
    @require("investigator")
    def api_delete_ioc(ioc_id: int):
        if remove_ioc(db, ioc_id, g.user["username"]):
            return jsonify(ok=True)
        return jsonify(error="not found"), 404

    @app.get("/api/v1/iocs/hits")
    @require("viewer")
    def api_ioc_hits():
        limit = request.args.get("limit", default=200, type=int)
        return jsonify(hits=list_hits(db, limit))

    # -- Offline map ------------------------------------------------------

    @app.get("/tiles/<int:z>/<int:x>/<int:y>")
    @require("viewer")
    def map_tile(z: int, x: int, y: int):
        blob = tiles.tile(z, x, y)
        if blob is None:
            return Response(PLACEHOLDER_TILE, mimetype="image/png",
                            headers={"Cache-Control": "no-store"})
        return Response(blob, mimetype=tiles.content_type,
                        headers={"Cache-Control": "max-age=86400"})

    @app.get("/api/v1/map/points")
    @require("viewer")
    def map_points():
        return jsonify(points=evidence_points(db), source=tiles.source_name)

    @app.get("/map")
    @require("viewer", api=False)
    def map_page():
        return render_template("map.html", user=g.user,
                               source=tiles.source_name)

    # -- Offline reference library ---------------------------------------

    @app.get("/reference")
    @require("viewer", api=False)
    def reference_page():
        catalog = library.catalog()
        zim = request.args.get("zim")
        query = request.args.get("q", "")
        results = library.zim_search(zim, query) if zim and query else None
        return render_template("reference.html", user=g.user, catalog=catalog,
                               zim=zim, query=query, results=results)

    @app.get("/reference/doc/<name>")
    @require("viewer", api=False)
    def reference_doc(name: str):
        doc = library.document(name)
        if doc is None:
            return render_template("error.html", user=g.user,
                                   message="No such document"), 404
        content, mime = doc
        if name.lower().endswith(".md"):
            body = render_markdown_basic(content.decode("utf-8", errors="replace"))
            return render_template("reference_doc.html", user=g.user,
                                   title=name, body=body)
        return Response(content, mimetype=mime)

    @app.get("/reference/zim/<zim_name>/", defaults={"article": None})
    @app.get("/reference/zim/<zim_name>/<path:article>")
    @require("viewer", api=False)
    def reference_zim(zim_name: str, article: str | None):
        if article is None:
            main = library.zim_main_page(zim_name)
            if main is None:
                return render_template(
                    "error.html", user=g.user,
                    message="ZIM unavailable (is python-libzim installed?)"), 404
            return redirect(url_for("reference_zim", zim_name=zim_name, article=main))
        result = library.zim_article(zim_name, article)
        if result is None:
            return render_template("error.html", user=g.user,
                                   message="Article not found"), 404
        content, mime = result
        return Response(content, mimetype=mime)

    # -- Hive Mind (local AI) --------------------------------------------

    @app.get("/api/v1/ai/status")
    @require("viewer")
    def ai_status():
        return jsonify(available=ai_engine.available(), url=cfg.ai_url,
                       model=cfg.ai_model)

    @app.post("/api/v1/ai/ask")
    @require("viewer")
    def ai_ask_route():
        body = request.get_json(silent=True) or {}
        question = (body.get("question") or "").strip()
        if not question:
            return jsonify(error="question is required"), 400
        result = ai_ask(db, ai_engine, question, body.get("case_id"))
        audit(db, g.user["username"], "ai_ask", question[:200])
        return jsonify(result)

    @app.post("/api/v1/ai/summarize/<int:case_id>")
    @require("viewer")
    def ai_summarize_route(case_id: int):
        result = summarize_case(db, ai_engine, case_id)
        if result is None:
            return jsonify(error="not found"), 404
        audit(db, g.user["username"], "ai_summarize", f"case {case_id}")
        return jsonify(result)

    @app.get("/assistant")
    @require("viewer", api=False)
    def assistant_page():
        return render_template("assistant.html", user=g.user,
                               ai_available=ai_engine.available(),
                               model=cfg.ai_model, cases=list_cases(db))

    # -- REST: integrity & audit -----------------------------------------

    @app.get("/api/v1/verify")
    @require("viewer")
    def api_verify():
        return jsonify(verify_chain(db))

    @app.get("/api/v1/anchor")
    @require("viewer")
    def api_anchor():
        return jsonify(chain_anchor(db, signing_key))

    @app.post("/api/v1/anchor/verify")
    @require("viewer")
    def api_anchor_verify():
        anchor = request.get_json(silent=True) or {}
        try:
            return jsonify(verify_anchor(db, anchor, signing_key))
        except (KeyError, TypeError):
            return jsonify(error="malformed anchor"), 400

    @app.post("/api/v1/cases/<int:case_id>/export")
    @require("investigator")
    def api_export_case(case_id: int):
        summary = export_case(db, cfg, case_id, signing_key, g.user["username"])
        if summary is None:
            return jsonify(error="not found"), 404
        audit(db, g.user["username"], "case_exported",
              f"case {case_id} -> {summary['bundle_dir']}")
        return jsonify(summary), 201

    @app.get("/api/v1/audit")
    @require("administrator")
    def api_audit():
        limit = max(1, min(request.args.get("limit", default=200, type=int), 2000))
        rows = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))
        return jsonify(audit=[dict(r) for r in rows])

    @app.get("/api/v1/health")
    def api_health():
        return jsonify(ok=True, version=__version__)

    # -- Dashboard pages --------------------------------------------------

    @app.get("/login")
    def login_page():
        return render_template("login.html", error=None)

    @app.post("/login")
    def login_submit():
        username, ip = request.form.get("username", ""), client_ip()
        if limiter.locked(username, ip):
            audit(db, username or "(blank)", "login_locked", f"ip={ip}")
            return render_template(
                "login.html", error="Too many attempts. Try again shortly."), 429
        session = authenticate(db, username, request.form.get("password", ""),
                               cfg.token_ttl_hours, source_ip=ip)
        if session is None:
            limiter.record_failure(username, ip)
            return render_template("login.html", error="Invalid credentials"), 401
        limiter.reset(username, ip)
        # Only redirect to local paths — never an attacker-supplied absolute URL.
        nxt = request.args.get("next") or url_for("dashboard")
        if not nxt.startswith("/") or nxt.startswith("//"):
            nxt = url_for("dashboard")
        resp = make_response(redirect(nxt))
        resp.set_cookie(
            COOKIE, session["token"], httponly=True, samesite="Lax",
            secure=cfg.secure_cookies, max_age=cfg.token_ttl_hours * 3600,
        )
        return resp

    @app.get("/logout")
    def logout_page():
        _, token = current_user()
        if token:
            revoke_token(db, token)
        resp = make_response(redirect(url_for("login_page")))
        resp.delete_cookie(COOKIE)
        return resp

    @app.get("/")
    @require("viewer", api=False)
    def dashboard():
        recent = search_events(db, limit=25)
        incidents = [
            dict(r) for r in db.query(
                "SELECT * FROM incidents WHERE status = 'open' ORDER BY severity DESC, id DESC LIMIT 10"
            )
        ]
        return render_template(
            "dashboard.html", user=g.user, stats=stats(db), recent=recent,
            incidents=incidents, verify=verify_chain(db),
        )

    @app.get("/incidents")
    @require("viewer", api=False)
    def incidents_page():
        rows = [dict(r) for r in db.query("SELECT * FROM incidents ORDER BY id DESC LIMIT 200")]
        return render_template("incidents.html", user=g.user, incidents=rows)

    @app.get("/incidents/<int:incident_id>")
    @require("viewer", api=False)
    def incident_page(incident_id: int):
        row = db.query_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
        if row is None:
            return render_template("error.html", user=g.user, message="Incident not found"), 404
        cases_open = list_cases(db)
        return render_template(
            "incident.html", user=g.user, incident=dict(row),
            timeline=incident_timeline(db, incident_id), cases=cases_open,
        )

    @app.get("/cases")
    @require("viewer", api=False)
    def cases_page():
        return render_template("cases.html", user=g.user, cases=list_cases(db))

    @app.get("/cases/<int:case_id>")
    @require("viewer", api=False)
    def case_page(case_id: int):
        case = get_case(db, case_id)
        if case is None:
            return render_template("error.html", user=g.user, message="Case not found"), 404
        return render_template(
            "case.html", user=g.user, case=case, timeline=case_timeline(db, case_id)
        )

    @app.get("/search")
    @require("viewer", api=False)
    def search_page():
        q = request.args
        results = None
        if any(q.get(k) for k in ("text", "device", "event_type", "tag", "since", "until")):
            results = search_events(
                db, text=q.get("text") or None, device=q.get("device") or None,
                event_type=q.get("event_type") or None, tag=q.get("tag") or None,
                since=q.get("since") or None, until=q.get("until") or None,
                limit=q.get("limit", default=200, type=int),
            )
        devices = [r["name"] for r in db.query("SELECT name FROM devices ORDER BY name")]
        return render_template(
            "search.html", user=g.user, results=results, query=q, devices=devices
        )

    @app.get("/devices")
    @require("viewer", api=False)
    def devices_page():
        rows = db.query(
            """SELECT d.*, COUNT(e.id) AS event_count, MAX(e.occurred_at) AS last_event
               FROM devices d LEFT JOIN events e ON e.device_id = d.id
               GROUP BY d.id ORDER BY d.name"""
        )
        from datetime import datetime, timedelta, timezone
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=5)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        devices = [dict(r) | {"online": r["last_seen"] >= cutoff} for r in rows]
        return render_template("devices.html", user=g.user, devices=devices)

    @app.get("/iocs")
    @require("viewer", api=False)
    def iocs_page():
        return render_template("iocs.html", user=g.user, iocs=list_iocs(db),
                               hits=list_hits(db, 100))

    @app.post("/iocs/new")
    @require("investigator", api=False)
    def ioc_new_form():
        try:
            add_ioc(db, request.form.get("kind", ""), request.form.get("value", ""),
                    request.form.get("note", ""), g.user["username"])
        except Exception:
            pass  # dashboard flow: invalid/duplicate entries are simply not added
        return redirect(url_for("iocs_page"))

    @app.post("/iocs/<int:ioc_id>/delete")
    @require("investigator", api=False)
    def ioc_delete_form(ioc_id: int):
        remove_ioc(db, ioc_id, g.user["username"])
        return redirect(url_for("iocs_page"))

    @app.get("/audit")
    @require("administrator", api=False)
    def audit_page():
        rows = db.query("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300")
        return render_template("audit.html", user=g.user, entries=[dict(r) for r in rows])

    # -- iPhone field companion ------------------------------------------

    @app.get("/field")
    @require("viewer", api=False)
    def field_page():
        open_incidents = [dict(r) for r in db.query(
            "SELECT * FROM incidents WHERE status = 'open' ORDER BY severity DESC, id DESC LIMIT 10")]
        return render_template("field.html", user=g.user, stats=stats(db),
                               incidents=open_incidents,
                               cases=list_cases(db)[:10])

    @app.post("/field/upload")
    @require("investigator", api=False)
    def field_upload():
        import hashlib
        import re as _re
        from datetime import datetime, timezone

        upload_file = request.files.get("photo")
        if upload_file is None or not upload_file.filename:
            return render_template("error.html", user=g.user,
                                   message="No photo attached"), 400
        data = upload_file.read()
        if len(data) > 25 * 1024 * 1024:
            return render_template("error.html", user=g.user,
                                   message="Photo too large (25 MB max)"), 400
        digest = hashlib.sha256(data).hexdigest()
        safe_name = _re.sub(r"[^A-Za-z0-9._-]", "_", upload_file.filename)[-80:]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        stored_name = f"{stamp}_{digest[:12]}_{safe_name}"
        (cfg.evidence_dir / stored_name).write_bytes(data)

        payload = {
            "name": stored_name, "sha256": digest, "size": len(data),
            "note": (request.form.get("note") or "").strip()[:500],
            "uploaded_by": g.user["username"],
        }
        case_id = request.form.get("case_id", type=int)
        if case_id:
            payload["case_id"] = case_id
        result = process_raw_event(
            db, correlator,
            {"device": "iPhone-Field", "event_type": "field_photo",
             "payload": payload},
            source=f"field:{g.user['username']}",
        )
        audit(db, g.user["username"], "field_photo_uploaded",
              f"{stored_name} -> event {result['event_id']}")
        return render_template("field_uploaded.html", user=g.user,
                               stored_name=stored_name, sha256=digest,
                               event_id=result["event_id"])

    # -- QR evidence labels ----------------------------------------------

    @app.get("/cases/<int:case_id>/qr.svg")
    @require("viewer", api=False)
    def case_qr(case_id: int):
        import io

        import segno

        case = get_case(db, case_id)
        if case is None:
            return jsonify(error="not found"), 404
        url = request.host_url.rstrip("/") + f"/cases/{case_id}"
        buf = io.BytesIO()
        segno.make(url, error="q").save(buf, kind="svg", scale=6, dark="#1f1a10")
        return Response(buf.getvalue(), mimetype="image/svg+xml")

    @app.get("/cases/<int:case_id>/label")
    @require("viewer", api=False)
    def case_label(case_id: int):
        case = get_case(db, case_id)
        if case is None:
            return render_template("error.html", user=g.user,
                                   message="Case not found"), 404
        return render_template("label.html", user=g.user, case=case)

    # Form-post helpers used by the dashboard (same auth as the API).

    @app.post("/cases/new")
    @require("investigator", api=False)
    def case_new_form():
        title = (request.form.get("title") or "").strip()
        if not title:
            return redirect(url_for("cases_page"))
        case = create_case(db, title, request.form.get("description", ""), g.user["username"])
        return redirect(url_for("case_page", case_id=case["id"]))

    @app.post("/cases/<int:case_id>/notes/new")
    @require("investigator", api=False)
    def case_note_form(case_id: int):
        body = (request.form.get("body") or "").strip()
        if body and get_case(db, case_id) is not None:
            add_note(db, case_id, g.user["username"], body)
        return redirect(url_for("case_page", case_id=case_id))

    @app.post("/cases/<int:case_id>/export-form")
    @require("investigator", api=False)
    def case_export_form(case_id: int):
        summary = export_case(db, cfg, case_id, signing_key, g.user["username"])
        if summary is None:
            return render_template("error.html", user=g.user,
                                   message="Case not found"), 404
        audit(db, g.user["username"], "case_exported",
              f"case {case_id} -> {summary['bundle_dir']}")
        return render_template("exported.html", user=g.user, summary=summary)

    @app.post("/incidents/<int:incident_id>/assign-form")
    @require("investigator", api=False)
    def incident_assign_form(incident_id: int):
        case_id = request.form.get("case_id", type=int)
        if case_id and get_case(db, case_id) is not None:
            assign_incident(db, incident_id, case_id, g.user["username"])
        return redirect(url_for("incident_page", incident_id=incident_id))

    @app.post("/incidents/<int:incident_id>/status-form")
    @require("investigator", api=False)
    def incident_status_form(incident_id: int):
        status = request.form.get("status", "")
        if status in ("open", "triaged", "closed"):
            set_incident_status(db, incident_id, status, g.user["username"])
        return redirect(url_for("incident_page", incident_id=incident_id))

    @app.template_filter("payload_pretty")
    def payload_pretty(value):
        return json.dumps(value, ensure_ascii=False)

    return app
