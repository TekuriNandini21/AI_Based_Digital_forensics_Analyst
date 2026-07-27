"""
app.py
------------------------------------------------------------
Flask application entry point for the AI-Powered Digital
Forensics Assistant.

Routes:
    GET  /                  -> Login page
    POST /login             -> Authenticate (Flask session)
    GET  /logout            -> Clear session
    GET  /dashboard         -> Main SOC-style dashboard
    POST /upload            -> Upload + analyze evidence file(s)
    GET  /investigation/<id>-> Investigation detail (JSON, used by dashboard)
    GET  /report/<id>       -> HTML report preview
    GET  /report/<id>/pdf   -> Download generated PDF report
    GET  /api/dashboard     -> JSON dashboard stats (for charts)
    GET  /api/investigations-> JSON list of past investigations
------------------------------------------------------------
"""

import os
import functools
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, send_file, flash
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth

import database as db
import analyzer
import ai_analyzer
import report_generator

load_dotenv()

app = Flask(__name__)
oauth = OAuth(app)

# Google
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

# GitHub
github = oauth.register(
    name="github",
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
    access_token_url="https://github.com/login/oauth/access_token",
    authorize_url="https://github.com/login/oauth/authorize",
    api_base_url="https://api.github.com/",
    client_kwargs={
        "scope": "read:user user:email"
    }
)
app.secret_key = os.getenv("FLASK_SECRET_KEY")

app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-key-change-me")

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {"csv", "json", "txt", "log"}
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "25"))

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/login/google")
def login_google():
    redirect_uri = url_for("google_callback", _external=True)
    print("Redirect URI:", redirect_uri)
    return google.authorize_redirect(redirect_uri)

@app.route("/auth/google/callback")
def google_callback():
    token = google.authorize_access_token()
    user = token.get("userinfo")
    session["logged_in"] = True
    session["username"] = user["name"]
    session["email"] = user["email"]
    session["picture"] = user.get("picture")
    return redirect(url_for("dashboard"))

@app.route("/login/github")
def login_github():
    redirect_uri = url_for("github_callback", _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route("/auth/github/callback")
def github_callback():
    token = github.authorize_access_token()

    # Get GitHub user details
    resp = github.get("user", token=token)
    user = resp.json()

    session["logged_in"] = True
    session["username"] = user["login"]      # GitHub username
    session["email"] = user.get("email")     # May be None
    session["picture"] = user["avatar_url"]

    return redirect(url_for("dashboard"))

# ----------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ----------------------------------------------------------------
# Auth routes
# ----------------------------------------------------------------

@app.route("/", methods=["GET"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


oauth = OAuth(app)
google = oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile"
    }
)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ----------------------------------------------------------------
# Dashboard
# ----------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    stats = db.get_dashboard_stats()
    return render_template(
    "dashboard.html",
    stats=stats,
    username=session.get("username"),
    email=session.get("email"),
    picture=session.get("picture")
)


@app.route("/api/dashboard")
@login_required
def api_dashboard():
    return jsonify(db.get_dashboard_stats())


@app.route("/api/investigations")
@login_required
def api_investigations():
    return jsonify(db.get_all_investigations())


# ----------------------------------------------------------------
# Upload + Analysis
# ----------------------------------------------------------------

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    case_name = request.form.get("case_name", "").strip()
    investigator = request.form.get("investigator", session.get("username", "Unknown")).strip()
    files = request.files.getlist("evidence_files")

    if not case_name:
        flash("Case name is required.", "error")
        return redirect(url_for("dashboard"))

    if not files or all(f.filename == "" for f in files):
        flash("Please select at least one evidence file.", "error")
        return redirect(url_for("dashboard"))

    try:
        investigation_id = db.create_investigation(case_name, investigator)
        all_incidents = []
        evidence_records = []

        for f in files:
            if f.filename == "" or not allowed_file(f.filename):
                continue

            filename = secure_filename(f.filename)
            safe_path = os.path.join(
                app.config["UPLOAD_FOLDER"],
                f"inv{investigation_id}_{filename}"
            )
            f.save(safe_path)
            file_size = os.path.getsize(safe_path)

            with open(safe_path, "r", errors="ignore") as fh:
                content = fh.read()

            result = analyzer.analyze_evidence_file(filename, content)

            evidence_id = db.add_evidence(
                investigation_id, filename,
                filename.rsplit(".", 1)[-1].lower(),
                file_size, result["lines_parsed"]
            )
            db.add_incidents_bulk(investigation_id, evidence_id, result["incidents"])

            all_incidents.extend(result["incidents"])
            evidence_records.append({
                "filename": filename,
                "incidents": len(result["incidents"]),
            })

        # Aggregate across all uploaded files for this investigation
        overall_summary = analyzer.build_summary(all_incidents)
        risk_score, risk_level = analyzer.calculate_risk_score(overall_summary)

        ai_summary = ai_analyzer.generate_ai_analysis(
            case_name, overall_summary, risk_score, risk_level, all_incidents
        )

        db.update_investigation_results(
            investigation_id, risk_score, risk_level, ai_summary,
            overall_summary["total_incidents"], len(all_incidents)
        )

        flash(
            f"Investigation '{case_name}' analyzed successfully. "
            f"Risk Level: {risk_level} ({risk_score}/100).",
            "success"
        )
        return redirect(url_for("report_view", investigation_id=investigation_id))

    except Exception as exc:
        flash(f"An error occurred while processing evidence: {exc}", "error")
        return redirect(url_for("dashboard"))


# ----------------------------------------------------------------
# Reports
# ----------------------------------------------------------------

@app.route("/investigation/<int:investigation_id>")
@login_required
def investigation_json(investigation_id):
    investigation = db.get_investigation(investigation_id)
    if not investigation:
        return jsonify({"error": "Not found"}), 404
    incidents = db.get_incidents_for_investigation(investigation_id)
    evidence = db.get_evidence_for_investigation(investigation_id)
    return jsonify({
        "investigation": investigation,
        "incidents": incidents,
        "evidence": evidence,
    })


@app.route("/report/<int:investigation_id>")
@login_required
def report_view(investigation_id):
    investigation = db.get_investigation(investigation_id)
    if not investigation:
        flash("Investigation not found.", "error")
        return redirect(url_for("dashboard"))

    incidents = db.get_incidents_for_investigation(investigation_id)
    evidence = db.get_evidence_for_investigation(investigation_id)
    summary = analyzer.build_summary(incidents)

    return render_template(
        "report.html",
        investigation=investigation,
        incidents=incidents,
        evidence=evidence,
        summary=summary,
    )


@app.route("/report/<int:investigation_id>/pdf")
@login_required
def report_pdf(investigation_id):
    investigation = db.get_investigation(investigation_id)
    if not investigation:
        flash("Investigation not found.", "error")
        return redirect(url_for("dashboard"))

    incidents = db.get_incidents_for_investigation(investigation_id)
    evidence = db.get_evidence_for_investigation(investigation_id)
    summary = analyzer.build_summary(incidents)

    pdf_path = report_generator.generate_pdf_report(
        investigation, evidence, incidents, summary,
        investigation.get("ai_summary", "")
    )

    return send_file(
        pdf_path, as_attachment=True,
        download_name=f"forensic_report_case_{investigation_id}.pdf"
    )


@app.route("/investigation/<int:investigation_id>/delete", methods=["POST"])
@login_required
def delete_investigation(investigation_id):
    db.delete_investigation(investigation_id)
    flash("Investigation deleted.", "success")
    return redirect(url_for("dashboard"))


# ----------------------------------------------------------------
# Error handlers
# ----------------------------------------------------------------

@app.errorhandler(413)
def too_large(e):
    flash(f"File too large. Maximum upload size is {MAX_UPLOAD_MB} MB.", "error")
    return redirect(url_for("dashboard"))


@app.errorhandler(404)
def not_found(e):
    return render_template("index.html"), 404


if __name__ == "__main__":
    port = int(os.getenv("FLASK_RUN_PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "True").lower() == "true"
    app.run(debug=debug, port=port, host="0.0.0.0")
