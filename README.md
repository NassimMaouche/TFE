# TFE
Projet # app.py

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "tfe_hub.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

ALLOWED_EXTENSIONS = {"pdf", "doc", "docx"}


# =========================
# DATABASE
# =========================

def get_db():
    if "db" not in session:
        pass

    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def init_db():
    db = get_db()

    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            school TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tfes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            school TEXT DEFAULT '',
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tfe_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(tfe_id)
                REFERENCES tfes(id)
                ON DELETE CASCADE,
            FOREIGN KEY(user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        );
    """)

    db.commit()
    db.close()


# =========================
# AUTHENTICATION
# =========================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):

        if "user_id" not in session:
            flash(
                "Connecte-toi pour accéder à cette page.",
                "warning"
            )
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


def current_user():
    if "user_id" not in session:
        return None

    db = get_db()

    user = db.execute(
        "SELECT * FROM users WHERE id = ?",
        (session["user_id"],)
    ).fetchone()

    db.close()

    return user


@app.context_processor
def inject_user():
    return {
        "current_user": current_user()
    }


# =========================
# FILES
# =========================

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# =========================
# HOME
# =========================

@app.route("/")
def index():

    db = get_db()

    search = request.args.get(
        "q",
        ""
    ).strip()

    category = request.args.get(
        "category",
        ""
    ).strip()

    if search or category:

        like = f"%{search}%"

        tfes = db.execute(
            """
            SELECT
                tfes.*,
                users.username
            FROM tfes
            JOIN users
                ON users.id = tfes.user_id
            WHERE
                (
                    tfes.title LIKE ?
                    OR tfes.description LIKE ?
                    OR tfes.category LIKE ?
                    OR tfes.school LIKE ?
                )
                AND
                (
                    ? = ''
                    OR tfes.category = ?
                )
            ORDER BY tfes.created_at DESC
            """,
            (
                like,
                like,
                like,
                like,
                category,
                category
            )
        ).fetchall()

    else:

        tfes = db.execute(
            """
            SELECT
                tfes.*,
                users.username
            FROM tfes
            JOIN users
                ON users.id = tfes.user_id
            ORDER BY tfes.created_at DESC
            LIMIT 50
            """
        ).fetchall()

    categories = db.execute(
        """
        SELECT DISTINCT category
        FROM tfes
        WHERE category != ''
        ORDER BY category
        """
    ).fetchall()

    stats = {
        "tfes": db.execute(
            "SELECT COUNT(*) FROM tfes"
        ).fetchone()[0],

        "students": db.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0],

        "messages": db.execute(
            "SELECT COUNT(*) FROM messages"
        ).fetchone()[0]
    }

    db.close()

    return render_template(
        "index.html",
        tfes=tfes,
        categories=categories,
        stats=stats,
        q=search,
        category=category
    )


# =========================
# REGISTER
# =========================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    if request.method == "POST":

        username = request.form[
            "username"
        ].strip()

        email = request.form[
            "email"
        ].strip().lower()

        password = request.form[
            "password"
        ]

        school = request.form.get(
            "school",
            ""
        ).strip()

        if len(username) < 3:

            flash(
                "Le nom d'utilisateur doit contenir au moins 3 caractères.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        if len(password) < 6:

            flash(
                "Le mot de passe doit contenir au moins 6 caractères.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        db = get_db()

        try:

            db.execute(
                """
                INSERT INTO users
                (
                    username,
                    email,
                    password_hash,
                    school,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    username,
                    email,
                    generate_password_hash(password),
                    school,
                    datetime.utcnow().isoformat()
                )
            )

            db.commit()

        except sqlite3.IntegrityError:

            db.close()

            flash(
                "Ce nom d'utilisateur ou cet email existe déjà.",
                "danger"
            )

            return render_template(
                "register.html"
            )

        db.close()

        flash(
            "Compte créé avec succès.",
            "success"
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register.html"
    )


# =========================
# LOGIN
# =========================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        identifier = request.form[
            "identifier"
        ].strip()

        password = request.form[
            "password"
        ]

        db = get_db()

        user = db.execute(
            """
            SELECT *
            FROM users
            WHERE username = ?
            OR email = ?
            """,
            (
                identifier,
                identifier.lower()
            )
        ).fetchone()

        db.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(
                url_for("index")
            )

        flash(
            "Identifiants incorrects.",
            "danger"
        )

    return render_template(
        "login.html"
    )


# =========================
# LOGOUT
# =========================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("index")
    )


# =========================
# UPLOAD TFE
# =========================

@app.route(
    "/upload",
    methods=["GET", "POST"]
)
@login_required
def upload():

    if request.method == "POST":

        title = request.form[
            "title"
        ].strip()

        description = request.form[
            "description"
        ].strip()

        category = request.form[
            "category"
        ].strip()

        school = request.form.get(
            "school",
            ""
        ).strip()

        file = request.files.get(
            "file"
        )

        if not title:
            flash(
                "Le titre est obligatoire.",
                "danger"
            )
            return render_template(
                "upload.html"
            )

        if not description:
            flash(
                "La description est obligatoire.",
                "danger"
            )
            return render_template(
                "upload.html"
            )

        if not category:
            flash(
                "La catégorie est obligatoire.",
                "danger"
            )
            return render_template(
                "upload.html"
            )

        if not file or not file.filename:

            flash(
                "Tu dois sélectionner un fichier.",
                "danger"
            )

            return render_template(
                "upload.html"
            )

        if not allowed_file(
            file.filename
        ):

            flash(
                "Formats acceptés : PDF, DOC et DOCX.",
                "danger"
            )

            return render_template(
                "upload.html"
            )

        original_filename = secure_filename(
            file.filename
        )

        unique_filename = (
            datetime.utcnow().strftime(
                "%Y%m%d%H%M%S%f"
            )
            + "_"
            + original_filename
        )

        file.save(
            os.path.join(
                UPLOAD_FOLDER,
                unique_filename
            )
        )

        db = get_db()

        db.execute(
            """
            INSERT INTO tfes
            (
                title,
                description,
                category,
                school,
                filename,
                original_filename,
                user_id,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                description,
                category,
                school,
                unique_filename,
                original_filename,
                session["user_id"],
                datetime.utcnow().isoformat()
            )
        )

        db.commit()
        db.close()

        flash(
            "Ton TFE a été publié.",
            "success"
        )

        return redirect(
            url_for("index")
        )

    return render_template(
        "upload.html"
    )


# =========================
# TFE DETAILS
# =========================

@app.route("/tfe/<int:tfe_id>")
def tfe_detail(tfe_id):

    db = get_db()

    tfe = db.execute(
        """
        SELECT
            tfes.*,
            users.username
        FROM tfes
        JOIN users
            ON users.id = tfes.user_id
        WHERE tfes.id = ?
        """,
        (tfe_id,)
    ).fetchone()

    if not tfe:

        db.close()

        return "TFE introuvable", 404

    messages = db.execute(
        """
        SELECT
            messages.*,
            users.username
        FROM messages
        JOIN users
            ON users.id = messages.user_id
        WHERE messages.tfe_id = ?
        ORDER BY messages.created_at ASC
        """,
        (tfe_id,)
    ).fetchall()

    db.close()

    return render_template(
        "tfe.html",
        tfe=tfe,
        messages=messages
    )


# =========================
# CHAT
# =========================

@app.route(
    "/tfe/<int:tfe_id>/message",
    methods=["POST"]
)
@login_required
def send_message(tfe_id):

    content = request.form.get(
        "content",
        ""
    ).strip()

    if not content:
        return redirect(
            url_for(
                "tfe_detail",
                tfe_id=tfe_id
            )
        )

    db = get_db()

    tfe = db.execute(
        "SELECT id FROM tfes WHERE id = ?",
        (tfe_id,)
    ).fetchone()

    if not tfe:

        db.close()

        return "TFE introuvable", 404

    db.execute(
        """
        INSERT INTO messages
        (
            tfe_id,
            user_id,
            content,
            created_at
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            tfe_id,
            session["user_id"],
            content[:2000],
            datetime.utcnow().isoformat()
        )
    )

    db.commit()
    db.close()

    return redirect(
        url_for(
            "tfe_detail",
            tfe_id=tfe_id
        ) + "#chat"
    )


# =========================
# DOWNLOAD
# =========================

@app.route(
    "/download/<path:filename>"
)
def download(filename):

    return send_from_directory(
        UPLOAD_FOLDER,
        filename,
        as_attachment=True
    )


# =========================
# PROFILE
# =========================

@app.route("/profile")
@login_required
def profile():

    db = get_db()

    user = db.execute(
        """
        SELECT
            id,
            username,
            email,
            school,
            created_at
        FROM users
        WHERE id = ?
        """,
        (session["user_id"],)
    ).fetchone()

    my_tfes = db.execute(
        """
        SELECT *
        FROM tfes
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (session["user_id"],)
    ).fetchall()

    db.close()

    return render_template(
        "profile.html",
        user=user,
        my_tfes=my_tfes
    )


# =========================
# SITEMAP GOOGLE
# =========================

@app.route("/sitemap.xml")
def sitemap():

    db = get_db()

    tfes = db.execute(
        "SELECT id FROM tfes"
    ).fetchall()

    urls = [
        url_for(
            "index",
            _external=True
        )
    ]

    for tfe in tfes:

        urls.append(
            url_for(
                "tfe_detail",
                tfe_id=tfe["id"],
                _external=True
            )
        )

    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    )

    for url in urls:

        xml += (
            f"<url>"
            f"<loc>{url}</loc>"
            f"</url>"
        )

    xml += "</urlset>"

    db.close()

    return (
        xml,
        200,
        {
            "Content-Type":
            "application/xml"
        }
    )


# =========================
# ROBOTS
# =========================

@app.route("/robots.txt")
def robots():

    return (
        "User-agent: *\n"
        "Allow: /\n"
        "Sitemap: "
        + url_for(
            "sitemap",
            _external=True
        )
        + "\n",
        200,
        {
            "Content-Type":
            "text/plain"
        }
    )


# =========================
# START
# =========================

with app.app_context():
    init_db()


if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(
            os.environ.get(
                "PORT",
                5000
            )
        ),
        debug=True
    )








Projet : Création d’une application web destinée aux étudiants.

Objectif : Permettre aux étudiants de publier leurs TFE, consulter ceux des autres et échanger grâce à un système de discussion.

Technologies : Python, Flask, HTML, CSS, JavaScript et SQLite.

Premières étapes :

1. Définir les fonctionnalités de l’application.
2. Créer les maquettes des différentes pages.
3. Créer la base de données.
4. Développer le système d’inscription et de connexion.
5. Créer la page d’accueil et le système de dépôt des TFE.
6. Ajouter progressivement la recherche et le chat.

Résultat attendu : Une application web accessible en ligne permettant aux étudiants de partager leurs TFE et de communiquer entre eux.
