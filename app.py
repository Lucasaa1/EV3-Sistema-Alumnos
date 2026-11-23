
"""!
@file app.py
@brief Sistema Alumnos de SecureDev - Evaluación Parcial 3 OCY1102.

API y portal web de alumnos con métricas Prometheus y controles
de seguridad para el ciclo de desarrollo DevSecOps.
"""

import os
import re
import secrets
import sqlite3
import time

from flask import (
    Flask,
    Response,
    g,
    jsonify,
    render_template_string,
    request,
    session,
)
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from werkzeug.security import check_password_hash


app = Flask(__name__)

# Configuración de seguridad.
# En producción, SECRET_KEY debe definirse en el entorno.
SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ADMIN_USUARIO = os.environ.get("ADMIN_USUARIO", "admin")
ADMIN_PASSWORD_HASH = os.environ.get("ADMIN_PASSWORD_HASH", "")

# Configuración del despliegue y almacenamiento.
VERSION = os.environ.get("APP_VERSION", "dev")
DB_PATH = os.environ.get("DB_PATH", "alumnos.db")


ALUMNOS_INICIALES = [
    (1, "Ana Pérez", "Ingeniería en Informática", 6.1),
    (2, "Benjamín Rojas", "Ingeniería en Ciberseguridad", 5.4),
    (3, "Camila Soto", "Analista Programador", 6.8),
    (4, "Diego Muñoz", "Ingeniería en Informática", 4.9),
]


# Métricas Prometheus: conservar estos nombres.
HTTP_PETICIONES = Counter(
    "http_requests_total",
    "Peticiones HTTP atendidas",
    ["method", "endpoint", "status"],
)

HTTP_LATENCIA = Histogram(
    "http_request_duration_seconds",
    "Duración de las peticiones HTTP",
    ["endpoint"],
)

LOGIN_FALLIDOS = Counter(
    "login_fallidos_total",
    "Intentos de inicio de sesión fallidos",
)

LOGIN_EXITOSOS = Counter(
    "login_exitosos_total",
    "Inicios de sesión correctos",
)

SOSPECHOSAS = Counter(
    "peticiones_sospechosas_total",
    "Peticiones con patrones de ataque",
    ["tipo"],
)

APP_INFO = Gauge(
    "app_info",
    "Versión desplegada de la aplicación",
    ["version"],
)

APP_INFO.labels(version=VERSION).set(1)


# Detección de patrones sospechosos.
PATRONES_ATAQUE = {
    "xss": re.compile(
        r"<\s*script|javascript:|onerror\s*=|onload\s*=|<\s*img",
        re.I,
    ),
    "sqli": re.compile(
        r"('|%27)\s*(or|and|union)\b|union\s+select|--|;\s*drop\b|sleep\(",
        re.I,
    ),
    "path_traversal": re.compile(
        r"\.\./|\.\.\\|%2e%2e",
        re.I,
    ),
}


PORTADA = """<!doctype html>
<html lang="es">
<head>
    <meta charset="utf-8">
    <title>Sistema Alumnos</title>
</head>
<body>
    <h1>Sistema Alumnos · SecureDev</h1>
    <p>Versión {{ version }}</p>

    <ul>
        <li><a href="/alumnos">Listado de alumnos (JSON)</a></li>
        <li><a href="/alumnos/1">Alumno 1</a></li>
        <li><a href="/hello?name=Ana">Saludo</a></li>
    </ul>

    <h2>Buscar alumno</h2>
    <form action="/alumnos/buscar" method="get">
        <input name="nombre" value="Ana">
        <button type="submit">Buscar</button>
    </form>

    <h2>Acceso administrador</h2>
    <form action="/login" method="post">
        <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
        <input name="usuario" value="admin">
        <input name="clave" type="password" value="">
        <button type="submit">Entrar</button>
    </form>
</body>
</html>"""


def conectar():
    """!
    @brief Abre la conexión SQLite para la petición.
    @return Conexión con filas accesibles por nombre de columna.
    """
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_error):
    """!
    @brief Cierra la conexión SQLite al finalizar la petición.
    """
    db = g.pop("db", None)
    if db is not None:
        db.close()


def iniciar_db():
    """!
    @brief Crea la tabla de alumnos y carga los datos iniciales.
    """
    db = sqlite3.connect(DB_PATH)

    db.execute(
        "CREATE TABLE IF NOT EXISTS alumnos ("
        "id INTEGER PRIMARY KEY, "
        "nombre TEXT, "
        "carrera TEXT, "
        "promedio REAL)"
    )

    if db.execute("SELECT COUNT(*) FROM alumnos").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO alumnos VALUES (?, ?, ?, ?)",
            ALUMNOS_INICIALES,
        )

    db.commit()
    db.close()


@app.before_request
def antes_de_la_peticion():
    """!
    @brief Registra el inicio y detecta patrones de ataque.
    """
    g.inicio = time.perf_counter()

    valores = list(request.args.values()) + list(request.form.values())

    for tipo, patron in PATRONES_ATAQUE.items():
        if any(patron.search(valor) for valor in valores):
            SOSPECHOSAS.labels(tipo=tipo).inc()

            app.logger.warning(
                "Petición sospechosa (%s) desde %s a %s",
                tipo,
                request.remote_addr,
                request.path,
            )


@app.after_request
def despues_de_la_peticion(respuesta):
    """!
    @brief Registra métricas y configura cabeceras HTTP de seguridad.
    @return Respuesta con cabeceras de seguridad.
    """
    endpoint = (
        request.url_rule.rule
        if request.url_rule
        else "desconocido"
    )

    if endpoint != "/metrics":
        HTTP_PETICIONES.labels(
            request.method,
            endpoint,
            str(respuesta.status_code),
        ).inc()

        HTTP_LATENCIA.labels(endpoint).observe(
            time.perf_counter()
            - g.get("inicio", time.perf_counter())
        )

    respuesta.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "form-action 'self'"
    )

    respuesta.headers["X-Frame-Options"] = "DENY"
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    respuesta.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    return respuesta


@app.route("/")
def portada():
    """!
    @brief Muestra la portada con token CSRF.
    @return Página HTML.
    """
    token = session.get("csrf_token")

    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token

    return render_template_string(
        PORTADA,
        version=VERSION,
        csrf_token=token,
    )


@app.route("/hello")
def hello():
    """!
    @brief Saluda al usuario escapando caracteres HTML.
    @return Página HTML con el saludo.
    """
    name = request.args.get("name", "visitante")

    return render_template_string(
        "<h1>Hola, {{ name }}!</h1>",
        name=name,
    )


@app.route("/health")
def health():
    """!
    @brief Comprueba el estado de la aplicación.
    @return JSON con estado operativo.
    """
    return jsonify({"estado": "ok"})


@app.route("/version")
def version():
    """!
    @brief Expone la versión para trazabilidad.
    @return Información de versión.
    """
    return jsonify({
        "aplicacion": "Sistema Alumnos",
        "version": VERSION,
    })


@app.route("/alumnos")
def listar_alumnos():
    """!
    @brief Obtiene todos los alumnos.
    @return Listado JSON de alumnos.
    """
    filas = conectar().execute(
        "SELECT * FROM alumnos ORDER BY id"
    ).fetchall()

    return jsonify([dict(fila) for fila in filas])


@app.route("/alumnos/<int:alumno_id>")
def obtener_alumno(alumno_id):
    """!
    @brief Obtiene un alumno por identificador.
    @return Datos JSON o respuesta 404.
    """
    fila = conectar().execute(
        "SELECT * FROM alumnos WHERE id = ?",
        (alumno_id,),
    ).fetchone()

    if fila is None:
        return jsonify({"error": "Alumno no encontrado"}), 404

    return jsonify(dict(fila))


@app.route("/alumnos/buscar")
def buscar_alumnos():
    """!
    @brief Busca alumnos mediante una consulta parametrizada.
    @return Coincidencias en JSON.
    """
    nombre = request.args.get("nombre", "")

    consulta = "SELECT * FROM alumnos WHERE nombre LIKE ?"

    try:
        filas = conectar().execute(
            consulta,
            (f"%{nombre}%",),
        ).fetchall()

    except sqlite3.Error:
        app.logger.exception("Error al buscar alumnos")

        return jsonify({
            "error": "Error interno al consultar alumnos"
        }), 500

    return jsonify([dict(fila) for fila in filas])


@app.route("/login", methods=["POST"])
def login():
    """!
    @brief Comprueba CSRF y las credenciales administrativas.
    @return Resultado JSON de la autenticación.
    """
    token_recibido = request.form.get("csrf_token", "")
    token_esperado = session.get("csrf_token", "")

    if (
        not token_recibido
        or not token_esperado
        or not secrets.compare_digest(
            token_recibido,
            token_esperado,
        )
    ):
        return jsonify({
            "error": "Token CSRF inválido"
        }), 403

    usuario = request.form.get("usuario", "")
    clave = request.form.get("clave", "")

    if (
        usuario == ADMIN_USUARIO
        and ADMIN_PASSWORD_HASH
        and check_password_hash(
            ADMIN_PASSWORD_HASH,
            clave,
        )
    ):
        LOGIN_EXITOSOS.inc()

        return jsonify({
            "mensaje": "Bienvenido, administrador"
        })

    LOGIN_FALLIDOS.inc()

    app.logger.warning(
        "Login fallido para el usuario '%s' desde %s",
        usuario,
        request.remote_addr,
    )

    return jsonify({
        "error": "Credenciales inválidas"
    }), 401


@app.route("/metrics")
def metrics():
    """!
    @brief Expone las métricas para Prometheus.
    @return Métricas en formato Prometheus.
    """
    return Response(
        generate_latest(),
        mimetype=CONTENT_TYPE_LATEST,
    )


iniciar_db()


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )
