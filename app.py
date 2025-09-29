from flask import Flask, render_template, request, redirect, url_for, session, flash
from supabase import create_client
from dotenv import load_dotenv
import os, bcrypt, requests
from datetime import datetime, timedelta
from functools import wraps
import base64
from io import BytesIO
from PIL import Image, UnidentifiedImageError
import json, logging, filetype
from collections import defaultdict
import time
import re
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# -----------------------------
# Configuração inicial
# -----------------------------
load_dotenv()
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
SUPABASE_TABLE = os.getenv("SUPABASE_TABLE")
EVOLUTION_SERVER = os.getenv("EVOLUTION_SERVER")
EVOLUTION_APIKEY = os.getenv("EVOLUTION_APIKEY")
WEBHOOK_GRUPOS = os.getenv("WEBHOOK_GRUPOS")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret")
limiter = Limiter(
    key_func=get_remote_address,  # identifica por IP
    app=app,                      # aplica no app Flask
    default_limits=[]             # sem limite global, só onde você colocar
)

# Segurança extra
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # Máximo 5 MB por upload
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=False,   # altere para True em produção com HTTPS
    SESSION_COOKIE_SAMESITE="Lax"
)

# -----------------------------
# Helpers
# -----------------------------
def parse_date_br(date_str: str):
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        return datetime.strptime(date_str.strip(), "%d/%m/%Y").date()
    except ValueError:
        return None

def tem_acesso_total_por_expiracao(data_exp_str: str) -> bool:
    d = parse_date_br(data_exp_str)
    if not d:
        return False
    return datetime.now().date() <= d

def evolution_status(instance_name: str) -> str:
    url = f"{EVOLUTION_SERVER}/instance/connect/{instance_name}"
    headers = {"apikey": EVOLUTION_APIKEY}
    try:
        resp = requests.get(url, headers=headers, timeout=10)
        resp.raise_for_status()
        data = resp.json() or {}
        return data.get("instance", {}).get("state") or data.get("instance", {}).get("status")
    except Exception:
        return None

def evolution_create_instance(nome: str) -> dict:
    url = f"{EVOLUTION_SERVER}/instance/create"
    headers = {"apikey": EVOLUTION_APIKEY, "Content-Type": "application/json"}
    payload = {"instanceName": nome, "integration": "WHATSAPP-BAILEYS", "qrcode": True}
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=15)
        resp.raise_for_status()
        return resp.json() or {}
    except Exception:
        return {}

def evolution_delete_instance(nome: str) -> bool:
    url = f"{EVOLUTION_SERVER}/instance/delete/{nome}"
    headers = {"apikey": EVOLUTION_APIKEY}
    try:
        resp = requests.delete(url, headers=headers, timeout=10)
        resp.raise_for_status()
        return True
    except Exception:
        return False

def safe_image_to_b64(file_storage, max_size=(1024, 1024)):
    """Valida e converte imagem para base64 com segurança"""
    filename = (file_storage.filename or "").lower()
    if filename.endswith(".svg") or file_storage.mimetype == "image/svg+xml":
        raise ValueError("SVG não permitido")

    # Verifica assinatura mágica
    file_storage.stream.seek(0)
    header = file_storage.stream.read(261)  # filetype precisa dos primeiros bytes
    kind = filetype.guess(header)
    file_storage.stream.seek(0)

    if not kind or kind.mime not in {"image/png", "image/jpeg", "image/gif", "image/webp"}:
        raise ValueError("Tipo de imagem não suportado")

    try:
        img = Image.open(file_storage)
        img.verify()
        file_storage.stream.seek(0)
        img = Image.open(file_storage)
    except (UnidentifiedImageError, Exception):
        raise ValueError("Arquivo não é uma imagem válida")

    img = img.convert("RGB")
    img.thumbnail(max_size)
    buffer = BytesIO()
    img.save(buffer, format="PNG", optimize=True)
    buffer.seek(0)
    return base64.b64encode(buffer.getvalue()).decode("utf-8")

# -----------------------------
# Segurança extra: Rate Limit
# -----------------------------
login_attempts = defaultdict(list)

def rate_limit_login(limit=5, window=60):
    """Limita X tentativas de login por IP dentro da janela (segundos)."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.remote_addr
            now = time.time()

            # mantém só tentativas dentro da janela
            login_attempts[ip] = [t for t in login_attempts[ip] if now - t < window]

            if len(login_attempts[ip]) >= limit:
                return render_template("login.html", erro="Muitas tentativas. Aguarde 1 minuto.")

            resp = f(*args, **kwargs)
            if request.method == "POST":
                login_attempts[ip].append(now)
            return resp
        return wrapped
    return decorator

# -----------------------------
# Segurança extra: Validação cadastro
# -----------------------------
def validar_nome(nome: str) -> bool:
    # Apenas letras, números e _, entre 3 e 20 caracteres
    return bool(re.match(r"^[A-Za-z0-9_]{3,20}$", nome))

# -----------------------------
# Decorators
# -----------------------------
def login_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return _wrap

def ativacao_required(f):
    @wraps(f)
    def _wrap(*args, **kwargs):
        if "usuario" not in session:
            return redirect(url_for("login"))
        if not session.get("acesso_total"):
            return redirect(url_for("home"))
        return f(*args, **kwargs)
    return _wrap

# -----------------------------
# Rotas principais
# -----------------------------
@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")  # até 5 tentativas por minuto
def login():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        lembrar = request.form.get("lembrar")

        result = supabase.table(SUPABASE_TABLE).select("*").eq("nome", nome).execute()
        if result.data:
            usuario = result.data[0]
            senha_hash = usuario.get("senha", "")

            if senha_hash and bcrypt.checkpw(senha.encode(), senha_hash.encode()):
                session["usuario"] = usuario["nome"]

                data_exp_str = usuario.get("ativacao")
                session["acesso_total"] = tem_acesso_total_por_expiracao(data_exp_str)

                if lembrar:
                    session.permanent = True
                    app.permanent_session_lifetime = timedelta(days=30)

                return redirect(url_for("home"))

        return render_template("login.html", erro="Usuário ou senha inválidos")

    return render_template("login.html")

@app.route("/cadastro", methods=["GET", "POST"])
def cadastro():
    if request.method == "POST":
        nome = request.form["nome"]
        senha = request.form["senha"]
        confirmar = request.form["confirmar"]
        empresa = request.form["empresa"]
        telefone = request.form["telefone"]

        if not validar_nome(nome):
            return render_template("cadastro.html", erro="Nome inválido. Use apenas letras/números (3-20 caracteres).")

        if senha != confirmar:
            return render_template("cadastro.html", erro="As senhas não coincidem.")

        existe = supabase.table(SUPABASE_TABLE).select("id").eq("nome", nome).execute()
        if existe.data:
            return render_template("cadastro.html", erro="Usuário já existe.")

        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

        supabase.table(SUPABASE_TABLE).insert({
            "nome": nome, "senha": senha_hash,
            "empresa": empresa, "telefone": telefone
        }).execute()

        return render_template("login.html", sucesso="Cadastro realizado! Faça login.")

    return render_template("cadastro.html")

@app.route("/perfil")
@login_required
def perfil():
    return render_template("perfil.html", usuario=session["usuario"])

@app.route("/home")
@login_required
def home():
    return render_template("home.html", acesso_total=session.get("acesso_total", False))

@app.route("/grupos", methods=["GET"])
@ativacao_required
def grupos():
    usuario = session["usuario"]

    result = supabase.table(SUPABASE_TABLE).select("dispositivo").eq("nome", usuario).execute()
    instancia = result.data[0].get("dispositivo") if result.data else None

    if not instancia:
        flash("❌ Nenhuma instância conectada.")
        return redirect(url_for("dispositivo"))

    url = f"{EVOLUTION_SERVER}/group/fetchAllGroups/{instancia}?getParticipants=false"
    headers = {"apikey": EVOLUTION_APIKEY}

    grupos = []
    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
        grupos = resp.json() or []
    except Exception as e:
        print("Erro ao buscar grupos:", e)

    return render_template("grupos.html", grupos=grupos, instancia=instancia)

@app.route("/grupos/enviar", methods=["POST"])
@ativacao_required
def enviar_grupos():
    usuario = session["usuario"]

    result = supabase.table(SUPABASE_TABLE).select("dispositivo").eq("nome", usuario).execute()
    instancia = result.data[0].get("dispositivo") if result.data else None

    if not instancia:
        flash("❌ Nenhuma instância conectada.")
        return redirect(url_for("dispositivo"))

    grupos = request.form.get("grupos")
    mensagem = request.form.get("mensagem")
    enviar_todos = request.form.get("enviarTodos") == "True"
    imagem_file = request.files.get("imagem")

    try:
        grupos = json.loads(grupos) if grupos else []
    except Exception:
        grupos = []

    imagem_b64 = None
    if imagem_file and imagem_file.filename:
        try:
            imagem_b64 = safe_image_to_b64(imagem_file)
        except ValueError as e:
            flash(str(e))
            return redirect(url_for("grupos"))

    payload = {
        "instancia": instancia,
        "grupos": grupos,
        "mensagem": mensagem,
        "imagem": imagem_b64,
        "enviarTodos": enviar_todos
    }

    try:
        if not WEBHOOK_GRUPOS:
            raise Exception("WEBHOOK_GRUPOS não configurado no .env")

        resp = requests.post(WEBHOOK_GRUPOS, json=payload, timeout=15)
        resp.raise_for_status()
        flash("✅ Mensagem enviada com sucesso!")
    except Exception as e:
        print("Erro ao enviar:", e)
        flash("❌ Erro ao enviar mensagem.")

    return redirect(url_for("grupos"))

@app.route("/planos")
@ativacao_required
def planos():
    return render_template("planos.html")

@app.route("/dispositivo", methods=["GET", "POST"])
@ativacao_required
def dispositivo():
    usuario = session["usuario"]
    qrcode_b64, pairing_code, code = None, None, None
    status, conectado, expirado = None, False, False

    result = supabase.table(SUPABASE_TABLE).select("dispositivo").eq("nome", usuario).execute()
    dispositivo_nome = result.data[0].get("dispositivo") if result.data else None

    if request.method == "GET" and dispositivo_nome:
        if evolution_status(dispositivo_nome) == "open":
            return render_template(
                "dispositivo.html",
                conectado=True,
                status=f"✅ Dispositivo {dispositivo_nome} conectado.",
                dispositivo_nome=dispositivo_nome
            )
        else:
            supabase.table(SUPABASE_TABLE).update({"dispositivo": None}).eq("nome", usuario).execute()
            dispositivo_nome = None

    if request.method == "POST":
        acao = request.form.get("acao")
        nome = request.form.get("nome", "").strip()

        if acao == "deletar" and dispositivo_nome:
            if evolution_delete_instance(dispositivo_nome):
                supabase.table(SUPABASE_TABLE).update({"dispositivo": None}).eq("nome", usuario).execute()
                status = f"🗑️ Dispositivo {dispositivo_nome} deletado."
                dispositivo_nome = None
            else:
                status = "❌ Erro ao deletar."

        elif acao == "criar" and nome:
            if evolution_status(nome) == "open":
                status = "❌ Esse nome já existe."
            else:
                data = evolution_create_instance(nome)
                qrcode = data.get("qrcode", {})

                qrcode_b64 = qrcode.get("base64")
                pairing_code = qrcode.get("pairingCode")
                code = qrcode.get("code")

                status = "📲 Escaneie o QR Code." if qrcode_b64 else f"📲 Instância {nome} criada."
                dispositivo_nome = nome

    return render_template(
        "dispositivo.html",
        qrcode_b64=qrcode_b64,
        pairing_code=pairing_code,
        code=code,
        status=status,
        conectado=conectado,
        expirado=expirado,
        dispositivo_nome=dispositivo_nome
    )

@app.route("/dispositivo/status/<nome>")
@ativacao_required
def dispositivo_status(nome):
    state = evolution_status(nome)
    if state == "open":
        usuario = session["usuario"]
        supabase.table(SUPABASE_TABLE).update({"dispositivo": nome}).eq("nome", usuario).execute()
    return {"status": state or "unknown"}

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# Segurança extra: headers
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer-when-downgrade"
    return response

if __name__ == "__main__":
    app.run(debug=False)
