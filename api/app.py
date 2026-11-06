"""
API REST + Dashboard Web do SecuraPy Platform.

Modulo D (API REST): rotas de eventos, alertas, analise e busca por IP,
com autenticacao por token (JWT) nas rotas de escrita.

Modulo E (Seguranca Web / Dashboard): headers de seguranca em todas as
respostas, template engine com escape automatico (Jinja2 - defende XSS),
login de operador com mensagem generica (anti-enumeracao) e logging de
acesso (OWASP A09).
"""

import logging
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv

load_dotenv()

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from pymongo.errors import PyMongoError

from api.auth import gerar_token, requer_token
from core import relatorios as rel
from core.coletor import carregar_todos_os_logs
from core.detector import detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas, verificar_blacklist
from core.enriquecimento import consultar_ip
from core.regras import aplicar_regras, carregar_regras
from db import mongo_repo
from ia.assistente import classificar_evento
from ml.classificar import ModeloInvalidoError, pontuar_ip

try:
    import mysql.connector
    from db import mysql_repo
except ImportError:  # driver pode nao estar instalado em ambientes de teste
    mysql_repo = None

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_LOGS = os.path.join(BASE_DIR, "logs")
ARQUIVO_REGRAS = os.path.join(BASE_DIR, "config", "regras.json")
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}
REGEX_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")

_cache_geo = {}

logging.basicConfig(level=logging.INFO, format="%(asctime)s [ACESSO] %(message)s")
logger_acesso = logging.getLogger("securapy.acesso")


def ip_valido(ip):
    """Valida formato de IPv4 (cada octeto entre 0 e 255)."""
    m = REGEX_IPV4.match(ip or "")
    if not m:
        return False
    return all(0 <= int(octeto) <= 255 for octeto in m.groups())


def criar_app():
    app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "web", "templates"))
    app.secret_key = os.environ.get("FLASK_SECRET_KEY")
    if not app.secret_key:
        raise RuntimeError("FLASK_SECRET_KEY nao configurado (veja .env.example)")

    # ----------------------------------------------------------------
    # Modulo E - logging de acesso + headers de seguranca (todas as respostas)
    # ----------------------------------------------------------------
    @app.before_request
    def log_acesso():
        logger_acesso.info("%s %s de %s", request.method, request.path, request.remote_addr)

    @app.after_request
    def headers_seguranca(resposta):
        resposta.headers["X-Content-Type-Options"] = "nosniff"
        resposta.headers["X-Frame-Options"] = "DENY"
        resposta.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
        return resposta

    @app.errorhandler(Exception)
    def erro_generico(erro):
        from werkzeug.exceptions import HTTPException
        if isinstance(erro, HTTPException):
            return jsonify({"erro": erro.description}), erro.code

        app.logger.exception("Erro interno nao tratado")
        return jsonify({"erro": "Erro interno do servidor"}), 500

    # ----------------------------------------------------------------
    # Modulo D - API REST
    # ----------------------------------------------------------------

    @app.get("/api/eventos")
    def listar_eventos():
        try:
            pagina = int(request.args.get("pagina", 1))
            tamanho = int(request.args.get("tamanho", 20))
        except ValueError:
            return jsonify({"erro": "pagina e tamanho devem ser numeros inteiros"}), 400

        try:
            eventos, total = mongo_repo.buscar_eventos(
                fonte=request.args.get("fonte"),
                tipo=request.args.get("tipo"),
                ip=request.args.get("ip"),
                pagina=pagina,
                tamanho=tamanho,
            )
        except PyMongoError:
            return jsonify({"erro": "Falha ao consultar o banco de dados"}), 503

        return jsonify({"eventos": eventos, "total": total, "pagina": pagina, "tamanho": tamanho})

    @app.get("/api/alertas")
    def listar_alertas():
        try:
            pagina = int(request.args.get("pagina", 1))
            tamanho = int(request.args.get("tamanho", 20))
        except ValueError:
            return jsonify({"erro": "pagina e tamanho devem ser numeros inteiros"}), 400

        severidade = request.args.get("severidade")
        if severidade and severidade.upper() not in {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}:
            return jsonify({"erro": "severidade invalida"}), 400

        try:
            alertas, total = mongo_repo.buscar_alertas(
                severidade=severidade,
                ip=request.args.get("ip"),
                pagina=pagina,
                tamanho=tamanho,
            )
        except PyMongoError:
            return jsonify({"erro": "Falha ao consultar o banco de dados"}), 503

        return jsonify({"alertas": alertas, "total": total, "pagina": pagina, "tamanho": tamanho})

    @app.get("/api/alertas/<id_alerta>")
    def obter_alerta(id_alerta):
        try:
            alerta = mongo_repo.buscar_alerta_por_id(id_alerta)
        except PyMongoError:
            return jsonify({"erro": "Falha ao consultar o banco de dados"}), 503

        if alerta is None:
            return jsonify({"erro": "Alerta nao encontrado"}), 404
        return jsonify(alerta)

    @app.post("/api/alertas")
    @requer_token()
    def criar_alerta():
        corpo = request.get_json(silent=True)
        if not corpo or not isinstance(corpo, dict):
            return jsonify({"erro": "Corpo da requisicao deve ser um JSON valido"}), 400

        campos_obrigatorios = ["ip", "severidade", "descricao"]
        faltando = [c for c in campos_obrigatorios if c not in corpo]
        if faltando:
            return jsonify({"erro": f"Campos obrigatorios ausentes: {', '.join(faltando)}"}), 400

        if corpo["severidade"].upper() not in {"CRITICA", "ALTA", "MEDIA", "BAIXA", "INFO"}:
            return jsonify({"erro": "severidade invalida"}), 400

        try:
            id_criado = mongo_repo.inserir_alerta(corpo)
        except PyMongoError:
            return jsonify({"erro": "Falha ao salvar no banco de dados"}), 503

        return jsonify({"id": id_criado, "mensagem": "Alerta criado com sucesso"}), 201

    @app.post("/api/analisar")
    @requer_token()
    def analisar():
        corpo = request.get_json(silent=True) or {}

        if "eventos" in corpo:
            if not isinstance(corpo["eventos"], list):
                return jsonify({"erro": "'eventos' deve ser uma lista"}), 400
            eventos = corpo["eventos"]
        else:
            eventos = carregar_todos_os_logs(corpo.get("pasta_logs", PASTA_LOGS))

        regras = carregar_regras(ARQUIVO_REGRAS)
        alertas = aplicar_regras(eventos, regras)

        brute = detectar_brute_force(eventos)
        scan = detectar_port_scan(eventos)
        bl = verificar_blacklist(eventos, BLACKLIST)
        ameacas = gerar_resumo_ameacas(brute, scan, bl)

        try:
            for ameaca in ameacas:
                try:
                    resultado_ml = pontuar_ip(eventos, ameaca["ip"], BLACKLIST)
                    ameaca["score_ml"] = resultado_ml["score"]
                    ameaca["rotulo_ml"] = resultado_ml["rotulo"]
                except ModeloInvalidoError:
                    ameaca["score_ml"] = None
                    ameaca["rotulo_ml"] = "modelo_indisponivel"
        except Exception:
            pass

        try:
            n_eventos = mongo_repo.salvar_eventos(eventos)
            n_alertas = mongo_repo.salvar_alertas(alertas)
        except PyMongoError:
            return jsonify({"erro": "Falha ao persistir resultados no banco de dados"}), 503

        ameacas_serializaveis = rel.converter_sets(ameacas)

        return jsonify({
            "eventos_processados": len(eventos),
            "eventos_persistidos": n_eventos,
            "alertas_gerados": len(alertas),
            "alertas_persistidos": n_alertas,
            "ameacas": ameacas_serializaveis,
        })

    @app.get("/api/ip/<ip>")
    def consultar_ip_endpoint(ip):
        if not ip_valido(ip):
            return jsonify({"erro": "Formato de IP invalido"}), 400

        try:
            eventos_ip = mongo_repo.buscar_eventos_por_ip(ip)
            alertas_ip = mongo_repo.buscar_alertas_por_ip(ip)
        except PyMongoError:
            return jsonify({"erro": "Falha ao consultar o banco de dados"}), 503

        geo = consultar_ip(ip, _cache_geo)

        score_ml = None
        try:
            resultado_ml = pontuar_ip(eventos_ip or [{"ip": ip}], ip, BLACKLIST)
            score_ml = resultado_ml
        except ModeloInvalidoError:
            score_ml = {"erro": "modelo de ML indisponivel"}

        return jsonify({
            "ip": ip,
            "eventos": eventos_ip,
            "alertas": alertas_ip,
            "geolocalizacao": geo,
            "score_ml": score_ml,
        })

    @app.post("/api/login")
    def login_api():
        if mysql_repo is None:
            return jsonify({"erro": "Servico de autenticacao indisponivel"}), 503

        corpo = request.get_json(silent=True) or {}
        email, senha = corpo.get("email"), corpo.get("senha")
        if not email or not senha:
            return jsonify({"erro": "email e senha sao obrigatorios"}), 400

        try:
            usuario = mysql_repo.autenticar_usuario(email, senha)
        except mysql.connector.Error:
            return jsonify({"erro": "Servico de autenticacao indisponivel"}), 503

        if usuario is None:
            # mensagem generica - nao revela se o email existe (anti-enumeracao)
            return jsonify({"erro": "Credenciais invalidas"}), 401

        token = gerar_token(usuario)
        return jsonify({"token": token, "nivel_acesso": usuario["nivel_acesso"]})

    # ----------------------------------------------------------------
    # Modulo E - Dashboard web
    # ----------------------------------------------------------------

    @app.get("/")
    def raiz():
        return redirect(url_for("dashboard") if session.get("usuario") else url_for("tela_login"))

    @app.get("/login")
    def tela_login():
        return render_template("login.html", erro=None)

    @app.post("/login")
    def processar_login():
        if mysql_repo is None:
            return render_template("login.html", erro="Servico de autenticacao indisponivel"), 503

        email = request.form.get("email", "")
        senha = request.form.get("senha", "")

        try:
            usuario = mysql_repo.autenticar_usuario(email, senha)
        except mysql.connector.Error:
            return render_template("login.html", erro="Servico de autenticacao indisponivel"), 503

        if usuario is None:
            # mesma mensagem generica para usuario inexistente ou senha errada
            return render_template("login.html", erro="Credenciais invalidas"), 401

        session["usuario"] = {"email": usuario["email"], "nome": usuario["nome"], "nivel_acesso": usuario["nivel_acesso"]}
        return redirect(url_for("dashboard"))

    @app.get("/logout")
    def logout():
        session.clear()
        return redirect(url_for("tela_login"))

    @app.get("/dashboard")
    def dashboard():
        if "usuario" not in session:
            return redirect(url_for("tela_login"))

        try:
            eventos_amostra, total_eventos = mongo_repo.buscar_eventos(tamanho=1)
            alertas_amostra, total_alertas = mongo_repo.buscar_alertas(tamanho=1)
            top10 = mongo_repo.top_ips(n=10)
            por_severidade = mongo_repo.contagem_alertas_por_severidade()
        except PyMongoError:
            return render_template("dashboard.html", usuario=session["usuario"], erro_banco=True,
                                    total_eventos=0, total_alertas=0, top10=[], por_severidade={})

        return render_template(
            "dashboard.html",
            usuario=session["usuario"],
            erro_banco=False,
            total_eventos=total_eventos,
            total_alertas=total_alertas,
            top10=top10,
            por_severidade=por_severidade,
        )

    @app.get("/dashboard/ip/<ip>")
    def dashboard_buscar_ip(ip):
        if "usuario" not in session:
            return redirect(url_for("tela_login"))

        if not ip_valido(ip):
            return render_template("busca_ip.html", ip=ip, erro="Formato de IP invalido"), 400

        eventos_ip = mongo_repo.buscar_eventos_por_ip(ip)
        alertas_ip = mongo_repo.buscar_alertas_por_ip(ip)
        geo = consultar_ip(ip, _cache_geo)

        explicacao_ia = None
        if alertas_ip:
            explicacao_ia = classificar_evento(alertas_ip[0])

        return render_template(
            "busca_ip.html", ip=ip, erro=None, eventos=eventos_ip,
            alertas=alertas_ip, geo=geo, explicacao_ia=explicacao_ia,
        )

    return app


app = criar_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
