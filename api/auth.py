"""
API - Autenticacao por Token (JWT)
Rotas de escrita da API exigem um header Authorization: Bearer <token>.
O segredo de assinatura vem sempre de variavel de ambiente - nunca
hardcoded no codigo (JWT_SECRET em .env).
"""

import datetime
import os
from functools import wraps

import jwt
from flask import jsonify, request

ALGORITMO = "HS256"
VALIDADE_HORAS = 8


def _obter_segredo():
    segredo = os.environ.get("JWT_SECRET")
    if not segredo:
        raise RuntimeError(
            "JWT_SECRET nao configurado. Defina a variavel de ambiente "
            "(veja .env.example) antes de iniciar a API."
        )
    return segredo


def gerar_token(usuario):
    """Gera um JWT assinado contendo id, email e nivel de acesso do usuario."""
    agora = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "sub": str(usuario["id"]),
        "email": usuario["email"],
        "nivel_acesso": usuario["nivel_acesso"],
        "iat": agora,
        "exp": agora + datetime.timedelta(hours=VALIDADE_HORAS),
    }
    return jwt.encode(payload, _obter_segredo(), algorithm=ALGORITMO)


def verificar_token(token):
    """Verifica e decodifica um JWT. Retorna o payload ou None se invalido/expirado."""
    try:
        return jwt.decode(token, _obter_segredo(), algorithms=[ALGORITMO])
    except jwt.PyJWTError:
        return None


def _extrair_token_do_header():
    cabecalho = request.headers.get("Authorization", "")
    if not cabecalho.startswith("Bearer "):
        return None
    return cabecalho[len("Bearer "):].strip()


def requer_token(nivel_minimo=1):
    """Decorator: exige um Bearer token JWT valido (e nivel de acesso minimo)."""
    def decorador(funcao):
        @wraps(funcao)
        def wrapper(*args, **kwargs):
            token = _extrair_token_do_header()
            if not token:
                return jsonify({"erro": "Token de autenticacao ausente"}), 401

            payload = verificar_token(token)
            if payload is None:
                return jsonify({"erro": "Token invalido ou expirado"}), 401

            if payload.get("nivel_acesso", 0) < nivel_minimo:
                return jsonify({"erro": "Nivel de acesso insuficiente"}), 403

            request.usuario_autenticado = payload
            return funcao(*args, **kwargs)
        return wrapper
    return decorador
