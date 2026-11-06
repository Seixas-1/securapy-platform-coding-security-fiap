"""
DB - Repositorio MySQL (usuarios e permissoes da plataforma)
Usuarios tem integridade relacional (email unico, nivel de acesso),
por isso vao para o MySQL. Todas as queries sao parametrizadas para
evitar SQL Injection. Credenciais sempre vem de variavel de ambiente.
"""

import hashlib
import hmac
import os
import secrets

import mysql.connector
from mysql.connector import Error as MySQLError

_ITERACOES_HASH = 200_000


def obter_conexao():
    """Abre uma nova conexao com o MySQL usando credenciais do ambiente."""
    return mysql.connector.connect(
        host=os.environ.get("MYSQL_HOST", "localhost"),
        port=int(os.environ.get("MYSQL_PORT", "3306")),
        user=os.environ.get("MYSQL_USER", "root"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database=os.environ.get("MYSQL_DATABASE", "securapy"),
    )


def criar_tabelas(conexao=None):
    """Cria a tabela de usuarios/operadores da plataforma se nao existir."""
    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INT AUTO_INCREMENT PRIMARY KEY,
            nome VARCHAR(120) NOT NULL,
            email VARCHAR(160) NOT NULL UNIQUE,
            senha_hash VARCHAR(255) NOT NULL,
            senha_salt VARCHAR(64) NOT NULL,
            nivel_acesso TINYINT NOT NULL DEFAULT 1,
            criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT chk_nivel_acesso CHECK (nivel_acesso BETWEEN 1 AND 5)
        )
        """
    )
    conexao.commit()
    cursor.close()
    if propria:
        conexao.close()


def _gerar_hash_senha(senha, salt=None):
    """Gera hash PBKDF2-SHA256 da senha. Nunca armazenamos texto puro."""
    salt = salt or secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac("sha256", senha.encode("utf-8"), salt.encode("utf-8"), _ITERACOES_HASH)
    return hash_bytes.hex(), salt


def _verificar_senha(senha, hash_armazenado, salt):
    hash_calculado, _ = _gerar_hash_senha(senha, salt)
    return hmac.compare_digest(hash_calculado, hash_armazenado)


def criar_usuario(nome, email, senha, nivel_acesso=1, conexao=None):
    """
    Cadastra um operador da plataforma.

    Retorna (True, id) em caso de sucesso, ou (False, mensagem) em caso de
    erro tratado - ex: email duplicado ou nivel de acesso invalido.
    """
    if not (1 <= nivel_acesso <= 5):
        return False, "Nivel de acesso deve estar entre 1 e 5"

    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor()

    senha_hash, salt = _gerar_hash_senha(senha)

    try:
        cursor.execute(
            "INSERT INTO usuarios (nome, email, senha_hash, senha_salt, nivel_acesso) "
            "VALUES (%s, %s, %s, %s, %s)",
            (nome, email, senha_hash, salt, nivel_acesso),
        )
        conexao.commit()
        novo_id = cursor.lastrowid
        return True, novo_id
    except MySQLError as erro:
        if erro.errno == 1062:  # duplicate entry
            return False, f"Email '{email}' ja cadastrado"
        return False, "Erro ao cadastrar usuario"
    finally:
        cursor.close()
        if propria:
            conexao.close()


def autenticar_usuario(email, senha, conexao=None):
    """
    Autentica um operador por email e senha (queries parametrizadas).

    Retorna o dict do usuario (sem o hash) em caso de sucesso, ou None.
    Mensagem de erro deve ser sempre generica no nivel da API (anti-enumeracao).
    """
    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor(dictionary=True)

    try:
        cursor.execute(
            "SELECT id, nome, email, senha_hash, senha_salt, nivel_acesso "
            "FROM usuarios WHERE email = %s",
            (email,),
        )
        usuario = cursor.fetchone()
    finally:
        cursor.close()
        if propria:
            conexao.close()

    if usuario is None:
        return None

    if not _verificar_senha(senha, usuario["senha_hash"], usuario["senha_salt"]):
        return None

    return {
        "id": usuario["id"],
        "nome": usuario["nome"],
        "email": usuario["email"],
        "nivel_acesso": usuario["nivel_acesso"],
    }


def buscar_usuario_por_email(email, conexao=None):
    """Busca um usuario pelo email (query parametrizada, sem retornar senha)."""
    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios WHERE email = %s",
            (email,),
        )
        return cursor.fetchone()
    finally:
        cursor.close()
        if propria:
            conexao.close()


def listar_usuarios(conexao=None):
    """Lista todos os usuarios cadastrados (sem senha)."""
    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, nome, email, nivel_acesso, criado_em FROM usuarios ORDER BY id")
        return cursor.fetchall()
    finally:
        cursor.close()
        if propria:
            conexao.close()


def atualizar_nivel_acesso(email, novo_nivel, conexao=None):
    """Atualiza o nivel de acesso de um usuario (query parametrizada)."""
    if not (1 <= novo_nivel <= 5):
        return False, "Nivel de acesso deve estar entre 1 e 5"

    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor()
    try:
        cursor.execute(
            "UPDATE usuarios SET nivel_acesso = %s WHERE email = %s",
            (novo_nivel, email),
        )
        conexao.commit()
        return (cursor.rowcount > 0), None
    finally:
        cursor.close()
        if propria:
            conexao.close()


def remover_usuario(email, conexao=None):
    """Remove um usuario pelo email (query parametrizada)."""
    propria = conexao is None
    conexao = conexao if conexao is not None else obter_conexao()
    cursor = conexao.cursor()
    try:
        cursor.execute("DELETE FROM usuarios WHERE email = %s", (email,))
        conexao.commit()
        return cursor.rowcount > 0
    finally:
        cursor.close()
        if propria:
            conexao.close()
