"""
DB - Repositorio MongoDB (eventos e alertas)
Eventos e alertas tem volume alto e schema flexivel, por isso vao para o
MongoDB. Credenciais sempre vem de variavel de ambiente - nunca hardcoded.
"""

import os
from bson import ObjectId
from bson.errors import InvalidId
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import PyMongoError

_cliente = None


def _montar_uri():
    uri = os.environ.get("MONGO_URI")
    if uri:
        return uri

    usuario = os.environ.get("MONGO_USER")
    senha = os.environ.get("MONGO_PASSWORD")
    host = os.environ.get("MONGO_HOST", "localhost")
    porta = os.environ.get("MONGO_PORT", "27017")

    if usuario and senha:
        return f"mongodb://{usuario}:{senha}@{host}:{porta}/?authSource=admin"
    return f"mongodb://{host}:{porta}/"


def obter_db():
    """Retorna o handle do banco securapy, reutilizando a conexao."""
    global _cliente
    if _cliente is None:
        _cliente = MongoClient(_montar_uri(), serverSelectionTimeoutMS=5000)
    nome_db = os.environ.get("MONGO_DB", "securapy")
    return _cliente[nome_db]


def criar_indices(db=None):
    """Cria indices em ip e timestamp para acelerar consultas e agregacoes."""
    db = db if db is not None else obter_db()
    db.eventos.create_index([("ip", ASCENDING)])
    db.eventos.create_index([("timestamp", DESCENDING)])
    db.eventos.create_index([("fonte", ASCENDING)])
    db.alertas.create_index([("ip", ASCENDING)])
    db.alertas.create_index([("timestamp", DESCENDING)])
    db.alertas.create_index([("severidade", ASCENDING)])


def salvar_eventos(eventos, db=None):
    """Insere uma lista de eventos normalizados no MongoDB."""
    if not eventos:
        return 0
    db = db if db is not None else obter_db()
    try:
        resultado = db.eventos.insert_many([dict(e) for e in eventos])
        return len(resultado.inserted_ids)
    except PyMongoError as erro:
        print(f"[ERRO] Falha ao salvar eventos no MongoDB: {erro}")
        return 0


def salvar_alertas(alertas, db=None):
    """Insere uma lista de alertas no MongoDB."""
    if not alertas:
        return 0
    db = db if db is not None else obter_db()
    try:
        resultado = db.alertas.insert_many([dict(a) for a in alertas])
        return len(resultado.inserted_ids)
    except PyMongoError as erro:
        print(f"[ERRO] Falha ao salvar alertas no MongoDB: {erro}")
        return 0


def buscar_eventos(fonte=None, tipo=None, ip=None, inicio=None, fim=None, pagina=1, tamanho=20, db=None):
    """Busca eventos com filtros opcionais e paginacao."""
    db = db if db is not None else obter_db()
    filtro = {}
    if fonte:
        filtro["fonte"] = fonte
    if tipo:
        filtro["tipo"] = tipo
    if ip:
        filtro["ip"] = ip
    if inicio or fim:
        filtro_timestamp = {}
        if inicio:
            filtro_timestamp["$gte"] = inicio
        if fim:
            filtro_timestamp["$lte"] = fim
        filtro["timestamp"] = filtro_timestamp

    pagina = max(1, pagina)
    tamanho = max(1, min(tamanho, 200))
    pular = (pagina - 1) * tamanho

    cursor = db.eventos.find(filtro, {"_id": 0}).sort("timestamp", DESCENDING).skip(pular).limit(tamanho)
    total = db.eventos.count_documents(filtro)
    return list(cursor), total


def buscar_alertas(severidade=None, ip=None, pagina=1, tamanho=20, db=None):
    """Busca alertas com filtros opcionais e paginacao."""
    db = db if db is not None else obter_db()
    filtro = {}
    if severidade:
        filtro["severidade"] = severidade.upper()
    if ip:
        filtro["ip"] = ip

    pagina = max(1, pagina)
    tamanho = max(1, min(tamanho, 200))
    pular = (pagina - 1) * tamanho

    cursor = db.alertas.find(filtro, {"_id": 0}).sort("timestamp", DESCENDING).skip(pular).limit(tamanho)
    total = db.alertas.count_documents(filtro)
    return list(cursor), total


def inserir_alerta(alerta, db=None):
    """Insere um unico alerta (POST /api/alertas) e retorna o id gerado."""
    db = db if db is not None else obter_db()
    resultado = db.alertas.insert_one(dict(alerta))
    return str(resultado.inserted_id)


def buscar_alerta_por_id(id_alerta, db=None):
    """Busca um alerta pelo id do Mongo. Retorna None se o id for invalido ou nao existir."""
    db = db if db is not None else obter_db()
    try:
        oid = ObjectId(id_alerta)
    except (InvalidId, TypeError):
        return None

    documento = db.alertas.find_one({"_id": oid})
    if documento is None:
        return None

    documento["id"] = str(documento.pop("_id"))
    return documento


def buscar_eventos_por_ip(ip, db=None):
    """Retorna todos os eventos de um IP especifico (sem paginacao)."""
    db = db if db is not None else obter_db()
    return list(db.eventos.find({"ip": ip}, {"_id": 0}).sort("timestamp", DESCENDING))


def buscar_alertas_por_ip(ip, db=None):
    """Retorna todos os alertas de um IP especifico (sem paginacao)."""
    db = db if db is not None else obter_db()
    return list(db.alertas.find({"ip": ip}, {"_id": 0}).sort("timestamp", DESCENDING))


def top_ips(n=5, db=None):
    """Agregacao: retorna os N IPs com mais eventos registrados."""
    db = db if db is not None else obter_db()
    pipeline = [
        {"$group": {"_id": "$ip", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
        {"$limit": n},
    ]
    resultado = list(db.eventos.aggregate(pipeline))
    return [{"ip": item["_id"], "total": item["total"]} for item in resultado]


def contagem_alertas_por_severidade(db=None):
    """Agregacao: conta alertas agrupados por severidade."""
    db = db if db is not None else obter_db()
    pipeline = [
        {"$group": {"_id": "$severidade", "total": {"$sum": 1}}},
        {"$sort": {"total": -1}},
    ]
    resultado = list(db.alertas.aggregate(pipeline))
    return {item["_id"]: item["total"] for item in resultado}


def limpar_colecoes(db=None):
    """Remove todos os documentos (usado em testes/re-ingestao)."""
    db = db if db is not None else obter_db()
    db.eventos.delete_many({})
    db.alertas.delete_many({})
