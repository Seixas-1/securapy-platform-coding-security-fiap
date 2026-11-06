"""
Core - Relatorios e Filtros (reaproveitado do 1o semestre)
Funcoes de apoio para filtrar eventos, buscar por IP, rankear IPs
suspeitos e exportar relatorios em JSON. Reutilizadas pela API REST
e pelo dashboard web no 2o semestre.
"""

import json
import os


def filtrar_eventos(eventos, fonte=None, tipo=None, ip=None):
    """Filtra eventos pelos criterios fornecidos."""
    return [
        e for e in eventos
        if (fonte is None or e.get("fonte") == fonte)
        and (tipo is None or e.get("tipo") == tipo)
        and (ip is None or e.get("ip") == ip)
    ]


def top_ips(eventos, n=10):
    """Retorna os N IPs com mais eventos registrados."""
    contagem = {}
    for evento in eventos:
        ip = evento.get("ip")
        if ip:
            contagem[ip] = contagem.get(ip, 0) + 1

    ordenado = sorted(contagem.items(), key=lambda x: x[1], reverse=True)
    return ordenado[:n]


def resumo_por_fonte(eventos):
    """Conta eventos agrupados por fonte."""
    por_fonte = {}
    for evento in eventos:
        fonte = evento.get("fonte", "desconhecida")
        por_fonte[fonte] = por_fonte.get(fonte, 0) + 1
    return por_fonte


def resumo_por_severidade(alertas):
    """Conta alertas agrupados por severidade."""
    por_severidade = {}
    for alerta in alertas:
        severidade = alerta.get("severidade", "desconhecida")
        por_severidade[severidade] = por_severidade.get(severidade, 0) + 1
    return por_severidade


def converter_sets(obj):
    """Converte recursivamente sets em listas, para permitir serializacao JSON."""
    if isinstance(obj, set):
        return list(obj)
    if isinstance(obj, dict):
        return {k: converter_sets(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [converter_sets(item) for item in obj]
    return obj


def exportar_relatorio_json(dados, caminho):
    """Salva um relatorio completo em formato JSON."""
    diretorio = os.path.dirname(caminho)
    if diretorio:
        os.makedirs(diretorio, exist_ok=True)

    dados_serializaveis = converter_sets(dados)

    with open(caminho, "w", encoding="utf-8") as f:
        json.dump(dados_serializaveis, f, indent=2, ensure_ascii=False)

    print(f"[INFO] Relatorio exportado para: {caminho}")
