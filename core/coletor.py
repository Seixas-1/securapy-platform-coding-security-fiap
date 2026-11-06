"""
Core - Coletor de Logs (reaproveitado do 1o semestre)
Le arquivos de log de diferentes fontes (auth, firewall, web), parseia
cada linha e normaliza os eventos em um formato padronizado de dicionario.

Formato padronizado de evento:
{
    "timestamp": "2025-02-20 08:15:01",
    "fonte": "auth",              # auth | firewall | web
    "tipo": "FAIL",               # OK | FAIL | BLOCK | ALLOW | GET | POST | DELETE
    "ip": "185.220.101.1",
    "detalhes": "usuario=admin",  # informacoes extras dependendo da fonte
    "linha_original": "..."       # linha crua do log
}
"""

import os


def parsear_linha_auth(linha):
    """Parseia uma linha do auth.log e retorna um dicionario normalizado."""
    if not linha or not linha.strip():
        return None

    partes = linha.strip().split()

    if len(partes) < 4:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]

    ip = None
    usuario = None

    for parte in partes[3:]:
        if parte.startswith("ip="):
            ip = parte.split("=", 1)[1]
        elif parte.startswith("usuario="):
            usuario = parte.split("=", 1)[1]

    if ip is None:
        return None

    detalhes = f"usuario={usuario}" if usuario else ""

    return {
        "timestamp": timestamp,
        "fonte": "auth",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def parsear_linha_firewall(linha):
    """Parseia uma linha do firewall.log e retorna um dicionario normalizado."""
    if not linha or not linha.strip():
        return None

    partes = linha.strip().split()

    if len(partes) < 4:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]

    ip = None
    proto = None
    dst = None
    dport = None

    for parte in partes[3:]:
        if parte.startswith("src="):
            ip = parte.split("=", 1)[1]
        elif parte.startswith("proto="):
            proto = parte.split("=", 1)[1]
        elif parte.startswith("dst="):
            dst = parte.split("=", 1)[1]
        elif parte.startswith("dport="):
            dport = parte.split("=", 1)[1]

    if ip is None:
        return None

    detalhes_partes = []
    if proto:
        detalhes_partes.append(f"proto={proto}")
    if dst:
        detalhes_partes.append(f"dst={dst}")
    if dport:
        detalhes_partes.append(f"dport={dport}")

    detalhes = " ".join(detalhes_partes)

    return {
        "timestamp": timestamp,
        "fonte": "firewall",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def parsear_linha_web(linha):
    """Parseia uma linha do web_access.log e retorna um dicionario normalizado."""
    if not linha or not linha.strip():
        return None

    partes = linha.strip().split()

    if len(partes) < 4:
        return None

    timestamp = partes[0] + " " + partes[1]
    tipo = partes[2]  # metodo HTTP

    ip = None
    url = None
    status = None

    for parte in partes[3:]:
        if parte.startswith("ip="):
            ip = parte.split("=", 1)[1]
        elif parte.startswith("url="):
            url = parte.split("=", 1)[1]
        elif parte.startswith("status="):
            status = parte.split("=", 1)[1]

    if ip is None:
        return None

    detalhes_partes = []
    if url:
        detalhes_partes.append(f"url={url}")
    if status:
        detalhes_partes.append(f"status={status}")

    detalhes = " ".join(detalhes_partes)

    return {
        "timestamp": timestamp,
        "fonte": "web",
        "tipo": tipo,
        "ip": ip,
        "detalhes": detalhes,
        "linha_original": linha.strip(),
    }


def carregar_log(caminho_arquivo, fonte):
    """Le um arquivo de log e retorna uma lista de eventos normalizados."""
    eventos = []

    parsers = {
        "auth": parsear_linha_auth,
        "firewall": parsear_linha_firewall,
        "web": parsear_linha_web,
    }

    parser = parsers.get(fonte)
    if parser is None:
        print(f"[ERRO] Fonte desconhecida: '{fonte}'")
        return []

    try:
        with open(caminho_arquivo, "r", encoding="utf-8") as f:
            for numero_linha, linha in enumerate(f, start=1):
                if not linha.strip():
                    continue

                evento = parser(linha)

                if evento is None:
                    print(f"[AVISO] Linha mal formatada em '{caminho_arquivo}' (linha {numero_linha}): {linha.strip()}")
                    continue

                eventos.append(evento)

    except FileNotFoundError:
        print(f"[ERRO] Arquivo nao encontrado: '{caminho_arquivo}'")
        return []

    return eventos


def carregar_todos_os_logs(pasta_logs):
    """Le todos os arquivos de log da pasta e retorna uma lista unificada de eventos."""
    todos_eventos = []

    try:
        arquivos = os.listdir(pasta_logs)
    except FileNotFoundError:
        print(f"[ERRO] Pasta nao encontrada: '{pasta_logs}'")
        return []

    for arquivo in sorted(arquivos):
        if not arquivo.endswith(".log"):
            continue

        if "auth" in arquivo:
            fonte = "auth"
        elif "firewall" in arquivo:
            fonte = "firewall"
        elif "web" in arquivo:
            fonte = "web"
        else:
            print(f"[AVISO] Fonte nao identificada para o arquivo '{arquivo}', pulando.")
            continue

        caminho_completo = os.path.join(pasta_logs, arquivo)
        eventos = carregar_log(caminho_completo, fonte)

        print(f"[INFO] {len(eventos)} eventos carregados de '{arquivo}'")
        todos_eventos.extend(eventos)

    return todos_eventos
