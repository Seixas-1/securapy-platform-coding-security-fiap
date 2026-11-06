"""
Core - Enriquecimento de IPs
Adiciona contexto geografico e organizacional aos IPs suspeitos consultando
a API publica do ipinfo.io. Classifica IPs em privados (rede interna) e
publicos, e consulta apenas os publicos para economizar requisicoes.

Formato do resultado de enriquecimento:
{
    "ip": "185.220.101.1",
    "privado": False,
    "cidade": "Frankfurt am Main",
    "regiao": "Hesse",
    "pais": "DE",
    "org": "AS208294 Fastethernet",
    "hostname": "tor-exit.r2"
}
"""

import requests

TIMEOUT_SEGUNDOS = 5


def eh_ip_privado(ip):
    """Verifica se um endereco IP pertence a uma faixa de rede privada (RFC 1918)."""
    try:
        octetos = [int(x) for x in ip.split(".")]
    except (ValueError, AttributeError):
        return False

    if len(octetos) != 4:
        return False

    primeiro, segundo = octetos[0], octetos[1]

    if primeiro == 10:
        return True
    if primeiro == 172 and 16 <= segundo <= 31:
        return True
    if primeiro == 192 and segundo == 168:
        return True
    if primeiro == 127:
        return True

    return False


def _resultado_rede_interna(ip):
    return {
        "ip": ip,
        "privado": True,
        "cidade": "Rede Interna",
        "regiao": "Rede Interna",
        "pais": "Rede Interna",
        "org": "Rede Interna",
        "hostname": "Rede Interna",
    }


def _resultado_desconhecido(ip):
    return {
        "ip": ip,
        "privado": False,
        "cidade": "Desconhecido",
        "regiao": "Desconhecido",
        "pais": "Desconhecido",
        "org": "Desconhecido",
        "hostname": "Desconhecido",
    }


def consultar_ip(ip, cache):
    """Consulta a API do ipinfo.io para obter informacoes de geolocalizacao."""
    if ip in cache:
        return cache[ip]

    if eh_ip_privado(ip):
        resultado = _resultado_rede_interna(ip)
        cache[ip] = resultado
        return resultado

    try:
        resposta = requests.get(f"https://ipinfo.io/{ip}/json", timeout=TIMEOUT_SEGUNDOS)
        if resposta.status_code != 200:
            resultado = _resultado_desconhecido(ip)
            cache[ip] = resultado
            return resultado

        dados = resposta.json()
        resultado = {
            "ip": dados.get("ip", ip),
            "privado": False,
            "cidade": dados.get("city", "Desconhecido"),
            "regiao": dados.get("region", "Desconhecido"),
            "pais": dados.get("country", "Desconhecido"),
            "org": dados.get("org", "Desconhecido"),
            "hostname": dados.get("hostname", "Desconhecido"),
        }
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        resultado = _resultado_desconhecido(ip)
    except (ValueError, requests.exceptions.JSONDecodeError):
        resultado = _resultado_desconhecido(ip)

    cache[ip] = resultado
    return resultado


def enriquecer_alertas(alertas, cache):
    """Adiciona informacoes de geolocalizacao a uma lista de alertas."""
    if not alertas:
        return []

    ips_unicos = {alerta["ip"] for alerta in alertas if alerta.get("ip")}
    for ip in ips_unicos:
        consultar_ip(ip, cache)

    resultado = []
    for alerta in alertas:
        novo_alerta = dict(alerta)
        ip = alerta.get("ip")
        novo_alerta["geolocalizacao"] = cache.get(ip, _resultado_desconhecido(ip))
        resultado.append(novo_alerta)

    return resultado


def exibir_enriquecimento(dados_ip):
    """Exibe as informacoes de um IP de forma formatada no terminal."""
    tipo = "Privado (Rede Interna)" if dados_ip.get("privado") else "Publico"
    print(f"{'IP:':<15} {dados_ip.get('ip')}")
    print(f"{'Tipo:':<15} {tipo}")
    print(f"{'Cidade:':<15} {dados_ip.get('cidade')}")
    print(f"{'Regiao:':<15} {dados_ip.get('regiao')}")
    print(f"{'Pais:':<15} {dados_ip.get('pais')}")
    print(f"{'Organizacao:':<15} {dados_ip.get('org')}")
