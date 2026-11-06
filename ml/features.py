"""
ML - Extracao de Features por IP
Reduz a lista de eventos de um IP a um vetor numerico de features,
usado tanto para treinar o classificador quanto para pontuar IPs novos.

Features:
    num_fails        - tentativas de login falhas (auth/FAIL)
    num_portas       - portas distintas bloqueadas pelo firewall (BLOCK)
    em_blacklist      - 1 se o IP esta na blacklist conhecida, 0 caso contrario
    num_web_erros     - requisicoes web com status de erro (4xx/5xx)
"""


def _extrair_campo(detalhes, chave):
    if not detalhes:
        return None
    for parte in detalhes.split():
        if parte.startswith(f"{chave}="):
            return parte.split("=", 1)[1]
    return None


def extrair_features_ip(eventos, ip, blacklist=None):
    """Calcula o vetor de features de um IP a partir da lista de eventos."""
    blacklist = blacklist or set()

    num_fails = 0
    portas = set()
    num_web_erros = 0

    for evento in eventos:
        if evento.get("ip") != ip:
            continue

        if evento.get("fonte") == "auth" and evento.get("tipo") == "FAIL":
            num_fails += 1

        elif evento.get("fonte") == "firewall" and evento.get("tipo") == "BLOCK":
            porta = _extrair_campo(evento.get("detalhes", ""), "dport")
            if porta:
                portas.add(porta)

        elif evento.get("fonte") == "web":
            status = _extrair_campo(evento.get("detalhes", ""), "status")
            if status and status.isdigit() and int(status) >= 400:
                num_web_erros += 1

    return {
        "num_fails": num_fails,
        "num_portas": len(portas),
        "em_blacklist": 1 if ip in blacklist else 0,
        "num_web_erros": num_web_erros,
    }


def ips_unicos(eventos):
    """Lista todos os IPs unicos presentes nos eventos."""
    return sorted({evento["ip"] for evento in eventos if evento.get("ip")})


ORDEM_FEATURES = ["num_fails", "num_portas", "em_blacklist", "num_web_erros"]


def features_para_vetor(features_dict):
    """Converte o dict de features para a lista ordenada usada pelo modelo."""
    return [features_dict[chave] for chave in ORDEM_FEATURES]
