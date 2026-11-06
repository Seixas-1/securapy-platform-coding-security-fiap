"""
Core - Detector de Anomalias
Analisa o conjunto de eventos para identificar padroes de ataque que so
ficam visiveis quando multiplos eventos sao correlacionados.

Detecta:
- Brute Force: muitas tentativas de login falhas do mesmo IP
- Port Scan: mesmo IP tentando acessar muitas portas distintas
- IPs em Blacklist: IPs conhecidamente maliciosos presentes nos logs
"""


def _extrair_campo(detalhes, chave):
    if not detalhes:
        return None
    for parte in detalhes.split():
        if parte.startswith(f"{chave}="):
            return parte.split("=", 1)[1]
    return None


def detectar_brute_force(eventos, threshold=5):
    """Identifica IPs com muitas tentativas de login falhas."""
    contagem = {}
    usuarios = {}

    for evento in eventos:
        if evento.get("fonte") != "auth" or evento.get("tipo") != "FAIL":
            continue

        ip = evento.get("ip")
        contagem[ip] = contagem.get(ip, 0) + 1

        usuario = _extrair_campo(evento.get("detalhes", ""), "usuario")
        usuarios.setdefault(ip, set())
        if usuario:
            usuarios[ip].add(usuario)

    resultado = {}
    for ip, tentativas in contagem.items():
        if tentativas < threshold:
            continue

        if tentativas > 20:
            severidade = "CRITICA"
        elif tentativas > 10:
            severidade = "ALTA"
        elif tentativas > 5:
            severidade = "MEDIA"
        else:
            severidade = "BAIXA"

        resultado[ip] = {
            "tentativas": tentativas,
            "usuarios": usuarios.get(ip, set()),
            "severidade": severidade,
        }

    return resultado


def detectar_port_scan(eventos, threshold=3):
    """Identifica IPs que tentaram acessar muitas portas distintas."""
    portas_por_ip = {}

    for evento in eventos:
        if evento.get("fonte") != "firewall" or evento.get("tipo") != "BLOCK":
            continue

        ip = evento.get("ip")
        porta = _extrair_campo(evento.get("detalhes", ""), "dport")
        if porta is None:
            continue

        portas_por_ip.setdefault(ip, set())
        portas_por_ip[ip].add(porta)

    resultado = {}
    for ip, portas in portas_por_ip.items():
        quantidade = len(portas)
        if quantidade < threshold:
            continue

        if quantidade > 10:
            severidade = "CRITICA"
        elif quantidade > 5:
            severidade = "ALTA"
        else:
            severidade = "MEDIA"

        resultado[ip] = {
            "portas": portas,
            "quantidade": quantidade,
            "severidade": severidade,
        }

    return resultado


def verificar_blacklist(eventos, blacklist):
    """Cruza os IPs encontrados nos eventos com uma blacklist conhecida."""
    ips_eventos = {evento["ip"] for evento in eventos if evento.get("ip")}
    ips_encontrados = ips_eventos & set(blacklist)

    contagem_por_ip = {}
    for evento in eventos:
        ip = evento.get("ip")
        if ip in ips_encontrados:
            contagem_por_ip[ip] = contagem_por_ip.get(ip, 0) + 1

    return ips_encontrados, contagem_por_ip


def gerar_resumo_ameacas(brute_force, port_scan, blacklist_resultado):
    """Consolida todas as deteccoes em um resumo unificado de ameacas."""
    ips_blacklist, contagem_blacklist = blacklist_resultado

    # Preserva a ordem de primeira aparicao (nao usa set de strings direto,
    # cuja ordem de iteracao nao e deterministica) para que, em caso de
    # empate na pontuacao, o IP detectado primeiro fique antes no resultado.
    todos_ips = list(dict.fromkeys(
        list(brute_force.keys()) + list(port_scan.keys()) + list(ips_blacklist)
    ))

    resumo = []
    for ip in todos_ips:
        deteccoes = []
        pontuacao = 0
        detalhes = {}

        if ip in brute_force:
            deteccoes.append("brute_force")
            pontuacao += 5
            detalhes["brute_force"] = brute_force[ip]

        if ip in port_scan:
            deteccoes.append("port_scan")
            pontuacao += 5
            detalhes["port_scan"] = port_scan[ip]

        if ip in ips_blacklist:
            deteccoes.append("blacklist")
            pontuacao += 5
            detalhes["blacklist"] = {"eventos": contagem_blacklist.get(ip, 0)}

        resumo.append({
            "ip": ip,
            "deteccoes": deteccoes,
            "pontuacao": pontuacao,
            "severidade": _classificar_severidade_pontuacao(pontuacao),
            "detalhes": detalhes,
        })

    return sorted(resumo, key=lambda ameaca: ameaca["pontuacao"], reverse=True)


def _classificar_severidade_pontuacao(pontuacao):
    if pontuacao >= 15:
        return "CRITICA"
    elif pontuacao >= 10:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    else:
        return "BAIXA"
