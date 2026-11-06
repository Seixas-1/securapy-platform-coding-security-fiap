"""
Core - Motor de Regras
Carrega regras de deteccao de um arquivo JSON, avalia cada evento contra
as regras ativas e gera alertas quando uma regra eh violada.

Formato de um alerta gerado:
{
    "timestamp": "2025-02-20 08:15:01",
    "regra_id": "R001",
    "regra_nome": "Login com Usuario Privilegiado",
    "severidade": "MEDIA",
    "ip": "185.220.101.1",
    "descricao": "Tentativa de login com usuario admin"
}

Niveis de severidade (baseados na pontuacao):
    >= 9: CRITICA
    >= 7: ALTA
    >= 5: MEDIA
    >= 3: BAIXA
     < 3: INFO
"""

import json


def carregar_regras(caminho_config):
    """Le o arquivo regras.json e retorna a lista de regras ativas."""
    try:
        with open(caminho_config, "r", encoding="utf-8") as f:
            dados = json.load(f)
    except FileNotFoundError:
        print(f"[ERRO] Arquivo de regras nao encontrado: '{caminho_config}'")
        return []
    except json.JSONDecodeError:
        print(f"[ERRO] JSON invalido em: '{caminho_config}'")
        return []

    regras = dados.get("regras", [])
    return [r for r in regras if r.get("ativa", False)]


def classificar_severidade(pontuacao):
    """Converte uma pontuacao numerica em nivel de severidade."""
    if pontuacao >= 9:
        return "CRITICA"
    elif pontuacao >= 7:
        return "ALTA"
    elif pontuacao >= 5:
        return "MEDIA"
    elif pontuacao >= 3:
        return "BAIXA"
    else:
        return "INFO"


def _extrair_campo(detalhes, chave):
    """Extrai o valor de 'chave=valor' dentro da string de detalhes."""
    if not detalhes:
        return None
    for parte in detalhes.split():
        if parte.startswith(f"{chave}="):
            return parte.split("=", 1)[1]
    return None


def avaliar_regra(regra, evento):
    """Avalia se um evento viola uma regra especifica."""
    if regra.get("fonte") != evento.get("fonte"):
        return None

    condicao = regra.get("condicao")
    detalhes = evento.get("detalhes", "")
    disparou = False

    if condicao == "usuario_privilegiado":
        usuario = _extrair_campo(detalhes, "usuario")
        disparou = usuario is not None and usuario in regra.get("usuarios_alvo", [])

    elif condicao == "porta_critica":
        dport = _extrair_campo(detalhes, "dport")
        if dport is not None:
            try:
                disparou = int(dport) in regra.get("portas_criticas", [])
            except ValueError:
                disparou = False

    elif condicao == "path_traversal":
        url = _extrair_campo(detalhes, "url") or ""
        disparou = any(padrao in url for padrao in regra.get("padroes", []))

    elif condicao == "xss":
        url = _extrair_campo(detalhes, "url") or ""
        disparou = any(padrao in url for padrao in regra.get("padroes", []))

    elif condicao == "reconhecimento":
        url = _extrair_campo(detalhes, "url") or ""
        disparou = any(suspeita in url for suspeita in regra.get("urls_suspeitas", []))

    if not disparou:
        return None

    severidade = classificar_severidade(regra.get("severidade_base", 0))

    return {
        "timestamp": evento.get("timestamp"),
        "regra_id": regra.get("id"),
        "regra_nome": regra.get("nome"),
        "severidade": severidade,
        "ip": evento.get("ip"),
        "descricao": regra.get("descricao", regra.get("nome", "")),
    }


def aplicar_regras(eventos, regras):
    """Aplica todas as regras a todos os eventos e retorna os alertas gerados."""
    alertas = []
    for evento in eventos:
        for regra in regras:
            resultado = avaliar_regra(regra, evento)
            if resultado is not None:
                alertas.append(resultado)
    return alertas
