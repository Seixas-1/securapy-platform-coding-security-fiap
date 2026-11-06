"""
ML - Classificacao e Priorizacao de Risco
Carrega o modelo treinado (verificando o hash de integridade) e atribui
a cada IP suspeito um score de risco, usado para ordenar os alertas.
"""

import hashlib
import os

import joblib

from ml.features import extrair_features_ip, features_para_vetor

CAMINHO_MODELO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo.pkl")
CAMINHO_HASH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo.sha256")

_modelo_cache = None


class ModeloInvalidoError(Exception):
    """Levantado quando o hash do modelo nao confere com o arquivo .pkl."""


def verificar_integridade_modelo(caminho_modelo=CAMINHO_MODELO, caminho_hash=CAMINHO_HASH):
    """Confere se o hash SHA-256 do modelo salvo ainda corresponde ao arquivo."""
    if not os.path.exists(caminho_modelo) or not os.path.exists(caminho_hash):
        return False, None

    hash_atual = hashlib.sha256(open(caminho_modelo, "rb").read()).hexdigest()
    hash_esperado = open(caminho_hash).read().strip()
    return hash_atual == hash_esperado, hash_atual


def carregar_modelo(forcar_recarregar=False):
    """Carrega o modelo treinado, verificando a integridade antes de usar."""
    global _modelo_cache

    if _modelo_cache is not None and not forcar_recarregar:
        return _modelo_cache

    valido, hash_atual = verificar_integridade_modelo()
    if not valido:
        if hash_atual is None:
            raise ModeloInvalidoError(
                "Modelo nao encontrado. Rode 'python -m ml.treinar' primeiro."
            )
        raise ModeloInvalidoError(
            f"Hash do modelo nao confere (esperado != {hash_atual}). "
            "O arquivo modelo.pkl pode ter sido alterado ou corrompido."
        )

    dados = joblib.load(CAMINHO_MODELO)
    _modelo_cache = dados
    return dados


def pontuar_ip(eventos, ip, blacklist=None):
    """
    Calcula o score de risco (0-100) e o rotulo (ataque/normal) de um IP.

    Retorna dict: {"ip", "score", "rotulo", "features"}
    """
    dados_modelo = carregar_modelo()
    pipeline = dados_modelo["pipeline"]

    features = extrair_features_ip(eventos, ip, blacklist)
    vetor = [features_para_vetor(features)]

    probabilidade_ataque = float(pipeline.predict_proba(vetor)[0][1])
    rotulo = "ataque" if probabilidade_ataque >= 0.5 else "normal"

    return {
        "ip": ip,
        "score": round(probabilidade_ataque * 100, 1),
        "rotulo": rotulo,
        "features": features,
    }


def pontuar_ameacas(ameacas, eventos, blacklist=None):
    """Adiciona o score de ML a cada ameaca do resumo do detector e reordena."""
    for ameaca in ameacas:
        resultado = pontuar_ip(eventos, ameaca["ip"], blacklist)
        ameaca["score_ml"] = resultado["score"]
        ameaca["rotulo_ml"] = resultado["rotulo"]

    return sorted(ameacas, key=lambda a: a.get("score_ml", 0), reverse=True)


def detectar_anomalias(eventos, ips=None, blacklist=None, contaminacao=0.15):
    """
    Bonus - Deteccao de anomalias com Isolation Forest sobre as features
    de trafego, para achar padroes fora do esperado sem depender de rotulo.
    """
    from sklearn.ensemble import IsolationForest
    from ml.features import ips_unicos, ORDEM_FEATURES

    ips = ips or ips_unicos(eventos)
    if len(ips) < 2:
        return []

    matriz = [features_para_vetor(extrair_features_ip(eventos, ip, blacklist)) for ip in ips]

    modelo = IsolationForest(contamination=contaminacao, random_state=42)
    previsoes = modelo.fit_predict(matriz)  # -1 = anomalia, 1 = normal

    resultado = []
    for ip, vetor, previsao in zip(ips, matriz, previsoes):
        if previsao == -1:
            resultado.append({
                "ip": ip,
                "anomalia": True,
                "features": dict(zip(ORDEM_FEATURES, vetor)),
            })
    return resultado
