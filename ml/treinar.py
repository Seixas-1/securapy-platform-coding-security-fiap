"""
ML - Treinamento do Classificador de Risco
Extrai features dos eventos reais (logs/) e as combina com um dataset
sintetico gerado por regras conhecidas de ataque (poucos IPs reais nao
dao amostras suficientes para treinar/validar um modelo). Treina um
Pipeline (StandardScaler + LogisticRegression), avalia com validacao
cruzada e persiste o modelo com hash de integridade (SHA-256).

Rodar com: python -m ml.treinar
"""

import hashlib
import json
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_validate, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

from core.coletor import carregar_todos_os_logs
from ml.features import extrair_features_ip, ips_unicos, features_para_vetor, ORDEM_FEATURES

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_LOGS = os.path.join(BASE_DIR, "logs")
CAMINHO_MODELO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo.pkl")
CAMINHO_HASH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "modelo.sha256")
CAMINHO_METRICAS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metricas.json")

BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}

SEED = 42


def _rotular(num_fails, num_portas, em_blacklist, num_web_erros):
    """Regra de rotulagem: ataque se pelo menos 2 sinais fortes aparecerem."""
    sinais = 0
    if num_fails >= 5:
        sinais += 1
    if num_portas >= 3:
        sinais += 1
    if em_blacklist:
        sinais += 1
    if num_web_erros >= 3:
        sinais += 1
    return 1 if sinais >= 2 else 0


def _gerar_amostra_sintetica(rng, ataque):
    """Gera uma linha de features sintetica, coerente com o perfil pedido."""
    if ataque:
        num_fails = rng.randint(4, 30)
        num_portas = rng.randint(2, 15)
        em_blacklist = rng.choice([0, 1, 1])
        num_web_erros = rng.randint(0, 10)
    else:
        num_fails = rng.randint(0, 3)
        num_portas = rng.randint(0, 2)
        em_blacklist = 0
        num_web_erros = rng.randint(0, 2)

    rotulo = _rotular(num_fails, num_portas, em_blacklist, num_web_erros)
    return {
        "num_fails": num_fails,
        "num_portas": num_portas,
        "em_blacklist": em_blacklist,
        "num_web_erros": num_web_erros,
    }, rotulo


def montar_dataset(n_sinteticas=400):
    """Combina os IPs reais dos logs com amostras sinteticas rotuladas."""
    rng = random.Random(SEED)

    eventos = carregar_todos_os_logs(PASTA_LOGS)
    X, y = [], []

    for ip in ips_unicos(eventos):
        features = extrair_features_ip(eventos, ip, BLACKLIST)
        rotulo = _rotular(**features)
        X.append(features_para_vetor(features))
        y.append(rotulo)

    for _ in range(n_sinteticas):
        ataque = rng.random() < 0.5
        features, rotulo = _gerar_amostra_sintetica(rng, ataque)
        X.append(features_para_vetor(features))
        y.append(rotulo)

    return X, y


def treinar_e_avaliar():
    """Treina o Pipeline, avalia com validacao cruzada e persiste o modelo."""
    X, y = montar_dataset()

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("modelo", LogisticRegression(random_state=SEED, max_iter=1000)),
    ])

    resultado_cv = cross_validate(
        pipeline, X, y, cv=5,
        scoring=["precision", "recall", "f1"],
    )

    metricas = {
        "precisao_media": float(resultado_cv["test_precision"].mean()),
        "recall_medio": float(resultado_cv["test_recall"].mean()),
        "f1_medio": float(resultado_cv["test_f1"].mean()),
    }

    print("=" * 50)
    print("  Validacao cruzada (5 folds)")
    print("=" * 50)
    print(f"  Precisao : {metricas['precisao_media']:.3f}")
    print(f"  Recall   : {metricas['recall_medio']:.3f}")
    print(f"  F1-score : {metricas['f1_medio']:.3f}")

    X_treino, X_teste, y_treino, y_teste = train_test_split(
        X, y, test_size=0.25, random_state=SEED, stratify=y,
    )
    pipeline.fit(X_treino, y_treino)
    y_previsto = pipeline.predict(X_teste)

    relatorio = classification_report(y_teste, y_previsto, target_names=["normal", "ataque"])
    print("\n" + relatorio)

    # Treina a versao final com todos os dados disponiveis
    pipeline.fit(X, y)

    joblib.dump({"pipeline": pipeline, "features": ORDEM_FEATURES}, CAMINHO_MODELO)

    hash_modelo = hashlib.sha256(open(CAMINHO_MODELO, "rb").read()).hexdigest()
    with open(CAMINHO_HASH, "w") as f:
        f.write(hash_modelo)

    metricas["hash_sha256"] = hash_modelo
    metricas["relatorio_classificacao"] = relatorio
    with open(CAMINHO_METRICAS, "w", encoding="utf-8") as f:
        json.dump(metricas, f, indent=2, ensure_ascii=False)

    print(f"\n[INFO] Modelo salvo em: {CAMINHO_MODELO}")
    print(f"[INFO] Hash SHA-256: {hash_modelo}")

    return metricas


if __name__ == "__main__":
    treinar_e_avaliar()
