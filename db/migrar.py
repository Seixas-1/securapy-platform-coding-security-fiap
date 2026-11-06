"""
DB - Script de Migracao / Ingestao Inicial
Le os logs via nucleo (core/), aplica regras e deteccao, e popula o
MongoDB com eventos e alertas. Rodar com: python -m db.migrar
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.coletor import carregar_todos_os_logs
from core.regras import carregar_regras, aplicar_regras
from core.detector import detectar_brute_force, detectar_port_scan, verificar_blacklist, gerar_resumo_ameacas
from db.mongo_repo import obter_db, criar_indices, salvar_eventos, salvar_alertas, limpar_colecoes

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASTA_LOGS = os.path.join(BASE_DIR, "logs")
ARQUIVO_REGRAS = os.path.join(BASE_DIR, "config", "regras.json")
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def migrar(limpar_antes=False):
    """Executa a ingestao completa: logs -> regras -> deteccao -> MongoDB."""
    db = obter_db()
    criar_indices(db)

    if limpar_antes:
        limpar_colecoes(db)

    eventos = carregar_todos_os_logs(PASTA_LOGS)
    regras = carregar_regras(ARQUIVO_REGRAS)
    alertas = aplicar_regras(eventos, regras)

    brute = detectar_brute_force(eventos)
    scan = detectar_port_scan(eventos)
    bl = verificar_blacklist(eventos, BLACKLIST)
    ameacas = gerar_resumo_ameacas(brute, scan, bl)

    n_eventos = salvar_eventos(eventos, db)
    n_alertas = salvar_alertas(alertas, db)

    print(f"[INFO] {n_eventos} eventos persistidos no MongoDB")
    print(f"[INFO] {n_alertas} alertas persistidos no MongoDB")
    print(f"[INFO] {len(ameacas)} IPs suspeitos no resumo de ameacas")

    return {
        "eventos": n_eventos,
        "alertas": n_alertas,
        "ameacas": ameacas,
    }


if __name__ == "__main__":
    migrar(limpar_antes="--limpar" in sys.argv)
