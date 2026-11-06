"""
Gera um relatorio de exemplo (saida/relatorio_exemplo.json) rodando o
pipeline completo do nucleo sobre os logs de teste, sem depender do
MongoDB - util como entregavel de demonstracao da GS.

Rodar com: python -m scripts.gerar_relatorio_exemplo
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.coletor import carregar_todos_os_logs
from core.detector import detectar_brute_force, detectar_port_scan, gerar_resumo_ameacas, verificar_blacklist
from core.regras import aplicar_regras, carregar_regras
from core.relatorios import exportar_relatorio_json, resumo_por_fonte, resumo_por_severidade, top_ips
from ml.classificar import ModeloInvalidoError, pontuar_ip

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLACKLIST = {"185.220.101.1", "45.33.32.156", "91.240.118.172", "23.94.5.100"}


def main():
    eventos = carregar_todos_os_logs(os.path.join(BASE_DIR, "logs"))
    regras = carregar_regras(os.path.join(BASE_DIR, "config", "regras.json"))
    alertas = aplicar_regras(eventos, regras)

    brute = detectar_brute_force(eventos)
    scan = detectar_port_scan(eventos)
    bl = verificar_blacklist(eventos, BLACKLIST)
    ameacas = gerar_resumo_ameacas(brute, scan, bl)

    for ameaca in ameacas:
        try:
            resultado_ml = pontuar_ip(eventos, ameaca["ip"], BLACKLIST)
            ameaca["score_ml"] = resultado_ml["score"]
            ameaca["rotulo_ml"] = resultado_ml["rotulo"]
        except ModeloInvalidoError:
            ameaca["score_ml"] = None
            ameaca["rotulo_ml"] = "modelo_indisponivel"

    relatorio = {
        "total_eventos": len(eventos),
        "total_alertas": len(alertas),
        "eventos_por_fonte": resumo_por_fonte(eventos),
        "alertas_por_severidade": resumo_por_severidade(alertas),
        "top_10_ips": top_ips(eventos, 10),
        "ameacas": ameacas,
        "alertas": alertas,
    }

    caminho = os.path.join(BASE_DIR, "saida", "relatorio_exemplo.json")
    exportar_relatorio_json(relatorio, caminho)


if __name__ == "__main__":
    main()
