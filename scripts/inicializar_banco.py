"""
Script de inicializacao: cria as tabelas do MySQL, os indices do MongoDB
e um usuario administrador inicial (lido de variaveis de ambiente -
nunca hardcoded). Rodar uma vez apos o 'docker-compose up':

    docker compose exec api python -m scripts.inicializar_banco
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import mongo_repo, mysql_repo


def main():
    print("[INFO] Criando indices no MongoDB...")
    mongo_repo.criar_indices()

    print("[INFO] Criando tabelas no MySQL...")
    mysql_repo.criar_tabelas()

    email_admin = os.environ.get("ADMIN_EMAIL")
    senha_admin = os.environ.get("ADMIN_PASSWORD")

    if email_admin and senha_admin:
        ok, resultado = mysql_repo.criar_usuario(
            nome="Administrador", email=email_admin, senha=senha_admin, nivel_acesso=5,
        )
        if ok:
            print(f"[INFO] Usuario administrador criado (id={resultado})")
        else:
            print(f"[INFO] Usuario administrador ja existia ou nao pode ser criado: {resultado}")
    else:
        print("[AVISO] ADMIN_EMAIL/ADMIN_PASSWORD nao definidos - nenhum usuario inicial criado.")

    print("[INFO] Inicializacao concluida.")


if __name__ == "__main__":
    main()
