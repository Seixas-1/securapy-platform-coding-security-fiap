"""
Modulo F - Verificacao dos containers via Docker SDK (docker-py)
Confirma que os 3 servicos da plataforma (api, mongo, mysql) subiram
e estao no estado "running". Rodar com: python -m scripts.verificar_docker
"""

import sys

import docker

SERVICOS_ESPERADOS = ["securapy_api", "securapy_mongo", "securapy_mysql"]


def verificar_containers():
    """Retorna dict {nome_container: status} para os servicos esperados."""
    cliente = docker.from_env()
    status = {}

    for nome in SERVICOS_ESPERADOS:
        try:
            container = cliente.containers.get(nome)
            status[nome] = container.status
        except docker.errors.NotFound:
            status[nome] = "nao encontrado"

    return status


def main():
    try:
        status = verificar_containers()
    except docker.errors.DockerException as erro:
        print(f"[ERRO] Nao foi possivel conectar ao Docker: {erro}")
        sys.exit(1)

    print("=" * 45)
    print("  Status dos containers do SecuraPy Platform")
    print("=" * 45)

    todos_rodando = True
    for nome, estado in status.items():
        marcador = "OK" if estado == "running" else "FALHA"
        print(f"  [{marcador}] {nome:<20} -> {estado}")
        if estado != "running":
            todos_rodando = False

    print("=" * 45)
    if todos_rodando:
        print("Todos os servicos estao rodando.")
        sys.exit(0)
    else:
        print("Um ou mais servicos nao estao rodando.")
        sys.exit(1)


if __name__ == "__main__":
    main()
