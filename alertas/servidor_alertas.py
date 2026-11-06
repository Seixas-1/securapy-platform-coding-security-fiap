"""
Tempo Real - Servidor de Alertas (reaproveitado e completado do 1o semestre)
Servidor TCP que aceita conexoes de multiplos clientes (consoles de
monitoramento) e faz broadcast de alertas de seguranca para todos os
clientes conectados.

Comandos suportados pelo cliente:
    /status    - mostra quantos clientes conectados e alertas na sessao
    /historico - envia os ultimos 10 alertas
    /sair      - desconecta do servidor
"""

import socket
import threading

# Configuracao
HOST = "0.0.0.0"
PORTA = 9999
MAX_CLIENTES = 10

# Estado global do servidor
clientes = {}       # {conexao: endereco}
lock = threading.Lock()
historico_alertas = []


def formatar_alerta(alerta_dict):
    """Converte um dicionario de alerta em string formatada para exibicao."""
    timestamp = alerta_dict.get("timestamp", "")
    hora = timestamp.split(" ")[-1] if timestamp else "??:??:??"
    severidade = alerta_dict.get("severidade", "INFO")
    nome = alerta_dict.get("regra_nome", "Alerta")
    ip = alerta_dict.get("ip", "?")
    descricao = alerta_dict.get("descricao", "")

    return f"[{hora}] [{severidade}] {nome} - {ip} - {descricao}"


def broadcast_alerta(alerta):
    """Envia um alerta para todos os clientes conectados."""
    if isinstance(alerta, dict):
        mensagem = formatar_alerta(alerta)
    else:
        mensagem = str(alerta)

    with lock:
        historico_alertas.append(mensagem)
        desconectados = []
        for conexao in list(clientes.keys()):
            try:
                conexao.send((mensagem + "\n").encode())
            except (OSError, ConnectionError):
                desconectados.append(conexao)

        for conexao in desconectados:
            clientes.pop(conexao, None)
            try:
                conexao.close()
            except Exception:
                pass


def remover_cliente(conexao):
    """Remove um cliente da lista de conectados."""
    with lock:
        endereco = clientes.pop(conexao, None)

    try:
        conexao.close()
    except Exception:
        pass

    if endereco:
        print(f"[INFO] Cliente desconectado: {endereco}")


def tratar_cliente(conexao, endereco):
    """Gerencia a comunicacao com um cliente individual (thread por cliente)."""
    with lock:
        clientes[conexao] = endereco

    print(f"[INFO] Novo cliente conectado: {endereco}")

    try:
        conexao.send("Bem-vindo ao SecuraPy - Servidor de Alertas\n".encode())
    except OSError:
        remover_cliente(conexao)
        return

    try:
        while True:
            dados = conexao.recv(1024).decode()
            if not dados:
                break

            comando = dados.strip()

            if comando == "/status":
                with lock:
                    n_clientes = len(clientes)
                    n_alertas = len(historico_alertas)
                resposta = f"[STATUS] {n_clientes} cliente(s) conectado(s), {n_alertas} alerta(s) na sessao\n"
                conexao.send(resposta.encode())

            elif comando == "/historico":
                with lock:
                    ultimos = historico_alertas[-10:]
                if ultimos:
                    resposta = "\n".join(ultimos) + "\n"
                else:
                    resposta = "[HISTORICO] Nenhum alerta registrado ainda\n"
                conexao.send(resposta.encode())

            elif comando == "/sair":
                conexao.send("Encerrando conexao. Ate logo!\n".encode())
                break

    except (ConnectionResetError, ConnectionAbortedError, OSError):
        pass
    finally:
        remover_cliente(conexao)


def iniciar_servidor(host=HOST, porta=PORTA):
    """Inicia o servidor TCP de alertas."""
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((host, porta))
    servidor.listen(MAX_CLIENTES)

    print(f"[INFO] Servidor de alertas escutando em {host}:{porta}")

    try:
        while True:
            conexao, endereco = servidor.accept()
            thread = threading.Thread(target=tratar_cliente, args=(conexao, endereco), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[INFO] Encerrando servidor de alertas...")
    finally:
        servidor.close()


if __name__ == "__main__":
    iniciar_servidor()
