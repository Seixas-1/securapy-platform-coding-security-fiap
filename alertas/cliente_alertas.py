"""
Tempo Real - Cliente de Alertas (reaproveitado e completado do 1o semestre)
Conecta ao servidor de alertas e recebe notificacoes em tempo real.
Permite enviar comandos: /status, /historico, /sair
"""

import socket
import threading

HOST = "127.0.0.1"
PORTA = 9999


def receber_alertas(cliente):
    """Thread que fica ouvindo mensagens do servidor e exibindo no terminal."""
    while True:
        try:
            dados = cliente.recv(4096).decode()
            if not dados:
                print("\n[INFO] Servidor encerrou a conexao.")
                break
            print(dados.strip())
        except (ConnectionResetError, OSError):
            print("\n[INFO] Conexao com o servidor perdida.")
            break


def conectar_servidor(host=HOST, porta=PORTA):
    """Conecta ao servidor de alertas e inicia a interacao."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        cliente.connect((host, porta))
    except ConnectionRefusedError:
        print(f"[ERRO] Nao foi possivel conectar a {host}:{porta}. O servidor esta rodando?")
        return

    thread = threading.Thread(target=receber_alertas, args=(cliente,), daemon=True)
    thread.start()

    print("Conectado ao servidor de alertas do SecuraPy. Comandos: /status /historico /sair")

    try:
        while True:
            comando = input()
            if not comando:
                continue
            cliente.send(comando.encode())
            if comando.strip() == "/sair":
                break
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        cliente.close()


if __name__ == "__main__":
    conectar_servidor()
