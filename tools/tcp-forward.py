"""Прозрачный TCP-форвардер для проверки восстановления связи.

Слушает 127.0.0.1:<listen> и проксирует на 127.0.0.1:<target>. Нужен, чтобы
имитировать «служба осциллографа пропала и вернулась», не трогая настоящий
DaVinci: логгер смотрит на форвардер, а тот — на 7411.

    python build/tcp-forward.py 7412 7411
"""
import socket
import sys
import threading

stop = threading.Event()


def pump(src, dst):
    try:
        while not stop.is_set():
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


def handle(client):
    try:
        upstream = socket.create_connection(("127.0.0.1", target), timeout=3)
    except OSError:
        client.close()
        return
    threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
    threading.Thread(target=pump, args=(upstream, client), daemon=True).start()


if __name__ == "__main__":
    listen, target = int(sys.argv[1]), int(sys.argv[2])
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", listen))
    server.listen(16)
    print(f"forward 127.0.0.1:{listen} -> {target}", flush=True)
    try:
        while True:
            client, _ = server.accept()
            threading.Thread(target=handle, args=(client,), daemon=True).start()
    except KeyboardInterrupt:
        stop.set()
