import os
import socket

HOST = os.environ["VPN_IP"] or '127.0.0.1'
PORT = 5000

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    print(f"Python echo server is listening on {HOST}:{PORT}")
    s.listen()

    while True:
        print(f"Waiting for connection on {HOST}:{PORT}")
        conn, addr = s.accept()
        print(f"Connection accepted from {addr}")
        with conn:
            while True:
                data = conn.recv(1024)
                if not data:
                    print("No data received, closing connection")
                    break
                conn.sendall(f"This is a response from Python echo server on {HOST} to the message \n  >> {data.decode('utf-8')}".encode('utf-8'))
