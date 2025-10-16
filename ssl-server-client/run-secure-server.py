import socket
import ssl
import threading


def run_secure_server(host='127.0.0.1', port=12345, certfile='server.crt', keyfile='server.key'):
    # Create a TCP/IP socket
    bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bindsocket.bind((host, port))
    bindsocket.listen(5)
    print(f"Secure server listening on {host}:{port}")

    # Configure SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)

    while True:
        try:
            # Accept a new connection
            newsocket, fromaddr = bindsocket.accept()
            print(f"Connection from {fromaddr}")

            # Wrap the socket with SSL
            connstream = context.wrap_socket(newsocket, server_side=True)
            print("SSL/TLS handshake completed with client.")

            # Receive data from the client
            data = connstream.recv(1024)
            print(f"Received from client: {data.decode()}")

            # Send a response to the client
            connstream.sendall(b"Hello from secure server!")

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            # Clean up the connection
            connstream.shutdown(socket.SHUT_RDWR)
            connstream.close()

if __name__ == '__main__':
    #server_thread = threading.Thread(target=run_secure_server, args=('127.0.0.1', 12345, 'server.crt', 'server.key')               daemon=True)
    #server_thread.start()

    run_secure_server('127.0.0.1', 12345, 'server.crt', 'server.key')
