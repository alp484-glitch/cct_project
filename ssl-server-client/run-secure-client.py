import socket
import ssl
import time


def run_secure_client(host='127.0.0.1', port=12345, cafile='server.crt'):
    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Configure SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=cafile)
    context.check_hostname = False  # Disable hostname checking for localhost
    context.verify_mode = ssl.CERT_REQUIRED

    # Wrap the socket with SSL
    conn = context.wrap_socket(sock, server_hostname=host)

    try:
        # Connect to the server
        conn.connect((host, port))
        print("SSL/TLS handshake completed with server.")

        # Send data to the server
        conn.sendall(b"Hello from secure client!")

        # Receive a response from the server
        data = conn.recv(1024)
        print(f"Received from server: {data.decode()}")

    except ssl.SSLError as e:
        print(f"SSL error: {e}")
    except Exception as e:
        print(f"Connection error: {e}")
    finally:
        # Clean up the connection
        conn.close()

if __name__ == "__main__":
    time.sleep(1)  # Wait for the server to start
    # Run the secure client
    run_secure_client('127.0.0.1', 12345, 'server.crt')