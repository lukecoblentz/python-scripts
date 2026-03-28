# Port Forwarder

# Import Socket
import socket
import threading

LISTENING_HOST = '127.0.0.1'
LISTENING_PORT = 9999

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8000

def relay(source, destination, direction):
    while True:
        data = source.recv(4096)

        if not data:
            break

        print(f'{direction}: received {len(data)} bytes')
        print(data[:100])  # Print the first 100 bytes of the data

        destination.sendall(data)

def handle_client(client_socket, client_address):
    print(f'Accepted connection from {client_address}')

    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((TARGET_HOST, TARGET_PORT))
    print(f'Connected to remote target {TARGET_HOST}:{TARGET_PORT}')
    client_to_target = threading.Thread(
    target=relay,
    args=(client_socket, remote_socket, 'Client -> Target')
    )

    target_to_client = threading.Thread(
    target=relay,
    args=(remote_socket, client_socket, 'Target -> Client')
    )
    
    client_to_target.start()
    target_to_client.start()

    client_to_target.join()
    target_to_client.join()

    client_socket.close()
    remote_socket.close()
    print(f'Closed connection from {client_address}')



# Server Socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# AF_INET: IPv4
# SOCK_STREAM: TCP
# Bind the server to the local host and port
server.bind((LISTENING_HOST, LISTENING_PORT))
# Server listens for incoming connections
server.listen(5)

print(f'Listening on {LISTENING_HOST}:{LISTENING_PORT}')
while True:
    # Accept a client connection
    client_socket, client_address = server.accept()

    # Handle the client connection in a new thread
    client_thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address)
    )
    client_thread.start()


