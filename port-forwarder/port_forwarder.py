# Port Forwarder

# Import Socket
import socket

LISTENING_HOST = '127.0.0.1'
LISTENING_PORT = 9999

TARGET_HOST = '127.0.0.1'
TARGET_PORT = 8000

# Server Socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# AF_INET: IPv4
# SOCK_STREAM: TCP
# Bind the server to the local host and port
server.bind((LISTENING_HOST, LISTENING_PORT))
# Server listens for incoming connections
server.listen(5)

print(f'Listening on {LISTENING_HOST}:{LISTENING_PORT}')

# Accept incoming connections
client_socket, client_address = server.accept()
print(f'Accepted connection from {client_address}')

# Connect to the remote target
# Incoming Traffic: client_socket
# Outgoing Traffic: remote_socket
remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
remote_socket.connect((TARGET_HOST, TARGET_PORT))
print(f'Connected to remote target {TARGET_HOST}:{TARGET_PORT}')

# Receive the data from the client
data = client_socket.recv(4096)
print(f'Received {len(data)} bytes from client')
print(data[:100])  # Print the first 100 bytes of the data

remote_socket.sendall(data)

# Receive reply from the target
while True:
    response = remote_socket.recv(4096)
    
    if not response:
        break

    print(f'Received {len(response)} bytes from target')
    print(response[:100])  # Print the first 100 bytes of the response

    client_socket.sendall(response)

# Close the connections
client_socket.close()
remote_socket.close()
server.close()

