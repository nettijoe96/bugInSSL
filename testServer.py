import socket
import ssl
import localSystemVariables

def createServerSideSocket(port, backlog=5):
    context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="mycert.pem", keyfile="mykey.pem")
    context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF #also could be VERIFY_CRL_CHECK_CHAIN
    context.load_verify_locations(cafile=localSystemVariables.CRL)

    sock = socket.socket()
    sock.bind(('', port))
    sock.listen(backlog)

    return sock, context

def acceptSocket(sock, context):

    newSocket, fromAddr = sock.accept()
    connStream = context.wrap_socket(newSocket, server_side=True)
    try:
        print("data received:")
        print(bytes.decode(sock.recv(1024)))
    finally:
        try:
            connStream.shutdown(socket.SHUT_RDWR)
        except OSError as e:
            pass
        connStream.close()


port = 5000

sock, context = createServerSideSocket(port)
print('socket has been created')

try:
    acceptSocket(sock, context)
    print('accepted')
except Exception as e:
    print(e)
