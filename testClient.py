"""
I comment too
"""

import ssl
import socket
import localSystemVariables

def createClientSideSocket(server_ip):
    '''Create an SSL-wrapped socket for client-side use.

    The client is the device that temporarily connects to the server to request or send data.  This function creates an SSLSocket that can be
    connected to the address of the desired server.

    @param server_ip The hostname (IP address) of the server to connect to
    @returns SSLSocket
    '''
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile="cacert.pem")
    context.verify_flags = ssl.VERIFY_CRL_CHECK_LEAF
    context.load_verify_locations("crl.pem")
    conn = context.wrap_socket(socket.socket(), server_hostname=server_ip)
    return conn

conn = createClientSideSocket(localSystemVariables.myIP)
conn.connect((localSystemVariables.myIP, 5000))
conn.sendall(str.encode("test data"))

