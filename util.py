from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
import OpenSSL

def loadCert_Cryptography(data):
    cert = x509.load_pem_x509_certificate(data, default_backend())
    return cert


def loadPrivKeyCryptography(bytes, password=None):
    """
    load the private key from a bytes (it is already loaded from file)
    """
    private_key = serialization.load_pem_private_key(bytes, password, backend=default_backend())
    return private_key


def loadPrivKeyOpenSSL(fileType, pubBytes, passphrase=None):
    pk = OpenSSL.crypto.load_privatekey(fileType, pubBytes, passphrase)
    return pk


def loadCSRFile(filename):
    """
    loading the CSR DN information from a preset file in order to make a CSR object.
    """
    csrDict = {}
    with open(filename) as f:
        for line in f:
            if line.startswith('#'):
                continue
            elif line == '':
                continue
            ele = line.split('=')
            csrDict[ele[0]] = ele[1].strip('\n')
    return csrDict

def loadCSR_Cryptography(data):
    """
    load CSR object from cryptography library from bytes
    :param data: csr bytes
    :return: csr object
    """
    csr = x509.load_pem_x509_csr(data, default_backend())
    return csr