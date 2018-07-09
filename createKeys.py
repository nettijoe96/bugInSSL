from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
import cryptography.hazmat.primitives.serialization as serialization
import util
import OpenSSL
import localSystemVariables
from cryptography import x509
import datetime
from cryptography.hazmat.primitives import hashes
import os

def generateCSR(privkey, myIP):
    # if there is a password, that is the 3rd arg
    req = OpenSSL.crypto.X509Req()

    #before adding data, get it from preset file
    req.get_subject().C = "US"
    req.get_subject().ST = "MA"
    req.get_subject().L = "Boston"
    req.get_subject().O = "Org"
    req.get_subject().OU = "Dept"
    req.get_subject().CN = localSystemVariables.myIP
    req.set_pubkey(privkey)
    req.sign(privkey, "sha256")
    ftype = OpenSSL.crypto.FILETYPE_PEM
    csr = OpenSSL.crypto.dump_certificate_request(ftype, req)
    return csr

def generateCACert():
    with open("cakey.pem", 'rb') as f: privKey = f.read()
    privKeyCryptography = util.loadPrivKeyCryptography(privKey)
    privKeyOpenSSL = util.loadPrivKeyOpenSSL(OpenSSL.crypto.FILETYPE_PEM, privKey)
    csr = generateCSR(privKeyOpenSSL, localSystemVariables.myIP)
    csr = util.loadCSR_Cryptography(csr)
    subject = csr.subject

    keyUsageExt = x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False)

    cert = x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(subject) \
        .public_key(csr.public_key()) \
        .serial_number(x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .add_extension(keyUsageExt, critical=True) \
        .sign(privKeyCryptography, hashes.SHA256(), default_backend())

    with open("cacert.pem", 'wb') as f: f.write(cert.public_bytes(serialization.Encoding.PEM))

    return cert

def generateMyCert(certname, IP):
    with open("mykey.pem", 'rb') as f: privKey = f.read()
    privKeyOpenSSL = util.loadPrivKeyOpenSSL(OpenSSL.crypto.FILETYPE_PEM, privKey)
    csr = generateCSR(privKeyOpenSSL, IP)
    with open("csr.pem", 'wb') as f: f.write(csr)
    os.system("sh sign.sh " + certname)

myKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
with open("mykey.pem", "wb") as f: f.write(myKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
myKey = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
with open("cakey.pem", "wb") as f: f.write(myKey.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.TraditionalOpenSSL, encryption_algorithm=serialization.NoEncryption()))
generateCACert()
generateMyCert("mycert.pem", localSystemVariables.myIP)
generateMyCert("revokeCert.pem", "8.8.8.8")

