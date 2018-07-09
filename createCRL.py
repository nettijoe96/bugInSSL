from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import cryptography.x509.extensions as extensions
import datetime
from cryptography.hazmat.primitives import hashes
import util

CACERT = "cacert.pem"
CAKEY = "cakey.pem"


def addToCRL(revokeObj, crlBuilder):
    """
     Adds a cert to the crl but does not sign crl
    """
    crlBuilder = crlBuilder.add_revoked_certificate(revokeObj)
    return crlBuilder


def finalizeCRL(crlBuilder, cakey):
    """
    signs a CRL
    """
    crl = crlBuilder.sign(private_key=cakey, algorithm=hashes.SHA256(), backend=default_backend())
    return crl


def genCRLBuilder(cacert):
    """
    Generates a new unsigned crl with no revocations in it
    """
    issuer = cacert.subject
    one_day = datetime.timedelta(1, 0, 0)
    builder = x509.CertificateRevocationListBuilder()
    builder = builder.issuer_name(issuer)
    builder = builder.last_update(datetime.datetime.today())
    builder = builder.next_update(datetime.datetime.today() + one_day)
    return builder


"""
revoke a certificate and return a revoked certificate object
"""
def generateRevocation(certFileName, reasonFlag):
    #load certificate to get serial
    with open(certFileName, "rb") as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data, default_backend())
    serial = cert.serial_number

    builder = x509.RevokedCertificateBuilder()
    #set time/date as current time/date
    builder = builder.revocation_date(datetime.datetime.today())
    #set CRL reason extension
    reason = x509.CRLReason(reasonFlag)
    builder = builder.add_extension(reason, critical=True)
    builder = builder.serial_number(serial)
    revoked_certificate = builder.build(default_backend())
    return revoked_certificate


def createCRL(withRevocation, revokeCertName=None):

    with open(CAKEY, "rb") as f: key = f.read()
    with open(CACERT, "rb") as f: cert = f.read()

    cacert = util.loadCert_Cryptography(cert)
    cakey = util.loadPrivKeyCryptography(key)
    crlBuilder = genCRLBuilder(cacert)
    if withRevocation:
        revokeObj = generateRevocation(revokeCertName, extensions.ReasonFlags.unspecified)
        crlBuilder = addToCRL(revokeObj, crlBuilder)
    crl = finalizeCRL(crlBuilder, cakey)
    return crl


if __name__ == "__main__":
    crl = createCRL(True, revokeCertName="revokeCert.pem")
    with open("crlWithRevocation.pem", "wb") as f: f.write(crl.public_bytes(serialization.Encoding.PEM))
    crl = createCRL(False)
    with open("crlEmpty.pem", "wb") as f: f.write(crl.public_bytes(serialization.Encoding.PEM))
