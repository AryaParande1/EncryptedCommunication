"""Generate a self-signed TLS certificate for local development."""

from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from config import SERVER_HOST, TLS_CERT_FILE, TLS_KEY_FILE, initialize_directories


def generate_certificate() -> None:
    initialize_directories()

    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, SERVER_HOST)]
    )
    sans = [x509.DNSName("localhost")]
    try:
        sans.append(x509.IPAddress(ip_address(SERVER_HOST)))
    except ValueError:
        sans.append(x509.DNSName(SERVER_HOST))

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    TLS_KEY_FILE.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    TLS_CERT_FILE.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    print(f"Created TLS certificate: {TLS_CERT_FILE}")
    print(f"Created private key:     {TLS_KEY_FILE}")


if __name__ == "__main__":
    generate_certificate()
