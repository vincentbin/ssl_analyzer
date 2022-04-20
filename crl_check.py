import enum
import requests
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID


class CRL_ERROR(Exception):
    pass


class CRLStatus(enum.Enum):
    GOOD = 0
    REVOKED = 1
    FAILED = 2


def check_crl(cert_pem):
    result = []
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)

        ext = cert.extensions

        crl_ex = ext.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS,
        )

        for dist_point in crl_ex.value:
            for full_name in dist_point.full_name:
                crl_url = full_name.value

                crl = _get_crl_from_url(crl_url)

                r = crl.get_revoked_certificate_by_serial_number(
                    cert.serial_number,
                )
                if r is not None:
                    result.append(CRLStatus.REVOKED)
                    err = f"Certificate with serial: {cert.serial_number} " \
                          f"is revoked since: {r.revocation_date}"
                    result.append(err)
                    break
        result.append(CRLStatus.GOOD)
    except ExtensionNotFound as e:
        result.append(CRLStatus.FAILED)
        result.append("CRL ERROR: {0}".format(e))
    except Exception as e:
        result.append(CRLStatus.FAILED)
        result.append("CRL ERROR: {0}".format(e))

    return result


def _get_crl_from_url(crl_url):
    ret = requests.get(crl_url)

    if ret.status_code != 200:
        raise CRL_ERROR("Unable to retrieve CRL:{0}".format(crl_url)) from None

    crl_data = ret.content

    return _crl_data_to_crypto(crl_data)


def _crl_data_to_crypto(crl_data):
    try:
        return x509.load_der_x509_crl(crl_data)
    except (TypeError, ValueError):
        pass

    try:
        return x509.load_pem_x509_crl(crl_data)
    except TypeError as e:
        raise CRL_ERROR(e) from None
