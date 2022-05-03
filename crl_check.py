import requests
from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import ExtensionOID


class CRL_ERROR(Exception):
    pass


class CRLStatus:
    GOOD = 'GOOD'
    REVOKED = 'REVOKED'
    FAILED = 'FAILED'


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

                rev = crl.get_revoked_certificate_by_serial_number(
                    cert.serial_number,
                )
                if rev is not None:
                    result.append(CRLStatus.REVOKED)
                    err = f"revoked since {rev.revocation_date}"
                    try:
                        r = rev.extensions.get_extension_for_class(x509.CRLReason)
                    except x509.ExtensionNotFound:
                        # Not all revoked certs have a reason extension.
                        pass
                    else:
                        err += str(r.value.reason)
                    # err = f"Certificate with serial: {cert.serial_number} " \
                    #       f"is revoked since: {rev.revocation_date}"
                    result.append(err)
                    break
        result.append(CRLStatus.GOOD)
    except ExtensionNotFound:
        result.append(CRLStatus.FAILED)
        result.append("CRL ERROR: Not Found CRL Extension")
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
