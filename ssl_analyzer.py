#!/usr/bin/env python3
import socket
import sys
import json
from datetime import datetime
from ssl import PROTOCOL_TLSv1
from time import sleep
from ocspchecker import ocspchecker
from crl_check import check_crl, CRLStatus
from db import get_connection, insert_data, close_connection

try:
    from OpenSSL import SSL, crypto
    from json2html import *
except ImportError:
    print('Please install required modules: pip install -r requirements.txt')
    sys.exit(1)


class Clr:
    """Text colors."""

    RST = '\033[39m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'


print('ssl_analyzer_start')


class VerifyCallback:
    def __init__(self):
        self.connection = None
        self.err_no = 0
        self.depth = None
        self.result = None

    def callback(self, connection, cert, err_no, depth, result):
        self.connection = connection
        self.err_no = err_no
        self.depth = depth
        self.result = result
        return result


class SSLChecker:
    total_valid = 0
    total_expired = 0
    total_failed = 0
    total_warning = 0

    def __init__(self):
        self.cafile = "./data/cacert.pem"
        self.verify = VerifyCallback()
        self.table_keys = ['host', 'open443', 'error', 'ssl_error', 'cert_ver', 'cert_alg', 'issuer_c', 'issuer_o',
                           'pub_key_type', 'pub_key_bits', 'cert_exp', 'valid_from', 'valid_till', 'validity_days',
                           'days_left', 'ocsp_status', 'ocsp_error', 'crl_status', 'crl_reason']
        # db conn
        self.db_connection = get_connection()

    def get_cert(self, host, port):
        """Connection to the host."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        ssl_context = SSL.Context(PROTOCOL_TLSv1)
        ssl_context.load_verify_locations(self.cafile)
        ssl_context.set_verify(SSL.VERIFY_PEER, self.verify.callback)

        sock.connect((host, int(port)))
        ssl_connection = SSL.Connection(ssl_context, sock)
        ssl_connection.set_tlsext_host_name(host.encode())
        ssl_connection.set_connect_state()
        ssl_connection.do_handshake()
        cert = ssl_connection.get_peer_certificate()

        sock.close()
        return cert

    def analyze_ssl(self, host, context):
        """Analyze the security of the SSL certificate."""
        try:
            from urllib.request import urlopen
        except ImportError:
            print('import err.')

        api_url = 'https://api.ssllabs.com/api/v3/'
        while True:
            main_request = json.loads(urlopen(api_url + 'analyze?host={}'.format(host)).read().decode('utf-8'))
            if main_request['status'] in ('DNS', 'IN_PROGRESS'):
                sleep(5)
                continue
            elif main_request['status'] == 'READY':
                break

        endpoint_data = json.loads(urlopen(api_url + 'getEndpointData?host={}&s={}'.format(
            host, main_request['endpoints'][0]['ipAddress'])).read().decode('utf-8'))

        # if the certificate is invalid
        if endpoint_data['statusMessage'] == 'Certificate not valid for domain name':
            return context

        context[host]['grade'] = main_request['endpoints'][0]['grade']
        context[host]['poodle_vuln'] = endpoint_data['details']['poodle']
        context[host]['heartbleed_vuln'] = endpoint_data['details']['heartbleed']
        context[host]['heartbeat_vuln'] = endpoint_data['details']['heartbeat']
        context[host]['freak_vuln'] = endpoint_data['details']['freak']
        context[host]['logjam_vuln'] = endpoint_data['details']['logjam']
        context[host]['drownVulnerable'] = endpoint_data['details']['drownVulnerable']

        return context

    def get_cert_sans(self, x509cert):
        """
        Get Subject Alt Names from Certificate. Shameless taken from stack overflow:
        https://stackoverflow.com/users/4547691/anatolii-chmykhalo
        """
        san = ''
        ext_count = x509cert.get_extension_count()
        for i in range(0, ext_count):
            ext = x509cert.get_extension(i)
            if 'subjectAltName' in str(ext.get_short_name()):
                san = ext.__str__()
        # replace commas to not break csv output
        san = san.replace(',', ';')
        return san

    def get_cert_info(self, host, context, cert):
        """Get all the information about cert and create a JSON file."""
        # context = {}
        context['cert_ver'] = cert.get_version()  # Version Number v1/v2/v3
        context['cert_sn'] = str(cert.get_serial_number())  # Serial Number
        context['cert_alg'] = cert.get_signature_algorithm().decode()  # Signature Algorithm
        # Issuer Name C=country name;O=OrganizationName;CN=common name
        cert_issuer = cert.get_issuer()
        context['issuer_c'] = cert_issuer.countryName
        context['issuer_o'] = cert_issuer.organizationName
        context['issuer_ou'] = cert_issuer.organizationalUnitName
        context['issuer_cn'] = cert_issuer.commonName
        # Subject Name
        cert_subject = cert.get_subject()
        context['issued_to'] = cert_subject.CN
        context['issued_o'] = cert_subject.O

        context['cert_sha1'] = cert.digest('sha1').decode()
        # context['cert_sans'] = self.get_cert_sans(cert)  # X509v3 Subject Alternative Name in Extensions
        pub = cert.get_pubkey()
        context['pub_key_type'] = pub.type()
        context['pub_key_bits'] = pub.bits()

        context['cert_exp'] = cert.has_expired()
        context['cert_valid'] = False if cert.has_expired() else True
        # Valid period
        valid_from = datetime.strptime(cert.get_notBefore().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_from'] = valid_from.strftime('%Y-%m-%d')
        valid_till = datetime.strptime(cert.get_notAfter().decode('ascii'),
                                       '%Y%m%d%H%M%SZ')
        context['valid_till'] = valid_till.strftime('%Y-%m-%d')

        # Validity days
        context['validity_days'] = (valid_till - valid_from).days

        # Validity in days from now
        now = datetime.now()
        context['days_left'] = (valid_till - now).days

        # Valid days left
        context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'],
                                                             '%Y-%m-%d') - datetime.now()).days
        if cert.has_expired():
            self.total_expired += 1
        else:
            self.total_valid += 1
        # If the certificate has less than 15 days validity
        if context['valid_days_to_expire'] <= 15:
            self.total_warning += 1

        status = ocspchecker.get_ocsp_status(host)
        status_len = len(status)
        if status_len == 2:
            context['ocsp_error'] = status[1]
        elif status_len == 3:
            context['ocsp_status'] = status[2].split(": ")[1]

        # since crl check is time-consuming, we just check it when ocsp fail or ocsp get revoked status
        crl_status = check_crl(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        context['crl_status'] = str(crl_status[0])
        if crl_status[0] is not CRLStatus.GOOD:
            tmp_str = crl_status[1]
            context['crl_reason'] = tmp_str[:250] # limit the string length to avoid database error

        return context

    def print_status(self, context, host):
        """Print all the usefull info about host."""
        print('\t{}[+]{} {}\n\t{}'.format(Clr.GREEN, Clr.RST, host, '-' * (len(host) + 5)))
        for key, value in context[host].items():
            print('\t\t', key, ': ', value)
        print('\n')

    def get_status_list(self, host, context):
        """
        obtain detail ssl info
        :param host: host to check
        :param context: raw res
        :return: list
        """
        ret = []
        for key in self.table_keys:
            ret.append(context[host][key])
        return ret

    def show_result(self, args):
        """Get the context."""
        context = {}
        hosts = args['hosts']

        for host in hosts:
            sub_context = dict.fromkeys(self.table_keys, 'null')
            sub_context['host'] = host
            try:
                # check if 443 port open
                port = 443
                is_open, update_host = self.check_port_open(host, port)
                if not is_open:
                    sub_context['open443'] = False  # it means the host did not open 443 port
                else:
                    sub_context['open443'] = True
                    if update_host:
                        host = 'www.' + host
                        sub_context['host'] = host
                # even port not open, still try to get cert
                cert = self.get_cert(host, port)
                self.get_cert_info(host, sub_context, cert)
            # except SSL.SysCallError:
            #     sub_context['error'] = 'Failed: Misconfiguration SSL/TLS'
            except Exception as error:
                sub_context['error'] = str(error)
                print('\t{}[-]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))
            except KeyboardInterrupt:
                print('{}Canceling script...{}\n'.format(Clr.YELLOW, Clr.RST))
                sys.exit(1)

            sub_context['ssl_error'] = str(self.verify.err_no)
            context[host] = sub_context
            self.print_status(context, host)

            # insert data to database
            insert_list = self.get_status_list(host, context)
            insert_data(self.db_connection, insert_list)

        close_connection(self.db_connection)

    def check_port_open(self, host, port):
        is_open = True
        is_success = True
        should_update_host = False
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                conn = sock.connect_ex((host, port))
                if (conn != 0):
                    is_success = False
            except Exception as err:
                is_success = False
                pass

            if not is_success:
                try:
                    host = 'www.' + host
                    conn = sock.connect_ex((host, port))
                    if conn != 0:
                        is_open = False
                    else:
                        should_update_host = True
                except Exception as err:
                    raise err
        return is_open, should_update_host


def csv_reader(f_name, divide_size=1, total_num=120000):
    """
    read csv
    :param total_num: nums want to analyze
    :param f_name: file name
    :param divide_size:
    :return: domain list
    """
    import csv
    print('start to read csv.')
    ret = []
    sites_count = total_num / divide_size
    f = csv.reader(open(f_name, 'r'))
    for no in range(divide_size):
        temp = []
        for i in range(int(sites_count)):
            line = next(f)
            temp.append(line[1])
        ret.append(temp)
    return ret


def checker_with_thread(thread_num=20):
    hosts = csv_reader('./data/top-1m.csv', thread_num)
    import threading
    for item in hosts:
        checker = SSLChecker()
        t = threading.Thread(target=checker.show_result, args=({'hosts': item},))
        t.setDaemon(False)
        t.start()


def checker_without_thread():
    hosts = csv_reader('./data/top-1m.csv')
    checker = SSLChecker()
    args = {
        'hosts': hosts[0]
        # 'hosts': ['hexun.com', 'expired.badssl.com', 'revoked.badssl.com', 'google.com']
    }
    checker.show_result(args)


if __name__ == '__main__':
    use_threads = True
    if use_threads:
        checker_with_thread()
    else:
        checker_without_thread()
