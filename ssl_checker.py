#!/usr/bin/env python3
import socket
import sys
import json
from argparse import ArgumentParser, SUPPRESS
from datetime import datetime
from ssl import PROTOCOL_TLSv1
from time import sleep
from csv import DictWriter
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
        self.errno = 0

    def callback(self, connection, cert, errno, depth, result):
        self.connection = connection
        self.errno = errno
        self.depth = depth
        self.result = result
        return result


class SSLChecker:
    total_valid = 0
    total_expired = 0
    total_failed = 0
    total_warning = 0

    def __init__(self):
        self.cafile = "./cacert.pem"
        self.verify = VerifyCallback()
        self.table_keys = ['host', 'open443', 'error', 'ssl_error', 'cert_ver', 'cert_alg', 'issuer_c', 'issuer_o',
                           'pub_key_type', 'pub_key_bits', 'cert_exp', 'valid_from', 'valid_till', 'validity_days',
                           'days_left', 'ocsp_status', 'ocsp_error', 'crl_status', 'crl_reason']
        # db conn
        self.db_connection = get_connection()

    def get_cert(self, host, port, user_args):
        """Connection to the host."""
        if user_args.socks:
            import socks
            if user_args.verbose:
                print('{}Socks proxy enabled{}\n'.format(Clr.YELLOW, Clr.RST))

            socks_host, socks_port = self.filter_hostname(user_args.socks)
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, socks_host, int(socks_port), True)
            socket.socket = socks.socksocket

        if user_args.verbose:
            print('{}Connecting to socket{}\n'.format(Clr.YELLOW, Clr.RST))

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
        if user_args.verbose:
            print('{}Closing socket{}\n'.format(Clr.YELLOW, Clr.RST))

        return cert

    def border_msg(self, message):
        """Print the message in the box."""
        row = len(message)
        h = ''.join(['+'] + ['-' * row] + ['+'])
        result = h + '\n' "|" + message + "|"'\n' + h
        print(result)

    def analyze_ssl(self, host, context, user_args):
        """Analyze the security of the SSL certificate."""
        try:
            from urllib.request import urlopen
        except ImportError:
            print('import err.')

        api_url = 'https://api.ssllabs.com/api/v3/'
        while True:
            if user_args.verbose:
                print('{}Requesting analyze to {}{}\n'.format(Clr.YELLOW, api_url, Clr.RST))

            main_request = json.loads(urlopen(api_url + 'analyze?host={}'.format(host)).read().decode('utf-8'))
            if main_request['status'] in ('DNS', 'IN_PROGRESS'):
                if user_args.verbose:
                    print('{}Analyze waiting for reports to be finished (5 secs){}\n'.format(Clr.YELLOW, Clr.RST))

                sleep(5)
                continue
            elif main_request['status'] == 'READY':
                if user_args.verbose:
                    print('{}Analyze is ready{}\n'.format(Clr.YELLOW, Clr.RST))

                break

        endpoint_data = json.loads(urlopen(api_url + 'getEndpointData?host={}&s={}'.format(
            host, main_request['endpoints'][0]['ipAddress'])).read().decode('utf-8'))

        if user_args.verbose:
            print('{}Analyze report message: {}{}\n'.format(Clr.YELLOW, endpoint_data['statusMessage'], Clr.RST))

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
        # context['host'] = host
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
            context['crl_reason'] = crl_status[1]

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

    def show_result(self, user_args):
        """Get the context."""
        context = {}
        start_time = datetime.now()
        hosts = user_args.hosts

        if not user_args.json_true and not user_args.summary_true:
            self.border_msg(' Analyzing {} host(s) '.format(len(hosts)))

        for host in hosts:
            if user_args.verbose:
                print('{}Working on host: {}{}\n'.format(Clr.YELLOW, host, Clr.RST))
            # Check duplication
            # if host in context.keys():
            #     continue

            sub_context = dict.fromkeys(self.table_keys, 'null')
            sub_context['host'] = host
            try:
                # check if 443 port open
                port = 443
                is_open = self.check_port_open(host, port)
                if not is_open:
                    sub_context['open443'] = False  # it means the host did not open 443 port
                else:
                    sub_context['open443'] = True
                    cert = self.get_cert(host, port, user_args)
                    self.get_cert_info(host, sub_context, cert)
                    # sub_context['tcp_port'] = int(port)
                    # use ssllabs api to analysis ssl
                    # context = self.analyze_ssl(host, context, user_args)
            except SSL.SysCallError:
                sub_context['error'] = 'Failed: Misconfiguration SSL/TLS'
            except Exception as error:
                sub_context['error'] = str(error)
                print('\t{}[-]{} {:<20s} Failed: {}\n'.format(Clr.RED, Clr.RST, host, error))
            except KeyboardInterrupt:
                print('{}Canceling script...{}\n'.format(Clr.YELLOW, Clr.RST))
                sys.exit(1)

            sub_context['ssl_error'] = self.verify.errno
            context[host] = sub_context
            self.print_status(context, host)

            # insert data to database
            insert_list = self.get_status_list(host, context)
            insert_data(self.db_connection, insert_list)

        if not user_args.json_true:
            self.border_msg(
                ' Successful: {} | Failed: {} | Valid: {} | Warning: {} | Expired: {} | Duration: {} '.format(
                    len(hosts) - self.total_failed, self.total_failed, self.total_valid,
                    self.total_warning, self.total_expired, datetime.now() - start_time))
            if user_args.summary_true:
                # Exit the script just
                return
        self.export_res(user_args, context)

    def export_csv(self, context, filename, user_args):
        """Export all context results to CSV file."""
        # prepend dict keys to write column headers
        if user_args.verbose:
            print('{}Generating CSV export{}\n'.format(Clr.YELLOW, Clr.RST))

        with open(filename, 'w') as csv_file:
            csv_writer = DictWriter(csv_file, list(context.items())[0][1].keys())
            csv_writer.writeheader()
            for host in context.keys():
                csv_writer.writerow(context[host])

    def export_html(self, context):
        """Export JSON to HTML."""
        html = json2html.convert(json=context)
        file_name = datetime.strftime(datetime.now(), '%Y_%m_%d_%H_%M_%S')
        with open('{}.html'.format(file_name), 'w') as html_file:
            html_file.write(html)

        return

    def check_port_open(self, host, port):
        is_open = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                conn = sock.connect_ex((host, port))
                if (conn != 0):
                    is_open = False
            except Exception as err:
                raise err
        return is_open

    def filter_hostname(self, host):
        """Remove unused characters and split by address and port."""
        host = host.replace('http://', '').replace('https://', '').replace('/', '')
        port = 443
        if ':' in host:
            host, port = host.split(':')

        return host, port

    def get_args(self, json_args={}):
        """Set argparse options."""
        parser = ArgumentParser(prog='ssl_checker.py', add_help=False,
                                description="""Collects useful information about given host's SSL certificates.""")

        if len(json_args) > 0:
            args = parser.parse_args()
            setattr(args, 'json_true', True)
            setattr(args, 'verbose', False)
            setattr(args, 'csv_enabled', False)
            setattr(args, 'html_true', False)
            setattr(args, 'json_save_true', False)
            setattr(args, 'socks', False)
            setattr(args, 'analyze', False)
            setattr(args, 'hosts', json_args['hosts'])
            return args

        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-H', '--host', dest='hosts', nargs='*',
                           required=False, help='Hosts as input separated by space')
        group.add_argument('-f', '--host-file', dest='host_file',
                           required=False, help='Hosts as input from file')
        parser.add_argument('-s', '--socks', dest='socks',
                            default=False, metavar='HOST:PORT',
                            help='Enable SOCKS proxy for connection')
        parser.add_argument('-c', '--csv', dest='csv_enabled',
                            default=False, metavar='FILENAME.CSV',
                            help='Enable CSV file export')
        parser.add_argument('-j', '--json', dest='json_true',
                            action='store_true', default=False,
                            help='Enable JSON in the output')
        parser.add_argument('-S', '--summary', dest='summary_true',
                            action='store_true', default=False,
                            help='Enable summary output only')
        parser.add_argument('-x', '--html', dest='html_true',
                            action='store_true', default=False,
                            help='Enable HTML file export')
        parser.add_argument('-J', '--json-save', dest='json_save_true',
                            action='store_true', default=False,
                            help='Enable JSON export individually per host')
        parser.add_argument('-a', '--analyze', dest='analyze',
                            default=False, action='store_true',
                            help='Enable SSL security analysis on the host')
        parser.add_argument('-v', '--verbose', dest='verbose',
                            default=False, action='store_true',
                            help='Enable verbose to see what is going on')
        parser.add_argument('-h', '--help', default=SUPPRESS,
                            action='help',
                            help='Show this help message and exit')

        args = parser.parse_args()

        # Get hosts from file if provided
        if args.host_file:
            with open(args.host_file) as f:
                args.hosts = f.read().splitlines()

        # Checks hosts list
        if isinstance(args.hosts, list):
            if len(args.hosts) == 0:
                parser.print_help()
                sys.exit(0)

        return args

    def export_res(self, user_args, context):
        # CSV export if -c/--csv is specified
        if user_args.csv_enabled:
            self.export_csv(context, user_args.csv_enabled, user_args)

        # HTML export if -x/--html is specified
        if user_args.html_true:
            self.export_html(context)

        # While using the script as a module
        if __name__ != '__main__':
            return json.dumps(context)

        # Enable JSON output if -j/--json argument specified
        if user_args.json_true:
            print(json.dumps(context))

        if user_args.json_save_true:
            for host in context.keys():
                with open(host + '.json', 'w', encoding='UTF-8') as fp:
                    fp.write(json.dumps(context[host]))


def csv_reader(f_name, divide_size=1):
    """
    read csv
    :param f_name: file name
    :param divide_size:
    :return: domain list
    """
    import csv
    print('start to read csv.')
    ret = []
    sites_count = 100000 / divide_size
    f = csv.reader(open(f_name, 'r'))
    for no in range(divide_size):
        temp = []
        for i in range(int(sites_count)):
            line = next(f)
            temp.append(line[1])
        ret.append(temp)
    return ret


if __name__ == '__main__':
    thread_num = 10
    hosts = csv_reader('top-1m.csv', thread_num)
    SSLChecker = SSLChecker()
    # args = {
    #     # 'hosts': hosts
    #     'hosts': ['expired.badssl.com', 'revoked.badssl.com', 'google.com']
    # }
    import threading
    for item in hosts:
        t = threading.Thread(target=SSLChecker.show_result, args=(SSLChecker.get_args(json_args={'hosts': item}),))
        t.setDaemon(False)
        t.start()

    # SSLChecker.show_result(SSLChecker.get_args(json_args=args))
    close_connection(SSLChecker.db_connection)
