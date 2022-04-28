import threading
import time
import pymysql
import ssl_analyzer


def init_test_conn():
    # connect database
    try:
        connection = pymysql.connect(host="127.0.0.1", user='root', password='123456', port=3306, charset='utf8')
    except Exception as e:
        return
    # create database and table
    with connection:
        with connection.cursor() as cursor:
            sql_create_db = 'CREATE DATABASE IF NOT EXISTS TestDB'
            cursor.execute(sql_create_db)
        connection.commit()
    connection = pymysql.connect(host="127.0.0.1", user='root', password='123456', port=3306, charset='utf8',
                                 db='TestDB')
    with connection:
        with connection.cursor() as cursor:
            sql_create_table = """CREATE TABLE IF NOT EXISTS certificate
                                    (
                                        id                    int auto_increment
                                            primary key,
                                        host                  varchar(256) not null,
                                        open443               varchar(256) null,
                                        error                 varchar(256) null,
                                        ssl_error             varchar(256) null,
                                        certificate_version   varchar(10)  null,
                                        certificate_algorithm varchar(256) null,
                                        issuer_country        varchar(256) null,
                                        issued_organization   varchar(256) null,
                                        public_key_type       varchar(256) null,
                                        public_key_bits       varchar(256) null,
                                        expired               varchar(256) null,
                                        valid_from            varchar(256) null,
                                        valid_to              varchar(256) null,
                                        validity_days         varchar(256) null,
                                        valid_days_left       varchar(256) null,
                                        ocsp_status           varchar(256) null,
                                        ocsp_error            varchar(256) null,
                                        crl_status            varchar(256) null,
                                        crl_reason            varchar(256) null
                                    ) default character set utf8 collate utf8_general_ci;"""
            cursor.execute(sql_create_table)
        connection.commit()


def get_test_connection():
    """
    get db conn
    :return: conn
    """
    while True:
        try:
            conn = pymysql.connect(
                host='127.0.0.1',
                port=3306,
                user='root',
                password='123456',
                database='TestDB',
                charset='utf8')
            return conn
        except Exception as e:
            print('wait for db.')
            time.sleep(2)


if __name__ == "__main__":
    init_test_conn()
    hosts = ssl_analyzer.csv_reader('top-1m.csv', divide_size=50, total_num=100)
    for item in hosts:
        checker = ssl_analyzer.SSLChecker()
        checker.db_connection = get_test_connection()
        t = threading.Thread(target=checker.show_result, args=(checker.get_args(json_args={'hosts': item}),))
        t.setDaemon(False)
        t.start()
