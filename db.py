import time
import pymysql


def get_connection():
    """
    get db conn
    :return: conn
    """
    while True:
        try:
            conn = pymysql.connect(
                host='db',
                # host='127.0.0.1',
                port=3306,
                user='root',
                password='123456',
                database='CertificateDB',
                charset='utf8')
            return conn
        except Exception as e:
            print('wait for db.')
            time.sleep(2)


def close_connection(conn):
    """
    close db conn
    :return: conn
    """
    conn.close()


def read_data(conn, limit):
    """
    obtain data
    :param limit: max_size
    :param conn: connection
    :return: data
    """
    cursor = conn.cursor()
    sql = """
        SELECT
            *
        FROM
            certificate
        LIMIT %s
    """
    try:
        cursor.execute(sql, limit)
        ret = cursor.fetchall()
        return ret
    except Exception as e:
        raise e
    finally:
        cursor.close()


def insert_data(conn, data):
    """
    insert to db
    :param conn: connection
    :param data:
    :return: None
    """
    cursor = conn.cursor()
    sql = """
            INSERT INTO
                certificate(   
                    host,
                    open443,
                    error,               
                    ssl_error,            
                    certificate_version,
                    certificate_algorithm,
                    issuer_country,
                    issued_organization,
                    public_key_type,
                    public_key_bits,
                    expired,                             
                    valid_from,               
                    valid_to,              
                    validity_days,
                    valid_days_left,            
                    ocsp_status,
                    crl_status,
                    crl_reason                  
                )
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    try:
        cursor.execute(sql, data)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(e)
    finally:
        cursor.close()


def batch_insert_data(conn, data):
    """
    insert to db
    :param conn: connection
    :param data: [(), (), (), ... ] tuple
    :return: None
    """
    cursor = conn.cursor()
    sql = """
            INSERT INTO
                certificate(     
                    host,              
                    issued_domain,            
                    issued_to,                
                    issued_by,                
                    valid_from,               
                    valid_to,              
                    validity_days,            
                    certificate_sn,           
                    certificate_version,      
                    certificate_algorithm,    
                    ocsp_status, 
                    expired                  
                )
            VALUES
                (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
    try:
        cursor.executemany(sql, data)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print(e)
    finally:
        cursor.close()
