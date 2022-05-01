desc certificate;

SELECT open443,
	   COUNT(open443) AS num
FROM certificate
GROUP BY open443;

SELECT open443,error,ssl_error, COUNT(*) AS num
FROM certificate
GROUP BY open443,error,ssl_error
ORDER BY open443, num DESC;

SELECT error,COUNT(error) AS num
FROM certificate
WHERE NOT (error = 'null')
GROUP BY error
ORDER BY num DESC;

SELECT open443,error,COUNT(*) AS num
FROM certificate
WHERE NOT (error = 'null')
GROUP BY open443,error
ORDER BY open443,num DESC;

SELECT error, ssl_error,COUNT(*) AS num
FROM certificate
WHERE NOT (error = 'null')
GROUP BY error,ssl_error
ORDER BY ssl_error,num DESC;

SELECT ssl_error,COUNT(ssl_error) AS num
FROM certificate 
WHERE NOT (ssl_error = 'null' or ssl_error = '0')
GROUP BY ssl_error
ORDER BY num DESC;

SELECT issuer_country,
	   COUNT(issuer_country) AS num,
       COUNT(issuer_country)*100.0/(SELECT COUNT(*) 
                                    FROM certificate
                                    WHERE NOT (issued_organization = 'null')) AS percentage
FROM certificate
WHERE NOT (issuer_country = 'null')
GROUP BY issuer_country
ORDER BY num DESC
LIMIT 10;


SELECT issued_organization,
	   COUNT(issued_organization) AS num,
       COUNT(issued_organization)*100.0/(SELECT COUNT(*) 
                                         FROM certificate
                                         WHERE NOT (issued_organization = 'null')) AS percentage
FROM certificate
WHERE NOT (issued_organization = 'null')
GROUP BY issued_organization
ORDER BY num DESC
LIMIT 10;


SELECT certificate_algorithm,
	   COUNT(certificate_algorithm) AS num,
       COUNT(certificate_algorithm)*100.0/(SELECT COUNT(*) 
                                           FROM certificate 
                                           WHERE NOT (certificate_algorithm = 'null')) AS percentage
FROM certificate
WHERE NOT (certificate_algorithm = 'null')
GROUP BY certificate_algorithm
ORDER BY num DESC;

SELECT public_key_type,
	   public_key_bits,
	   COUNT(*) AS num,
       COUNT(*)*100.0/(SELECT COUNT(*) 
                                     FROM certificate 
                                     WHERE NOT (public_key_bits = 'null')) AS percentage
FROM certificate
WHERE NOT (public_key_bits = 'null')
GROUP BY public_key_type,public_key_bits
ORDER BY public_key_type DESC,num DESC;


SELECT expired,COUNT(expired) AS num
FROM certificate
GROUP BY expired
ORDER BY num DESC;

SELECT validity_days, COUNT(validity_days) AS num
FROM certificate
WHERE NOT (validity_days = 'null')
GROUP BY validity_days
ORDER BY num DESC;

SELECT crl_status, COUNT(crl_status) AS num
FROM certificate
WHERE NOT (crl_status = 'null')
GROUP BY crl_status
ORDER BY num DESC

SELECT crl_reason, COUNT(crl_reason) AS num
FROM certificate
WHERE NOT (crl_reason = 'null')
GROUP BY crl_reason
ORDER BY num DESC

SELECT ocsp_status, COUNT(ocsp_status) AS num
FROM certificate
WHERE NOT (ocsp_status = 'null')
GROUP BY ocsp_status
ORDER BY num DESC

SELECT ocsp_error, COUNT(ocsp_error) AS num
FROM certificate
WHERE NOT (ocsp_error = 'null')
GROUP BY ocsp_error
ORDER BY num DESC
desc certificate

SELECT open443,
	   COUNT(open443) AS num
FROM certificate
GROUP BY open443;

SELECT error,COUNT(error) AS num
FROM certificate
WHERE NOT (error = 'null')
GROUP BY error
ORDER BY num DESC;

SELECT ssl_error,COUNT(ssl_error) AS num
FROM certificate 
WHERE NOT (ssl_error = 'null' or ssl_error = '0')
GROUP BY ssl_error
ORDER BY num DESC;

SELECT issuer_country,
	   COUNT(issuer_country) AS num,
       COUNT(issuer_country)*100.0/(SELECT COUNT(*) 
                                    FROM certificate
                                    WHERE NOT (issued_organization = 'null')) AS percentage
FROM certificate
WHERE NOT (issuer_country = 'null')
GROUP BY issuer_country
ORDER BY num DESC;


SELECT issued_organization,
	   COUNT(issued_organization) AS num,
       COUNT(issued_organization)*100.0/(SELECT COUNT(*) 
                                         FROM certificate
                                         WHERE NOT (issued_organization = 'null')) AS percentage
FROM certificate
WHERE NOT (issued_organization = 'null')
GROUP BY issued_organization
ORDER BY num DESC;


SELECT certificate_algorithm,
	   COUNT(certificate_algorithm) AS num,
       COUNT(certificate_algorithm)*100.0/(SELECT COUNT(*) 
                                           FROM certificate 
                                           WHERE NOT (certificate_algorithm = 'null')) AS percentage
FROM certificate
WHERE NOT (certificate_algorithm = 'null')
GROUP BY certificate_algorithm
ORDER BY num DESC;

SELECT public_key_bits,
	   public_key_type,
	   COUNT(public_key_bits) AS num,
       COUNT(public_key_bits)*100.0/(SELECT COUNT(*) 
                                     FROM certificate 
                                     WHERE NOT (public_key_bits = 'null')) AS percentage
FROM certificate
WHERE NOT (public_key_bits = 'null')
GROUP BY public_key_bits
ORDER BY num DESC;


SELECT expired,COUNT(expired) AS num
FROM certificate
GROUP BY expired
ORDER BY num DESC;

SELECT validity_days, COUNT(validity_days) AS num
FROM certificate
WHERE NOT (validity_days = 'null')
GROUP BY validity_days
ORDER BY num DESC;

SELECT crl_status, COUNT(crl_status) AS num
FROM certificate
WHERE NOT (crl_status = 'null')
GROUP BY crl_status
ORDER BY num DESC

SELECT crl_reason, COUNT(crl_reason) AS num
FROM certificate
WHERE NOT (crl_reason = 'null')
GROUP BY crl_reason
ORDER BY num DESC

SELECT ocsp_status, COUNT(ocsp_status) AS num
FROM certificate
WHERE NOT (ocsp_status = 'null')
GROUP BY ocsp_status
ORDER BY num DESC

SELECT ocsp_error, COUNT(ocsp_error) AS num
FROM certificate
WHERE NOT (ocsp_error = 'null')
GROUP BY ocsp_error
ORDER BY num DESC
