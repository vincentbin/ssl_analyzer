# ssl_analyzer
a ssl analyzer which could analyzer target domain's certificate.

## Get start
1. git clone https://github.com/vincentbin/ssl_analyzer.git
2. cd db
3. docker build -t mysql_ssl -f ./Dockerfile-db
4. docker run -p 3306:3306 --name mysql -e MYSQL_ROOT_PASSWORD=123456 -d mysql_ssl
5. python ../ssl_checker.py