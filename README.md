# ssl_analyzer
A ssl analyzer which could analyzer target domain's certificate.

Analyze the domain name ssl certificate information according to the input csv file (the csv file path can be entered in the configuration section), and write the detailed information into the mysql database. After the container starts, users can connect to mysql through the mysql client to view the analysis results (The startup demo video is shown below).

## Get start
1. git clone https://github.com/vincentbin/ssl_analyzer.git
2. cd ssl_analyzer
3. docker-compose up --build

### Configurations (optional)
- analyzer.conf
```Properties
[script]
# Use multi-thread or not
multi_thread=True
# The number of threads used by the task
thread_num=20
# The location of hosts csv file
hosts_csv_filename=./data/top-1m.csv
# The amount of hosts user want to analyze (Set to 0 to analyze all csv content)
analyze_num=120000
```

### Database connection info
- username: root
- password: 123456

### Running process is shown in the video below.

https://user-images.githubusercontent.com/17155788/166204713-74a30b28-65e2-4f70-98bb-142672ee7c05.mp4

## Code structure
```
.
├── analysis
│   ├── analysis_data.sql       // SQL statement for data analysis
│   ├── analysis_data_v2.ipynb  // Statistical analysis of the result data collected by the system
├── data
│   ├── cacert.pem              // Root certificate information
│   ├── certificate_table.csv   // Database storage results csv export file
│   ├── top-1m.csv              // Input domain name file (this file can be customized to specify the domain names you want to analyze)
├── db
│   ├── certificateTable.sql    // MySQL table design SQL for storing certificate details
│   ├── creatDB.sql             // Mysql build database SQL for container init
│   ├── init.sql                // Mysql container initialization SQL
│   ├── utf8mb4.cnf             // Mysql configuration settings
│   ├── Dockerfile              // Mysql Dockerfile
├── conf_reader.py              // Get analyzer.conf file's configuration information
├── crl_checker.py              // CRL check related code
├── db.py                       // Database related operation code
├── ssl_analyzer.py             // Code related to requesting domain name acquisition and parsing certificate information
├── requirements.txt            // Project dependencies
├── Dockerfile                  // Python script container
├── docker-compose.yml          // Configuration file for starting db & script containers
├── Dockerfile                  // Python script container
├── LICENSE                     // LICENSE
├── README                      // README
```
