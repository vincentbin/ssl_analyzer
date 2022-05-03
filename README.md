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
