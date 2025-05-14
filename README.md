# To submit sample/dir to CAPE for analysis, use: 
`python3 submit.py --conf=cape-api.conf --path=path-to-sample-or-folder --report-suffix=suffix`
For example, to submit samples in /home/cape/data/samples, with the output folder /home/cape/sandboxes/cape-reports-test
`python3 submit.py --conf=cape-api.conf --path=/home/cape/data/samples --report-suffix=test`

# To report all the result, use: 
`python3 report.py --conf=cape-api.conf --report-suffix=suffix`
Note that the suffix is the same as the one use when submit.
For example, to report on the previous submitted samples: 
`python3 report.py --conf=cape-api.conf --report-suffix=test`
Then the report will be in [results] path (/home/cape/sandboxes/results/timestamp), extracted_result_raw.json

Note that if no report-suffix is specified, default folder cape-reports are used. 

# Default configuration file includes:
[reports]
path = /home/cape/sandboxes/cape-reports/

[cape]
api = http://192.168.122.1:8000/apiv2

storage = /opt/CAPEv2/storage/analyses/

[results]
path = /home/cape/sandboxes/results/

[binaries]
sample = /home/cape/data/samples

[history]
log = /home/cape/sandboxes/log.txt
