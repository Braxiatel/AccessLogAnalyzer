###### Mini Log Analyzer
_________________

Small script to process NGINX access logs. The latest log file in the ``LOG_DIR`` is going to be processed upon 
running the script. Log file line should have the following format:

_1.136.218.80 -  - [30/Jun/2017:03:28:22 +0300] "GET /export/appinstall_raw/2017-06-30/ HTTP/1.0" 200 25652 "-" "Mozilla/5.0 (Windows; U; Windows NT 6.0; ru; rv:1.9.0.12) Gecko/2009070611 Firefox/3.0.12 (.NET CLR 3.5.30729)" "-" "-" "-" 0.004_

As the result of the analysis script outputs the following statistic metrics into the html report in ``REPORT_DIR`` 
directory.

- **count** - how many times URL appears in the log, absolute value
- **count_perc** - how many times URL appears in the log, percentage
- **time_sum** - sum $request_time for specific URL, absolute value
- **time_perc** - sum $request_time for specific URL, percentage
- **time_avg** - average $request_time for specific URL
- **time_max** - max $request_time for specific URL
- **time_med** - mean $request_time for specific URL

Report size can be limited by ``REPORT_SIZE`` variable. Final report contains ``REPORT_SIZE`` number of URLs with max 
 **time_sum**.

###### Running the script
______________

In order to run the script, Python 3.9 and higher is recommended. Third-party libraries are not required. 
Custom configuration file can be passed to the script. Configuration file might include the following parameters:

 - "REPORT_SIZE": Report size limit.
 - "REPORT_DIR": Directory for reports.
 - "LOG_DIR": Directory with logs.
 - "LOG_FILE": File for the logs. Default value is ``None``, logs are written down into stdout.

Path to the config file is passed with ``--config`` or ``-с`` variable.
Example:

`$ python log_analyzer --config ./config.json`

###### Running the tests
_____________
Unit tests and all test data can be found in ``tests`` folder. Tests can be run like this:

`$ python -m unittest`
