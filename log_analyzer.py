#!/usr/bin/env python3
import argparse
from datetime import datetime
from collections import namedtuple
import sys
import statistics
import logging
import os
import re
import gzip
import itertools
from typing import Generator
from string import Template
import json


logging.basicConfig(format='[%(asctime)s] %(levelname).1s %(message)s',
                    level=logging.INFO, datefmt='%Y.%m.%d %H:%M:%S')


result = namedtuple('log_file', ['date', 'filename'])
file_pattern = re.compile(r'^nginx-access-ui.log-(\d+)(\.gz)?$')
pattern = re.compile(r'\d+\.\d+\.\d+.\d+ - ?.+ - \[.+] "[A-Z]+ (.+) HTTP/1\.\d".+" (\d+?\.\d+)')

configuration = {
    "REPORT_SIZE": 100,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "LOG_FILE": None
}


def main(new_config):
    """
    Main procedure for log analyzing: 1) Validate new configuration file. 2) Find latest log file. 3) Check if the
    latest log file is already analyzed. 4) Process file if it is not analyzed yet. 5) Write a html report for processed
    file.
    :param new_config: path to configuration file
    """
    config = check_configuration(new_config)
    latest_log = find_latest_log(folder=config.get("LOG_DIR"))
    if not latest_log:
        logging.info("No new log files for analyzer are found.")
        return
    if not is_file_analyzed(latest_log.date, config):
        logging.info(f"Analyzing the latest log file {latest_log.filename}.")
        log_file = f"{config.get('LOG_DIR')}/{latest_log.filename}"
        report_ready_result = handle_file(read_file_into_data, log_file, config)
        create_report(report_ready_result, latest_log.date, config)
    else:
        logging.info("Latest log is already analyzed.")


def find_latest_log(folder: str) -> namedtuple:
    """
    Find the latest log file inside the provided folder
    :param folder: name of the folder
    :return: log filename and its date
    """
    format_data = "%Y%m%d"
    try:
        dates_dict = dict()
        for file in os.listdir(folder):
            valid_file = re.match(file_pattern, file)
            if valid_file:
                new_date = datetime.strptime(valid_file.group(1), format_data)
                dates_dict[new_date] = file
        result_tuple = result(max(dates_dict.keys()), dates_dict[max(dates_dict.keys())])
        logging.info(f"Found latest log file: {result_tuple}")
        return result_tuple
    except Exception as ex:
        logging.exception(f"Something went wrong, {ex}")


def is_file_analyzed(log_date: datetime, config: dict) -> bool:
    """
    Checks whether latest file is already analyzed.
    :param log_date: latest log file timestamp
    :param config: configuration as a dict
    :return: result of the check as a bool value
    """
    log_date = str(log_date)
    return os.path.exists(os.path.join(config.get("REPORT_DIR"),
                                       f'report-{log_date[:4]}.{log_date[5:7]}.{log_date[8:10]}.html'))


def _validate_paths_in_config(new_config: dict):
    config_with_paths = {key: new_config[key] for key in new_config.keys() & {'REPORT_DIR', 'LOG_DIR'}}
    for k, v in config_with_paths.items():
        if not os.path.exists(v):
            raise OSError(f"Provided directory {k}: {v} does not exist. Exiting.")


def _setup_logging(config):
    logger = logging.getLogger()
    fh = logging.FileHandler(config.get("LOG_FILE"))
    logger.addHandler(fh)


def check_configuration(configuration_file: str) -> dict:
    """
    Check that provided configuration file is valid.
    :param configuration_file: path to configuration file
    :return: configuration converted into dict
    """
    new_config = configuration.copy()
    try:
        if configuration_file and configuration_file.endswith(".json"):
            with open(configuration_file) as reader:
                config = json.load(reader)
                new_config.update(config)
                if new_config["LOG_FILE"] is not None:
                    _setup_logging(config=new_config)
                _validate_paths_in_config(new_config)
                logging.info("Changing configuration is completed.")
        elif configuration_file:
            raise ValueError(f"{configuration_file} is invalid")
        return new_config
    except FileNotFoundError:
        logging.exception(f"Provided configuration file {configuration_file} is not found. Exiting.")


def read_file_into_data(log_file: str) -> Generator[dict, None, None]:
    cols = ['new_url', 'req_time', 'line_count', 'processed']
    with gzip.open(log_file, 'rb') if log_file.endswith('gz') else open(log_file, 'rb') as reader:
        for line in reader:
            line_count = 1
            if re.match(pattern, line.decode("utf-8")):
                processed = 1
                yield dict(zip(cols, list(re.match(pattern, line.decode("utf-8")).groups()) +
                               [line_count] + [processed]))
            else:
                yield dict(zip(cols, ["", "0", line_count, 0]))


def handle_file(file_generator, log_file: str, config: dict) -> Generator[dict, None, None]:
    """
    Main function for log analyzing.
    :param file_generator: initial log file handling
    :param log_file: name of the log file for analysis
    :param config: dictionary with configuration parameters
    :return: generator with results of analysis
    """
    # Checking for errors in parsing. Exiting if results contain more than 20 percent of errors
    total_count = sum(data['line_count'] for data in file_generator(log_file=log_file))
    processed_lines = sum(data['processed'] for data in file_generator(log_file=log_file))
    try:
        if (total_count - processed_lines) / total_count * 100 > 20:
            raise ValueError(f"Too many errors in log parsing: "
                             f"{(total_count - processed_lines) / total_count * 100} percent. Exiting.")
    except ZeroDivisionError:
        logging.error(f"Log file {log_file} is probably empty.")
        return

    # Sorting initial generator by url, preparing for itertools.groupby
    sorted_gen = sorted(read_file_into_data(log_file=log_file), key=lambda a: a["new_url"], reverse=True)

    # 'grouping by' generator by the following pattern: ('url': [list of request times])
    grouped_by = ({k: list(map(lambda y: float(y['req_time']), list(g)))}
                  for k, g in itertools.groupby(sorted_gen, lambda x: x["new_url"]))

    # sorting generator by max request time and leaving only highest values
    sorted_by_max = sorted(grouped_by, key=lambda a: sum(*a.values()), reverse=True)[:config.get("REPORT_SIZE")]
    total_time = sum(float(data['req_time']) for data in file_generator(log_file=log_file))

    # constructing the final version of the generator with analysis
    final_g = ({"url": list(item.keys())[0],
                "count": len(*item.values()),
                "time_perc": (sum(*item.values()) / total_time) * 100,
                "count_perc": len(*item.values()) / total_count * 100,
                "time_avg": sum(*item.values()) / len(*item.values()),
                "time_med": statistics.median(*item.values()),
                "time_sum": sum(*item.values()),
                "time_max": max(*item.values())}
               for item in sorted_by_max)
    return final_g


def create_report(generator_result: Generator, c_time: datetime, config: dict):
    """
    Writing results of log analysis into an html report
    :param generator_result: results of log analysis in generator
    :param c_time: time of log creation which is used in the report name
    :param config: dict with configuration parameters
    """
    report_name = f'report-{str(c_time)[:4]}.{str(c_time)[5:7]}.{str(c_time)[8:10]}.html'
    path = os.path.join(config.get("REPORT_DIR"), report_name)
    if generator_result:
        logging.info(f"Creating the report into {report_name} file.")
        with open(os.path.join(config.get("REPORT_DIR"), 'report.html'), 'r') as reader:
            content = reader.read()
            s = Template(content)
            with open(path, 'w') as writer:
                writer.write(s.safe_substitute(table_json=[item for item in generator_result]))
            logging.info(f"New report is written into {report_name} file.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Simple implementation of access log processing.',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c", "--config", help="Provide another configuration file",
                        default="", type=str)
    args = parser.parse_args()

    try:
        main(args.config)
    except KeyboardInterrupt:
        sys.exit("\nGoodbye!")
    except Exception as e:
        logging.exception("Unexpected error occurred", e)
        sys.exit("\nExit due to an error.")

