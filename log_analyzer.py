#!/usr/bin/env python3
import argparse
from collections import namedtuple
import sys
import statistics
import logging
import os
import re
from time import sleep
import gzip
import itertools
from typing import Generator
from string import Template
import json


logging.basicConfig(format='[%(asctime)s] %(levelname).1s %(message)s',
                    level=logging.INFO, datefmt='%Y.%m.%d %H:%M:%S')


configuration = {
    "REPORT_SIZE": 100,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "LOG_FILE": None
}


def main(new_config):
    config = check_configuration(new_config)
    latest_log = find_latest_log(folder=config.get("LOG_DIR"))
    if latest_log:
        if not is_file_analyzed(latest_log.date, config):
            logging.info(f"Analyzing the latest log file {latest_log.filename}.")
            report_ready_result = handle_file(latest_log.filename, config)
            create_report(report_ready_result, latest_log.date, config)
        else:
            logging.info("No new log files for analyzer are found.")
    logging.info("Waiting for new logs to analyze...")


def find_latest_log(folder: str) -> namedtuple:
    """
    Find the latest log file inside the provided folder
    :param folder: name of the folder
    :return: log filename and its date
    """
    try:
        file_pattern = re.compile(r'^nginx-access-ui.log-(\d+)(\.gz)?$')  # regex = r'^nginx-access-ui.log-(\d+)(\.gz)?$'
        dates_dict = dict()
        result = namedtuple('log_file', ['date', 'filename'])
        for file in os.listdir(folder):
            valid_file = re.match(file_pattern, file)
            if valid_file:
                new_date = int(valid_file.group(1))
                dates_dict[new_date] = file
        result_tuple = result(max(dates_dict.keys()), dates_dict[max(dates_dict.keys())])
        logging.info(f"Found latest file: {result_tuple}")
        return result_tuple
    except ValueError:
        logging.info("Unable to find matching log file.")


def is_file_analyzed(log_date: int, config: dict) -> bool:
    log_date = str(log_date)
    return os.path.exists(os.path.join(config.get("REPORT_DIR"),
                                       f'report-{log_date[:4]}.{log_date[4:6]}.{log_date[6:8]}.html'))


def _validate_paths_in_config(new_config: dict):
    config_with_paths = {key: new_config[key] for key in new_config.keys() & {'REPORT_DIR', 'LOG_DIR'}}
    for k, v in config_with_paths.items():
        if not os.path.exists(v):
            logging.error(f"Provided directory {k} does not exist. Exiting.")
            raise ValueError()


def check_configuration(configuration_file: str) -> dict:
    new_config = configuration.copy()
    try:
        if configuration_file:
            with open(configuration_file) as reader:
                config = json.load(reader)
                new_config.update(config)
                if new_config["LOG_FILE"] is not None:
                    logger = logging.getLogger()
                    fh = logging.FileHandler(new_config.get("LOG_FILE"))
                    logger.addHandler(fh)
                _validate_paths_in_config(new_config)
                logging.info("Changing configuration is completed.")
        return new_config
    except FileNotFoundError:
        logging.error(f"Provided configuration file {configuration_file} is not found. Exiting.")
        raise ValueError()


def _read_file_into_data(log_file: str):
    pattern = re.compile(r'\d+\.\d+\.\d+.\d+ - ?.+ - \[.+] "[A-Z]+ (.+) HTTP/1\.\d".+" (\d+?\.\d+)')
    with gzip.open(log_file, 'rb') if log_file.endswith('gz') else open(log_file, 'rb') as reader:
        for line in reader:
            line_count = 1
            if re.match(pattern, line.decode("utf-8")):
                processed = 1
                yield list(re.match(pattern, line.decode("utf-8")).groups()) + [line_count] + [processed]
            else:
                yield ["", "0", line_count, 0]


def _initial_gen(log_file: str, config: dict) -> Generator[dict, None, None]:
    cols = ['new_url', 'req_time', 'line_count', 'processed']
    url_dicts = (dict(zip(cols, data)) for data in _read_file_into_data(f"{config.get('LOG_DIR')}/{log_file}"))
    return url_dicts


def handle_file(log_file: str, config: dict) -> Generator[dict, None, None]:
    """
    Main function for log analyzing.
    :param log_file: name of the log file for analysis
    :param config: dictionary with configuration parameters
    :return: generator with results of analysis
    """
    # Checking for errors in parsing. Exiting if results contain more than 20 percent of errors
    total_count = sum(data['line_count'] for data in _initial_gen(log_file=log_file, config=config))
    processed_lines = sum(data['processed'] for data in _initial_gen(log_file=log_file, config=config))
    try:
        if (total_count - processed_lines) / total_count * 100 > 20:
            logging.error((f"Too many errors in log parsing: "
                           f"{(total_count - processed_lines) / total_count * 100} percent. Exiting."))
            raise ValueError()
    except ZeroDivisionError:
        logging.error(f"Log file {log_file} is probably empty.")
        return

    # Sorting initial generator by url, preparing for itertools.groupby
    sorted_gen = sorted(_initial_gen(log_file=log_file, config=config), key=lambda a: a["new_url"], reverse=True)

    # 'grouping by' generator by the following pattern: ('url': [list of request times])
    grouped_by = ({k: list(map(lambda y: float(y['req_time']), list(g)))}
                  for k, g in itertools.groupby(sorted_gen, lambda x: x["new_url"]))

    # sorting generator by max request time and leaving only highest values
    sorted_by_max = sorted(grouped_by, key=lambda a: sum(*a.values()), reverse=True)[:config.get("REPORT_SIZE")]
    total_time = sum(float(data['req_time']) for data in _initial_gen(log_file=log_file, config=config))

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


def create_report(generator_result: Generator, c_time: int, config: dict):
    """
    Writing results of log analysis into an html report
    :param generator_result: results of log analysis in generator
    :param c_time: time of log creation which is used in the report name
    :param config: dict with configuration parameters
    """
    report_name = f'report-{str(c_time)[:4]}.{str(c_time)[4:6]}.{str(c_time)[6:8]}.html'
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

    while True:
        try:
            main(args.config)
            sleep(15)
        except KeyboardInterrupt:
            sys.exit("\nGoodbye!")
        except ValueError as e:
            logging.error(f"An error occurred: {e}")
            sys.exit("\nExit due to an error.")
        except Exception as e:
            logging.exception("Unexpected error occurred", e)
            sys.exit("\nExit due to an error.")

