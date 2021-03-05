import fnmatch
import getopt
import gzip
import json
import logging
import os
import re
import sys
from datetime import datetime
from statistics import median
from string import Template
from typing import Dict, List, TypedDict, Union

# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

CONFIG = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './log',
    'SUPPORTED_LOG_FORMATS': ['', '.gz'],
    'TERMINATED_PERCENT': 100,
    'LOGGING_FILE': None,
    'LOGGING_FORMAT': '[%(asctime)s] %(levelname).1s %(message)s',
    'NUMBER_ROUND_DEPTH': 3,
}

Config = TypedDict(
    'Config',
    REPORT_SIZE=int,
    REPORT_DIR=str,
    LOG_DIR=str,
    SUPPORTED_LOG_FORMATS=List[str],
    TERMINATED_PERCENT=float,
    LOGGING_FILE=Union[str, None],
    LOGGING_FORMAT=str,
    NUMBER_ROUND_DEPTH=int,
)

Filepath = TypedDict(
    'Filepath',
    path=str,
    date=datetime,
    extension=str,
)

ParsedLine = TypedDict(
    'ParsedLine',
    remote_addr=str,
    remote_user=str,
    http_x_real_ip=str,
    time_local=str,
    method=str,
    url=str,
    protocol=str,
    status=str,
    body_bytes_sent=str,
    http_referer=str,
    http_user_agent=str,
    http_x_forwarded_for=str,
    http_X_REQUEST_ID=str,
    http_X_RB_USER=str,
    request_time=float,
)

ParsedLog = TypedDict(
    'ParsedLog',
    total_count=int,
    total_time=float,
    parsed_lines=List[ParsedLine],
)

ProcessedLine = TypedDict(
    'ProcessedLine',
    url=str,
    count=int,
    time_sum=float,
    time_avg=float,
    time_max=float,
    time_list=List[float],
)

ProcessedLog = TypedDict(
    'ProcessedLog',
    total_count=int,
    total_time=float,
    data=Dict[str, ProcessedLine],
)

logging.basicConfig(format=CONFIG['LOGGING_FORMAT'], level=logging.INFO, handlers=[])
stdout_handler = logging.StreamHandler(sys.stdout)
logger = logging.getLogger()
logger.addHandler(stdout_handler)


def process_argv() -> dict:
    config_path = None
    config_dict = {}

    USAGE = '''\
Usage: log_analyzer.py
For custom config use `--config=<config_file>`
Example custom config file:
{
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log"
}
'''

    try:
        opts, _ = getopt.getopt(sys.argv[1:], shortopts='h', longopts=['config='])
    except getopt.GetoptError:
        logger.exception(f'Wrong args. {USAGE}')
        raise SystemExit()

    for opt, arg in opts:
        if opt == '-h':
            raise SystemExit(USAGE)
        if opt == '--config':
            config_path = arg

    if config_path:
        if not os.path.exists(config_path):
            logger.exception('Wrong path to config')
            raise SystemExit()

        with open(config_path) as f:
            try:
                config_dict = json.loads(' '.join(f.readlines()))
            except ValueError:
                logger.exception('Wrong config file, check that you have json structure')
                raise SystemExit()

    return config_dict


def get_config(config_dict: dict) -> Config:
    combined_config = {**CONFIG, **config_dict}

    logger.info('Run with config:')
    for key, value in combined_config.items():
        logger.info(f'{key} = {value}')
    return Config(**combined_config)


def generate_report_filename(config: Config, log_filepath: Filepath) -> Filepath:
    date = log_filepath['date'].strftime('%Y.%m.%d')
    filename = f'report-{date}.html'
    filepath = Filepath(
        path=os.path.join(config['REPORT_DIR'], filename),
        date=log_filepath['date'],
        extension='.html',
    )
    return filepath


def find_log(config: Config) -> Filepath:
    filename_mask = 'nginx-access-ui.log-*'
    date_format = '%Y%m%d'
    last_date = None
    log_filename = ''

    for filename in os.listdir(config['LOG_DIR']):
        if fnmatch.fnmatch(filename, filename_mask):
            name, extension = os.path.splitext(filename)
            if extension not in config['SUPPORTED_LOG_FORMATS']:
                continue

            date_str = ''.join(x for x in name if x.isdigit())
            try:
                date = datetime.strptime(date_str, date_format)
            except ValueError:
                continue

            if not last_date or date > last_date:
                last_date = date
                log_filename = filename

    if not last_date:
        logger.warning('Log not founded, check `LOG_DIR` in config')
        raise SystemExit()

    _, extension = os.path.splitext(log_filename)
    log_filepath = Filepath(
        path=os.path.join(config['LOG_DIR'], log_filename),
        date=last_date,
        extension=extension,
    )

    report_filepath = generate_report_filename(config, log_filepath)
    if os.path.exists(report_filepath['path']):
        logger.warning(f'Report already generated, check {report_filepath["path"]}')
        raise SystemExit()

    return log_filepath


def parse_log(config: Config, log_filepath: Filepath) -> ParsedLog:
    parsed_log = ParsedLog(
        total_count=0,
        total_time=0.0,
        parsed_lines=[],
    )

    log_pattern = re.compile(
        r'(\S+) (\S+)  (\S+) \[(.*)\] "(\S+) (\S+) (\S+) (\S+) (\S+) "(\S+)" "(.*?)" "(\S+)" "(\S+)" "(\S+)" (\S+)'
    )
    colnames = (
        'remote_addr',
        'remote_user',
        'http_x_real_ip',
        'time_local',
        'method',
        'url',
        'protocol',
        'status',
        'body_bytes_sent',
        'http_referer',
        'http_user_agent',
        'http_x_forwarded_for',
        'http_X_REQUEST_ID',
        'http_X_RB_USER',
        'request_time',
    )

    openers = {'.gz': gzip.open, '': open}
    opener = openers.get(log_filepath['extension'], open)
    lines = (line for line in opener(log_filepath['path'], mode='rt'))
    count = 0
    terminated_count = 0
    for line in lines:
        count += 1
        try:
            groups = log_pattern.match(line).groups()
        except AttributeError:
            logger.info(f'Skiped line: {line}')
            terminated_count += 1
            continue

        if terminated_count * 100 / count >= config['TERMINATED_PERCENT']:
            logger.exception(f'Error: TERMINATED_PERCENT achieved, parsing is stopped')
            raise SystemExit()

        parsed_dict = dict(zip(colnames, groups))
        parsed_dict['request_time'] = float(parsed_dict['request_time'])
        parsed_line = ParsedLine(**parsed_dict)
        parsed_log['total_count'] += 1
        parsed_log['total_time'] += float(parsed_line['request_time'])
        parsed_log['parsed_lines'].append(parsed_line)

    return parsed_log


def process_log(config: Config, parsed_log: ParsedLog) -> ProcessedLog:
    tmp_data = {}

    parsed_lines = (parsed_line for parsed_line in parsed_log['parsed_lines'])
    for parsed_line in parsed_lines:
        url = parsed_line['url']
        processed_line = tmp_data.get(url, None)
        if not processed_line:
            processed_line = ProcessedLine(
                url=url,
                count=0,
                time_sum=0.0,
                time_max=0.0,
                time_list=[],
            )

        processed_line['count'] += 1
        request_time = parsed_line['request_time']
        processed_line['time_sum'] += request_time
        processed_line['time_list'].append(request_time)
        if request_time > processed_line['time_max']:
            processed_line['time_max'] = request_time

        tmp_data[url] = processed_line

    processed_log = ProcessedLog(
        total_count=0,
        total_time=0.0,
        data={},
    )

    for url, processed_line in tmp_data.items():
        if processed_line['time_sum'] >= config['REPORT_SIZE']:
            processed_log['total_count'] += processed_line['count']
            processed_log['total_time'] += processed_line['time_sum']
            processed_log['data'][url] = processed_line

    return processed_log


def generate_report(config: Config, processed_log: ProcessedLog, log_filepath: Filepath) -> None:
    table_list = []
    nrd = config['NUMBER_ROUND_DEPTH']

    for url, processed_line in processed_log['data'].items():
        count_perc = round(processed_line['count'] * 100 / processed_log['total_count'], nrd)
        time_sum = round(processed_line['time_sum'], nrd)
        time_perc = round(processed_line['time_sum'] * 100 / processed_log['total_time'], nrd)
        time_avg = round(processed_line['time_sum'] / processed_line['count'], nrd)
        time_med = round(median(processed_line['time_list']), nrd)
        time_max = round(processed_line['time_max'], nrd)
        table_list.append(
            {
                'url': url,
                'count': processed_line['count'],
                'count_perc': count_perc,
                'time_sum': time_sum,
                'time_perc': time_perc,
                'time_avg': time_avg,
                'time_max': time_max,
                'time_med': time_med,
            })

    table_json = json.dumps(table_list)
    report_template_path = os.path.join(config['REPORT_DIR'], 'report.html')
    if not os.path.exists(report_template_path):
        logger.exception('Error: Report template (report.html) not found in REPORT_DIR')
        raise SystemExit()

    with open(report_template_path) as f:
        report_template = Template(f.read())
        report_render = report_template.safe_substitute(table_json=table_json)

    report_filepath = generate_report_filename(config, log_filepath)
    with open(report_filepath['path'], 'w') as f:
        f.write(report_render)

    logger.info(f'Success: report ready: {report_filepath["path"]}')
    return


def main():
    """Log Analyzer

    Steps:
    1. Process args
    2. Read config
    3. Find log
        3.1 Check already generated report
    4. Parse log
    5. Process log
    6. Generate report
    """

    config_dict: dict = process_argv()
    config: Config = get_config(config_dict)
    if config['LOGGING_FILE']:
        global logger, stdout_handler
        logger.removeHandler(stdout_handler)
        logger.addHandler(logging.FileHandler(filename=config['LOGGING_FILE']))
    log_filepath: Filepath = find_log(config)
    parsed_log: ParsedLog = parse_log(config, log_filepath)
    processed_log: ProcessedLog = process_log(config, parsed_log)
    generate_report(config, processed_log, log_filepath)
    return


if __name__ == '__main__':
    main()
