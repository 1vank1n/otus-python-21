import argparse
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

Fileinfo = TypedDict(
    'Fileinfo',
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


def process_argv() -> dict:
    parser = argparse.ArgumentParser(description='Create report from nginx log files')
    parser.add_argument('--config', dest='config_path', help='set path to custom config')
    args = parser.parse_args()
    return vars(args)


def load_config(
    *,
    config_path: str,
) -> dict:
    config_dict = {}
    if not os.path.exists(config_path):
        raise SystemExit('Wrong path to config')

    with open(config_path) as f:
        try:
            config_dict = json.loads(' '.join(f.readlines()))
        except ValueError:
            raise SystemExit('Wrong config file, check that you have json structure')
    return config_dict


def get_config(
    *,
    config_dict: dict,
) -> Config:
    combined_config = {**CONFIG, **config_dict}
    return Config(**combined_config)


def get_logger(
    *,
    config: Config,
) -> logging.Logger:
    logging.basicConfig(format=CONFIG['LOGGING_FORMAT'], level=logging.INFO, handlers=[])
    logger = logging.getLogger()
    if config['LOGGING_FILE']:
        logger.addHandler(logging.FileHandler(filename=config['LOGGING_FILE']))
    else:
        logger.addHandler(logging.StreamHandler(sys.stdout))
    return logger


def generate_report_filename(
    *,
    config: Config,
    log_fileinfo: Fileinfo,
) -> Fileinfo:
    date = log_fileinfo['date'].strftime('%Y.%m.%d')
    filename = f'report-{date}.html'
    fileinfo = Fileinfo(
        path=os.path.join(config['REPORT_DIR'], filename),
        date=log_fileinfo['date'],
        extension='.html',
    )
    return fileinfo


def find_log(
    *,
    config: Config,
    logger: logging.Logger,
) -> Fileinfo:
    filename_pattern = re.compile(r'nginx-access-ui\.log-(\d{8})')
    date_format = '%Y%m%d'
    last_date = None
    log_filename = ''

    for filename in os.listdir(config['LOG_DIR']):
        matched = filename_pattern.match(filename)
        if matched:
            _, extension = os.path.splitext(filename)
            if extension not in config['SUPPORTED_LOG_FORMATS']:
                continue

            date_str = matched.groups()[0]
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
    log_fileinfo = Fileinfo(
        path=os.path.join(config['LOG_DIR'], log_filename),
        date=last_date,
        extension=extension,
    )
    return log_fileinfo


def check_is_exist_report(
    *,
    config: Config,
    log_fileinfo: Fileinfo,
    logger: logging.Logger,
) -> None:
    report_fileinfo = generate_report_filename(config=config, log_fileinfo=log_fileinfo)
    if os.path.exists(report_fileinfo['path']):
        logger.warning(f'Report already generated, check {report_fileinfo["path"]}')
        raise SystemExit()


def parse_log(
    *,
    config: Config,
    log_fileinfo: Fileinfo,
    logger: logging.Logger,
) -> ParsedLog:
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
    opener = openers.get(log_fileinfo['extension'], open)
    lines = (line for line in opener(log_fileinfo['path'], mode='rt'))
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


def process_log(
    *,
    config: Config,
    parsed_log: ParsedLog,
) -> ProcessedLog:
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


def generate_report(
    *,
    config: Config,
    processed_log: ProcessedLog,
    log_fileinfo: Fileinfo,
    logger: logging.Logger,
) -> None:
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

    report_fileinfo = generate_report_filename(config=config, log_fileinfo=log_fileinfo)
    with open(report_fileinfo['path'], 'w') as f:
        f.write(report_render)

    logger.info(f'Success: report ready: {report_fileinfo["path"]}')
    return


def main():
    """Log Analyzer

    Steps:
    1. Process args
    2. Read config
    3. Setup logger
    4. Find log
    5. Check already generated report
    6. Parse log
    7. Process log
    8. Generate report
    """

    args: dict = process_argv()
    config_path: str = args.get('config_path', '')
    config_dict: dict = load_config(config_path=config_path) if config_path else {}
    config: Config = get_config(config_dict=config_dict)
    logger: logging.Logger = get_logger(config=config)
    log_fileinfo: Fileinfo = find_log(config=config, logger=logger)
    check_is_exist_report(config=config, log_fileinfo=log_fileinfo, logger=logger)
    parsed_log: ParsedLog = parse_log(config=config, log_fileinfo=log_fileinfo, logger=logger)
    processed_log: ProcessedLog = process_log(config=config, parsed_log=parsed_log)

    generate_report(
        config=config,
        processed_log=processed_log,
        log_fileinfo=log_fileinfo,
        logger=logger,
    )
    return


if __name__ == '__main__':
    main()
