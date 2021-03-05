import gzip
import json
import os
import shutil
import tempfile
import unittest
from datetime import datetime

import log_analyzer

CONFIG = {
    'REPORT_SIZE': 1000,
    'REPORT_DIR': './reports',
    'LOG_DIR': './log',
    'SUPPORTED_LOG_FORMATS': ['', '.gz'],
    'TERMINATED_PERCENT': 100,
    'LOGGING_FILE': None,
    'LOGGING_FORMAT': '[%(asctime)s] %(levelname).1s %(message)s',
}


class LogAnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_log_dir = tempfile.mkdtemp()
        cls.test_wrong_log_dir = tempfile.mkdtemp()
        cls.test_report_dir = tempfile.mkdtemp()
        cls.config = log_analyzer.get_config(
            {
                'LOG_DIR': cls.test_log_dir,
                'REPORT_DIR': cls.test_report_dir,
            })

        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210223.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210224.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210225.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210226.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210227.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210228.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210299.gz', 'w').close()
        open(f'{cls.test_log_dir}/nginx-access-ui.log-20210399.gz', 'w').close()

        cls.last_log_filename = f'{cls.test_log_dir}/nginx-access-ui.log-20210301.gz'
        cls.COUNT_LINES = 100
        cls.REQUEST_TIME = 555
        with gzip.open(cls.last_log_filename, 'wb') as f:
            line = f'1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET /api/v2/banner/25019354 HTTP/1.1" 200 927 "-" "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5" "-" "1498697422-2190034393-4708-9752759" "dc7161be3" {cls.REQUEST_TIME}\n'
            for _ in range(cls.COUNT_LINES):
                f.write(str.encode(line))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.test_log_dir)
        shutil.rmtree(cls.test_wrong_log_dir)
        shutil.rmtree(cls.test_report_dir)

    def tearDown(self):
        report_path = f'{self.test_report_dir}/report-2021.03.01.html'
        if os.path.exists(report_path):
            os.remove(report_path)

    def test_get_config(self):
        new_config = {
            'REPORT_SIZE': 25,
            'REPORT_DIR': './reports_new',
            'LOG_DIR': './log_new',
            'SUPPORTED_LOG_FORMATS': ['', '.gz', '.bz2'],
            'TERMINATED_PERCENT': 25,
            'NEW_KEY': 'new_value',
        }

        updated_config = log_analyzer.get_config(new_config)
        for key in new_config.keys():
            self.assertEqual(updated_config[key], new_config[key])

    def test_generate_report_filename(self):
        log_filename = 'nginx-test-log.gz'
        date = datetime(2021, 3, 1)
        log_filepath = log_analyzer.Filepath(
            path=os.path.join(self.config['LOG_DIR'], log_filename),
            date=date,
            extension='.gz',
        )

        report_filepath = log_analyzer.generate_report_filename(self.config, log_filepath)
        self.assertEqual(report_filepath['path'], f'{self.test_report_dir}/report-2021.03.01.html')
        self.assertEqual(report_filepath['date'], date)
        self.assertEqual(report_filepath['extension'], '.html')

    def test_find_log(self):
        log_filepath = log_analyzer.find_log(self.config)
        self.assertEqual(log_filepath['path'], self.last_log_filename)
        self.assertEqual(log_filepath['date'], datetime(2021, 3, 1))
        self.assertEqual(log_filepath['extension'], '.gz')

        with self.assertRaises(FileNotFoundError):
            """Check wrong log dir"""
            config = log_analyzer.get_config({'LOG_DIR': f'{self.test_log_dir}/wrong_path'})
            log_analyzer.find_log(config)

        with self.assertRaises(SystemExit):
            """Check dir without log"""
            config = log_analyzer.get_config({'LOG_DIR': self.test_wrong_log_dir})
            log_analyzer.find_log(config)

        report_path = f'{self.test_report_dir}/report-2021.03.01.html'
        with self.assertRaises(SystemExit):
            """Check already generated report"""
            open(report_path, 'w').close()
            config = log_analyzer.get_config(
                {
                    'LOG_DIR': self.test_log_dir,
                    'REPORT_DIR': self.test_report_dir
                })
            log_analyzer.find_log(config)

    def test_parse_log(self):
        log_filepath = log_analyzer.find_log(self.config)
        parsed_log = log_analyzer.parse_log(self.config, log_filepath)
        self.assertEqual(parsed_log['total_count'], self.COUNT_LINES)
        self.assertEqual(parsed_log['total_time'], self.COUNT_LINES * self.REQUEST_TIME)
        self.assertEqual(len(parsed_log['parsed_lines']), self.COUNT_LINES)
        self.assertEqual(parsed_log['parsed_lines'][0]['request_time'], self.REQUEST_TIME)

    def test_process_log(self):
        log_filepath = log_analyzer.find_log(self.config)
        parsed_log = log_analyzer.parse_log(self.config, log_filepath)
        processed_log = log_analyzer.process_log(self.config, parsed_log)
        self.assertEqual(processed_log['total_count'], self.COUNT_LINES)
        self.assertEqual(processed_log['total_time'], self.COUNT_LINES * self.REQUEST_TIME)
        self.assertEqual(len(processed_log['data'].items()), 1)
        processed_line = list(processed_log['data'].values())[0]
        self.assertEqual(processed_line['time_sum'], self.COUNT_LINES * self.REQUEST_TIME)

    def test_generate_report(self):
        TOTAL_COUNT = 1
        TIME = 5.0
        PROCESSED_LINE = log_analyzer.ProcessedLine(
            url='/test-url/',
            count=TOTAL_COUNT,
            time_sum=TIME,
            time_avg=TIME,
            time_max=TIME,
            time_list=[TIME, TIME],
        )
        DATA = {'/test-url/': PROCESSED_LINE}

        log_filepath = log_analyzer.find_log(self.config)
        processed_log = log_analyzer.ProcessedLog(
            total_count=1,
            total_time=5,
            data=DATA,
        )

        with self.assertRaises(SystemExit):
            """Check that report.html not found"""
            log_analyzer.generate_report(self.config, processed_log, log_filepath)

        report_template_path = os.path.join(self.config['REPORT_DIR'], 'report.html')
        report_template_content = '$table_json'
        with open(report_template_path, 'w') as f:
            f.write(report_template_content)

        log_analyzer.generate_report(self.config, processed_log, log_filepath)
        table_json = json.dumps(
            [
                {
                    'url': PROCESSED_LINE['url'],
                    'count': PROCESSED_LINE['count'],
                    'count_perc': 100.0,
                    'time_sum': PROCESSED_LINE['time_sum'],
                    'time_perc': 100.0,
                    'time_avg': PROCESSED_LINE['time_avg'],
                    'time_max': PROCESSED_LINE['time_max'],
                    'time_med': TIME,
                }
            ])

        report_filepath = log_analyzer.generate_report_filename(self.config, log_filepath)
        with open(report_filepath['path'], 'r') as f:
            line = f.read()
            self.assertEqual(line, table_json)


if __name__ == '__main__':
    unittest.main()
