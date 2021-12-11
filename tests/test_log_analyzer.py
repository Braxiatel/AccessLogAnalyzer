import os
import unittest
import log_analyzer

test_config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./tests/test_report",
    "LOG_DIR": "./tests/test_log",
    "TEST_DIR": "./tests"
}


class TestLogLocation(unittest.TestCase):

    def test_latest_gz_file(self):
        found_file = log_analyzer.find_latest_log(test_config.get('LOG_DIR'))
        self.assertEqual(found_file.filename, 'nginx-access-ui.log-20160631.gz')

    def test_bz_log_file(self):
        found_file = log_analyzer.find_latest_log(test_config.get('LOG_DIR'))
        self.assertNotEqual(found_file.filename, 'nginx-access-ui.log-20180631.bz')

    def test_invalid_log_file(self):
        found_file = log_analyzer.find_latest_log(test_config.get('LOG_DIR'))
        self.assertNotEqual(found_file.filename, 'packet_capture.log-20180631.gz')

    def test_plain_log_file(self):
        found_file = log_analyzer.find_latest_log(os.path.join(test_config.get('LOG_DIR'), "./plain_dir"))
        self.assertEqual(found_file.filename, 'nginx-access-ui.log-20160631')

    def check_empty_log_directory(self):
        with self.assertRaises(ValueError):
            test = log_analyzer.find_latest_log(os.path.join(test_config.get('LOG_DIR'), "./empty_dir"))
            self.assertEqual(test, None)


class TestLogAnalyzing(unittest.TestCase):

    def test_file_analyzed(self):
        analyzed_file = log_analyzer.is_file_analyzed(20160631, config=test_config)
        self.assertEqual(analyzed_file, True)

    def test_empty_log(self):
        self.assertEqual(log_analyzer.handle_file(log_file="nginx-access-ui.log-20160631.gz", config=test_config), None)

    def test_many_errors(self):
        test_file = os.path.join('plain_dir', 'nginx-access-ui.log-20160631')
        with self.assertRaises(ValueError):
            test = log_analyzer.handle_file(log_file=test_file, config=test_config)

    def test_result_generator(self):
        new_config = test_config.copy()
        new_config['LOG_DIR'] = os.path.join(test_config.get("LOG_DIR"), "valid_dir")
        test = log_analyzer.handle_file("nginx-access-ui.log-20180631", config=new_config)
        self.assertEqual(sum(item['count'] for item in test), 10)


class TestConfiguration(unittest.TestCase):

    def test_missing_configuration_file(self):
        with self.assertRaises(ValueError):
            log_analyzer.main("nonexistent.config")

    def test_config_changed(self):
        config_file = os.path.join(test_config.get("TEST_DIR"), "test_config.json")
        result = log_analyzer.check_configuration(configuration_file=config_file)
        self.assertEqual(result.get("LOG_DIR"), "./tests/test_log/empty_dir")

    def test_invalid_config(self):
        config_file = os.path.join(test_config.get("TEST_DIR"), "test_invalid_config.json")
        with self.assertRaises(ValueError):
            result = log_analyzer.check_configuration(configuration_file=config_file)


class TestReportCreation(unittest.TestCase):
    report = os.path.join(test_config.get("REPORT_DIR"), "report-2018.06.31.html")
    default_report = os.path.join(test_config.get("REPORT_DIR"), "report.html")

    def setUp(self):
        new_config = os.path.join(test_config.get("TEST_DIR"), "test_valid_config.json")
        log_analyzer.main(new_config=new_config)

    def test_report_is_created(self):
        self.assertEqual(os.path.exists(self.report), True)

    def test_report_is_not_empty(self):
        self.assertGreater(os.path.getsize(self.report), os.path.getsize(self.default_report))

    def tearDown(self):
        report = os.path.join(test_config.get("REPORT_DIR"), "report-2018.06.31.html")
        os.remove(report)


if __name__ == '__main__':
    unittest.main()
