#!/usr/bin/env python3
import configparser
import os


class ReadConfig:
    def __init__(self, filepath="analyzer.conf"):
        root_dir = os.path.dirname(os.path.abspath(__file__))
        config_path = os.path.join(root_dir, filepath)
        self.cf = configparser.ConfigParser()
        self.cf.read(config_path, encoding='utf-8')

    def get_thread_num(self):
        value = self.cf.get("script", "thread_num")
        return int(value)

    def get_csv_path(self):
        value = self.cf.get("script", "hosts_csv_filename")
        return str(value)

    def get_analyze_nums(self):
        value = self.cf.get("script", "analyze_num")
        return int(value)

    def get_multi_thread_opt(self):
        value = self.cf.get("script", "multi_thread")
        return bool(value)


if __name__ == '__main__':
    # test
    config = ReadConfig()
    print(config.get_thread_num())
    print(config.get_csv_path())
    print(config.get_analyze_nums())
    print(config.get_multi_thread_opt())
