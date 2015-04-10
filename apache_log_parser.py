"""
This module parsers the apache access log file and returns a list of dictionary objects. The dictionary object
contains each element of a log entry split into key value pairs.  The following data is available:
- host
- unused
- user
- time
- request
- status
- size %b
- referer
- user agent
"""


__author__ = 'James Adcock'

__version__ = "1.0"

import re
import time
import datetime
from datetime import timedelta


class Timezone(datetime.tzinfo):

    def __init__(self, name="+0000"):
        self.name = name
        seconds = int(name[:-2])*3600+int(name[-2:])*60
        self.offset = datetime.timedelta(seconds=seconds)

    def utcoffset(self, dt):
        return self.offset

    def dst(self, dt):
        return timedelta(0)

    def tzname(self, dt):
        return self.name


def parse_access_logs(path_to_access_log='/var/log/apache2/access.log'):
    """parsers the apache access log file and returns a list of dictionary objects.
    The dictionary object contains each element of a log entry split into key value pairs.
    :param path_to_access_log: string, the location of the apache logs
    :return: logs, list of dictionary objects
    """
    f = open(path_to_access_log, 'r')
    access_log = f.readlines()
    #  regex to find each element in log file
    elements = [
        r'(?P<host>\S+)',                   # host
        r'\S+',                             # unused
        r'(?P<user>\S+)',                   # user
        r'\[(?P<time>.+)\]',                # time
        r'"(?P<request>.+)"',               # request
        r'(?P<status>[0-9]+)',              # status
        r'(?P<size>\S+)',                   # size %b
        r'"(?P<referer>.*)"',               # referer
        r'"(?P<agent>.*)"',                 # user agent
    ]
    pattern = re.compile(r'\s+'.join(elements)+r'\s*\Z')
    logs = list()
    for line in access_log:
        m = pattern.match(line)
        try:  # save log data to dictionary
            log_data = m.groupdict()
            if log_data["user"] == "-":
                log_data["user"] = None
                log_data["status"] = int(log_data["status"])
            if log_data["size"] == "-":
                log_data["size"] = 0
            else:
                log_data["size"] = int(log_data["size"])
            if log_data["referer"] == "-":
                log_data["referer"] = None

            #  convert time to datetime object
            t = time.strptime(log_data["time"][:-6], "%d/%b/%Y:%H:%M:%S")
            t = list(t[:6]) + [0, Timezone(log_data["time"][-5:])]
            log_data["time"] = datetime.datetime(*t)
            logs.append(log_data)
        except AttributeError:  # exception may be caused by blank line
            pass
    return logs


if __name__ == '__main__':
    for log in parse_access_logs():
        print(log)


