#!/usr/bin/python

"""
DDoS Wall is designed to detect and block HTTP based DDoS traffic.  It achieves this by employing a number of
detection algorithms. If it is identified that a client is part of a DDoS attack its IP address is blocked
by writing a rule to the firewall.  DDoS_Wall will also configure the Iptables firewall with some basic rules
and will turn on SYN cookies if the system is potentially under attack.  Before running the ddos_wall command
please run ddosw_baseline to gain a system baseline.
DDoS Wall has to be run as root as it must be able to write rules to the firewall.
DDoW_Wall is designed to be used on a Linux system that is running the Apache web server
and has been tested on Ubuntu 14.04.
DDoS_WAll has been developed for research purposes only and should not be used on a production server!
"""

__author__ = 'James Adcock'

__version__ = "0.1"

import SocketServer
import SimpleHTTPServer
import urllib
import subprocess
import re
import time
import optparse
from ddosw_baseline import get_mean
import threading
import sysmon
import sys
import page_profile
from random import randint
import hashlib
import os


class Setup():
    """
    This class contains methods for setting up DDoS wall
    """
    connection_cache = list()
    system_status = 'green'  # The current state that the system is in
    syn_cookies = 0
    orange_score = -200
    red_score = -300

    def __init__(self):
        pass

    @staticmethod
    def parse_options():
        """
        This method parses the command line options that are passed to the application
        :return: options - dictionary containing all of the command line options
        """
        description = """DDoS_Wall is designed to mitigate common types of DDoS attacks.  It offers system
        monitoring and will enable TCP cookies if the system is under attack, this helps
        mitigate SYN flood attacks.  It also provides protection against HTTP based attacks which it
        will automatically detect and the offending IP addresses will be blocked. ddos_wall must be run
        with root privileges"""
        parser = optparse.OptionParser(description=description)
        parser.add_option('-c', '--cpu_orange', default=0, help='orange threshold for CPU utilisation', metavar='<ARG>')
        parser.add_option('-C', '--cpu_red', default=0, help='red threshold for CPU utilisation', metavar='<ARG>')
        parser.add_option('-m', '--memory_orange', default=0, help='orange threshold for RAM usage', metavar='<ARG>')
        parser.add_option('-M', '--memory_red', default=0, help='red threshold for RAM usage', metavar='<ARG>')
        parser.add_option('-n', '--network_orange', default=0, help='orange threshold for Network usage', metavar='<ARG>')
        parser.add_option('-N', '--network_red', default=0, help='red threshold for Network usage', metavar='<ARG>')
        parser.add_option('-p', '--port', default=1234, help='port that proxy listens on', metavar='<ARG>')
        parser.add_option('-a', '--ip_address', help='MANDATORY - ip address of server', metavar='<ARG>')
        parser.add_option('-I', '--interface', default='eth0', help='the interface forwarding traffic', metavar='<ARG>')
        parser.add_option('-t', '--time', default=10, help='the number of minutes that threshold is calculated over',
                          metavar='<ARG>')
        parser.add_option('-i', '--interval', default=10, help='the interval between polling the server', metavar='<ARG>')
        parser.add_option('-s', '--setup', action='store_true', default=False,
                          help='setup DDoS_Wall')
        parser.add_option('-r', '--reset', action='store_true', default=False, help='resets DDoS_Wall')

        opts, args = parser.parse_args()

        # IP address must be supplied
        if opts.ip_address is None:
            print("Please supply an IP Address for the server e.g --ip_address 10.10.10.10")
            exit(-1)

        options = dict()
        options['port'] = opts.port  # port that proxy listens on
        options['ip_address'] = opts.ip_address  # IP address of server
        options['interface'] = opts.interface  # the network interface
        options['cpu_orange_threshold'] = float(opts.cpu_orange)
        options['cpu_red_threshold'] = float(opts.cpu_red)
        options['ram_orange_threshold'] = float(opts.memory_orange)
        options['ram_red_threshold'] = float(opts.memory_red)
        options['network_orange_threshold'] = float(opts.network_orange)
        options['network_red_threshold'] = float(opts.network_red)
        options['time_period'] = opts.time  # how long in minutes the running average for the monitoring should be
        options['interval'] = opts.interval # length of tim in seconds between polling resource
        options['setup'] = opts.setup  # If setup needs running
        options['reset'] = opts.reset  # Reset DDoS_Wall

        return options

    @staticmethod
    def write_firewall_script():
        """
        This method creates an iptables script which redirects all traffic for port 80 and port 443
        to DDoS_Wall on the user supplied port.
        """
        ip_address = Setup.parse_options()['ip_address']
        port = Setup.parse_options()['port']
        interface = Setup.parse_options()['interface']

        firewall_script = """#!/bin/bash
        iptables -F
        iptables -t nat -A PREROUTING -p tcp -i %s -d %s --dport 80 -j DNAT --to %s:%s
        iptables -t nat -A PREROUTING -p tcp -i %s -d %s --dport 443 -j DNAT --to %s:%s
        iptables -A FORWARD -p tcp -i %s -d %s --dport %s -j ACCEPT
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -p tcp -m tcp --dport %s -j ACCEPT
        iptables -P OUTPUT ACCEPT
        iptables -P INPUT DROP
        """ % (interface, ip_address, ip_address, port,
                                                interface, ip_address, ip_address, port,
                                                interface, ip_address, port,
                                                port)

        directory = 'resources'
        if not os.path.exists(directory):
            os.makedirs(directory)
        rules = file('resources/rules.sh', 'w')
        rules.write(firewall_script)
        rules.close()
        subprocess.call(["chmod", "755", "resources/rules.sh"])
        subprocess.call("./resources/rules.sh")


class Monitoring(threading.Thread):
    """This class contains methods for monitoring the system and turnin- g on SYN Cookies """
    def calculate_thresholds(self):
        """
        This method calculates default threshold values which are used if non are specified when DDoS_Wall
        is started.  The default values use the MAX CPU data.  The orange threshold is set at 50% higher than
        the CPU max value in the server_stats.txt and the red threshold is set a 75% higher
        :return: dict, containing thresholds
        """
        try:
            f = open('resources/server_stats.txt', 'r')
        except IOError:
            print("server_stats.txt does not exist please run ddosw_baseline")
            sys.exit()

        #  extract the value rom server_stats.txt
        stats = f.readlines()
        f.close()
        raw_stats = list()
        for line in stats:
            stats = line.split()
            raw_stats.append(stats[2])

        thresholds = dict()

        #  set the orange threshold at 50% higher than the previously recorded maximum cpu value
        #  set the red threshold at 75% higher than the previously recorded maximum cpu value
        if float(raw_stats[1]) < 57:
            thresholds['orange_cpu_threshold'] = float(raw_stats[1]) * 1.5
            thresholds['red_cpu_threshold'] = float(raw_stats[1]) * 1.75
        else:  # ensure the threshold cannot go above 100%
            thresholds['orange_cpu_threshold'] = 85
            thresholds['red_cpu_threshold'] = 95

        return thresholds

    def get_system_load(self, interval, time_period, resource):
        """
        This method continuously polls the server and calculates the average CPU, RAM and
        network usage for a specified time period.
        :param interval: The interval in seconds between polling
        :param time_period: The amount of time in minutes the average load should be calculated for
        :param resource: the resource that should be monitored
        :return: the rolling average
        """

        interval = int(interval)
        time_period = int(time_period)
        stats = []

        # get running time in minutes, div by interval plus 1 sec for network baseline
        num_of_polls = int((time_period * 60) / (interval + 1))
        i = 0
        # get the average for minimum for time period, before dropping the oldest values
        while i < num_of_polls:
            if resource == 'cpu':
                stats.append(sysmon.get_cpu_utilisation())
            elif resource == 'memory':
                stats.append(sysmon.get_memory_usage())
            elif resource == 'network':
                stats.append(sysmon.get_network_interface_traffic(INTERFACE))
            time.sleep(interval)
            i += 1
        return stats

    def update_system_load(self, interval, stats, resource):
        """
        This method updates the stats list polling the server once, taking a reading and
        appending it to the list.  The first value in the list is then removed
        :param interval: number of second to wait between polling server
        :param stats: list containing reading for the resource
        :param resource:  the resource that is being monitored
        :return: updated list of values pertaining to resource being monitored
        """
        interval = int(interval)
        if resource == 'cpu':
            latest_reading = sysmon.get_cpu_utilisation()
        elif resource == 'memory':
            latest_reading = sysmon.get_memory_usage()
        elif resource == 'network':
            latest_reading = sysmon.get_network_interface_traffic(INTERFACE)

        del stats[0]
        stats.append(latest_reading)
        print("Latest %s reading is %0.2f" % (resource, latest_reading))
        time.sleep(interval)
        return stats

    def turn_on_syn_cookies(self):
        """
        This method turns on SYN cookies
        """
        f = open("/etc/sysctl.conf", "r")
        sysyctl = f.readlines()
        syn_cookies_on = False
        for line in sysyctl:  # check if syn cookies are already turned on
            if re.search(r'^net.ipv4.tcp_syncookies = 1', line):
                syn_cookies_on = True
            else:
                syn_cookies_on = False
        f.close()
        if not syn_cookies_on:
                f = open("/etc/sysctl.conf", "a")
                f.write("net.ipv4.tcp_syncookies = 1")
                f.close()
                subprocess.call(['sysctl', '-p'])
                print("SYN cookies have been turn on")

    def run(self):
        """
        This method checks which resource should be monitored and starts polling the relevant
        resource.  If the resource exceeds the threshold SYN cookies are turned on and the polling
        stop
        """

        syn_cookies = Setup.syn_cookies
        cpu_orange_threshold = Setup.parse_options()['cpu_orange_threshold']
        cpu_red_threshold = Setup.parse_options()['cpu_red_threshold']
        network_orange_threshold = Setup.parse_options()['network_orange_threshold']
        network_red_threshold = Setup.parse_options()['network_red_threshold']
        ram_orange_threshold = Setup.parse_options()['network_orange_threshold']
        ram_red_threshold = Setup.parse_options()['ram_orange_threshold']
        interval = Setup.parse_options()['interval']
        time_period = Setup.parse_options()['time_period']

        #  Check which resources should be monitored
        if cpu_orange_threshold > 0:
            resource = "cpu"
            print("CPU is being monitored, orange threshold set at %0.2f, red threshold set to %0.2f"
                  % (cpu_orange_threshold, cpu_red_threshold))
            resource_orange_threshold = float(cpu_orange_threshold)
            resource_red_threshold = float(cpu_red_threshold)
        elif network_orange_threshold > 0:
            resource = "network"
            print("Network usage is being monitored, orange threshold set at %0.2f, red threshold set to %0.2f"
                  % (network_orange_threshold, network_red_threshold))
            resource_orange_threshold = float(network_orange_threshold)
            resource_red_threshold = float(network_red_threshold)
        elif ram_orange_threshold > 0:
            resource = "memory"
            print("Memory is being monitored, orange threshold set at %0.2f , red threshold set to %0.2f"
                  % (ram_orange_threshold, ram_red_threshold))
            resource_orange_threshold = float(ram_orange_threshold)
            resource_red_threshold = float(ram_red_threshold)
        else:
            resource = "cpu"
            resource_orange_threshold = float(self.calculate_thresholds()['orange_cpu_threshold'])
            resource_red_threshold = float(self.calculate_thresholds()['red_cpu_threshold'])
            print("CPU is being monitored, orange threshold set at %0.2f, red threshold set to %0.2f"
                  % (resource_orange_threshold, resource_red_threshold))
        stats = self.get_system_load(interval, time_period, resource)
        print("System monitor engaged")
        while True:
            system_load = 100 * float(get_mean(stats))
            print "System load is %0.2f" % system_load
            #  If system load below orange threshold change status to green
            if system_load < resource_orange_threshold and Setup.system_status != 'green':
                Setup.system_status = 'green'
                print("ALERT: System status green")
            #  If system load exceeds orange threshold change status to orange
            elif system_load  >= resource_orange_threshold  \
                    and system_load < resource_red_threshold and Setup.system_status != 'orange':
                Setup.system_status = 'orange'
                print("ALERT: System status updated to orange")
                if syn_cookies == 0:
                    print("Turning on SYN Cookies")
                    self.turn_on_syn_cookies()
                    syn_cookies = 1
            #  If system load exceeds red threshold change system status to red
            elif system_load > resource_red_threshold and Setup.system_status != 'red':
                Setup.system_status = 'red'
                print("WARNING: System status updated to Red")
            else:
                print("No conditions met")
                print("Status: %s, System_load: %0.2f, Orange_threshold: %0.2f, Red_threshold: %0.2f" %
                      (Setup.system_status, system_load, resource_orange_threshold, resource_red_threshold))
            stats = self.update_system_load(interval, stats, resource)


class Proxy(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        """
        This method intercepts the HTTP request and forwards it to server.  Any methods that
        perform checks on the request should be called from this method
        """
        server_ip = Setup.parse_options()['ip_address']
        uri = "http://" + server_ip + self.path
        response = urllib.urlopen(uri)
        self.copyfile(response, self.wfile)
        headers = self.generate_header_dic(self.headers.headers)
        ip_address = self.client_address[0]  # get client iP address
        if Setup.system_status != 'green':
            self.process_request(ip_address, headers, self.path)
            self.process_response(ip_address, response.headers)

    def generate_header_dic(self, header_strings):
        """
        This method creates a dictionary from the a list containing headers.  The returned dictionary
        contains the each header with the key as the the header name for example
        [Cookie: 'some_cookie_name=some_cookie_value]
        :param header_strings: list, containing headers
        :return: dict, containing headers
        """
        headers = dict()

        for header_values in header_strings:
            header_list = header_values.split(':')
            headers[header_list[0]] = header_list[1]
        return headers

    def block_ip_address(self, ip_address):
        """
        This method write a rule to the firewall that blocks the
        supplied IP address
        :param ip_address: ip address of requesting client
        """

        rule = "iptables -A INPUT -s " + ip_address + " -j DROP\n"
        rules = open('resources/rules.sh', 'r')
        regex = re.compile(ip_address, re.MULTILINE)
        match = regex.search(rules.read())
        rules.close()
        # check if a rule to block this ip has already been written, this can happen due to threading
        if not match:
            f = open('resources/rules.sh', 'r')
            rules = f.readlines()
            f.close()

            rules.insert(6, rule)

            f = open('resources/rules.sh', 'w')
            rules = "".join(rules)
            f.write(rules)
            f.close()
            subprocess.call(["chmod", "755", "resources/rules.sh"])
            subprocess.call("./resources/rules.sh")
            print("IP address " + ip_address + " blocked")

    def check_request_profile(self, current_connection, path, thread_lock):
        """
        check if the current request is for an expected resource
        :param current_connection:
        :param path: dictionary
        :return: None
        """
        expected_resource = False
        #  if the resource being requested matches any in the list
        if current_connection['next_resource']:
            for resource in current_connection['next_resource']:
                if path[0] == '/' and len(path) > 1:
                    path = path[1:]
                if resource == path:
                    expected_resource = True
                    current_connection['additional_resource_request_received'] = True
                    print('expected resource found')
                    print("current_connection['additional_resource_request_received'] updated to %s" %
                          current_connection['additional_resource_request_received'])

            if not expected_resource:
                if not current_connection['request_profile_penalty']:
                    self.update_score(current_connection, -100, thread_lock)
                    self.update_connection_cache(current_connection, 'request_profile_penalty', thread_lock, True)
                    print('Expected resources not requested penalty applied')
                    print('request_profile_penalty updated to: %s' % current_connection['request_profile_penalty'])
                    current_connection['request_profile_penalty'] = True
        else:
            print('no resource expected')

    def update_next_page(self, current_connection, path):
        """
        This method adds the set of resources to the next resource object in the connection cache
        that is expected after a document request
        :param current_connection: dictionary
        :param path: string, the path of the resource which is current being requested
        :return: None
        """
        base_url = 'http://' + Setup.parse_options()['ip_address']
        profile = page_profile.create_page_profile(base_url)
        resource_found = False
        for page in profile:
            if page['page_name'] == path:
                current_connection['next_resource'] = page['resources']
                resource_found = True
        if not resource_found:
            current_connection['next_resource'] = []

    def get_download_data(self, response_headers):
        """
        gets the response body size in bytes and the time the request was sent and stores them in a dictionary
        :param response_headers: response object
        :return: dictionary
        """
        data = dict()
        data['time'] = time.time()
        data['data'] = response_headers['Content-Length']
        return data

    def calculate_download_rate(self, current_connection, response_headers, time_period=60):
        """

        :param current_connection: current connection object
        :param response_headers: the response header object
        :param time_period: the time period that th
        :return: float, data per second
        """
        self.update_download_data(current_connection, response_headers)
        download_data = current_connection['download_data']
        total_data = 0.0
        latest_response_time = int(download_data[len(download_data)-1]['time'])  # time of latest response
        first_response_time = int(download_data[0]['time'])  # time of first response
        time_since_first_response = latest_response_time - first_response_time
        if time_since_first_response > time_period:
            for data in download_data:
                seconds_since_request = int(latest_response_time) - int(data['time'])
                if seconds_since_request <= time_period:  # was the response in the last x seconds
                    total_data += float(data['data'])  # calculate data requested in the last x second
            data_per_second = total_data / float(time_period)
            return data_per_second

    def get_dowload_rate_threshold(self):
        """
        This method gets the highest recorded download rate from max_download.txt, adds 20% and returns
        the values
        :return: float, max download rate
        """
        try:
            f = open('resources/max_download.txt', 'r')
            max_download_rate = float(f.readline())
            max_download_rate *= 1.20
        except IOError:
            max_download_rate = 1000
            print("No max_download.txt file found download rate set at %s, you should run ddosw_baseline first!" %
                  max_download_rate)
        return max_download_rate

    def check_download_rate(self, thread_lock, current_connection, response_headers):
        """
        This method checks if the download rate has exceeded the maximum threshold
        :param thread_lock: object, instance of thread_lock
        :param current_connection: list, the current connection list
        :param response_headers: response object
        :param threshold: int, threshold at which download rate penalty is applied
        :return: none
        """
        threshold = self.get_dowload_rate_threshold()
        data_per_second = self.calculate_download_rate(current_connection, response_headers)
        if not current_connection['download_rate_penalty']:
            if data_per_second > threshold and not current_connection['download_rate_penalty']:
                self.update_score(current_connection, -100, thread_lock)
                self.update_connection_cache(current_connection, 'download_rate_penalty', thread_lock, True)
                print('Exceeded download rate 100 deducted from connection score')
                print('download_rate_penalty updated to: %s' % current_connection['download_rate_penalty'])
                current_connection['download_rate_penalty'] = True

    def update_download_data(self, current_connection, headers):
        """
        This method adds the response size and time to the connection_cache
        :param current_connection: list, current connection data
        :param headers:object, response headers
        :return: None
        """
        download_data = current_connection['download_data']
        download_data.append(self.get_download_data(headers))

    def check_user_agent_string(self, headers, current_connection, thread_lock):
        """ This method check if the current connection has provided a user agent string if it has not 100
         point are deducted from the current connections score
        :param headers: Dict - The header of the current request
        :param current_connection: Dict - The current_connection object
        :param thread_lock: instance of thread_lock
        :return: updated score
        """
        try:
            headers['User-Agent']
        except KeyError:
            if current_connection['user_agent_penalty'] is False:
                self.update_score(current_connection, -100, thread_lock)
                self.update_connection_cache(current_connection, 'user_agent_penalty', thread_lock, True)
                print('No user agent string 100 deducted from connection score')
                print('user_agent_penalty '
                      'updated to: %s' % current_connection['user_agent_penalty'])

    def update_score(self, current_connection, number, thread_lock):
        """
        This method updates the score for the current connection
        :param current_connection: the connection cache dict for the current connection
        :param number: integer, the amount to be added to the score
        :param thread_lock: threading.Lock
        :return: None
        """
        thread_lock.acquire()
        current_connection['score'] += number
        thread_lock.release()

    def update_connection_cache(self, current_connection, key, thread_lock, value=True):
        """
        This method updates connection cache
        :param current_connection: the connection cache dict for the current connection
        :param key: string, the key for the dictionary
        :param thread_lock: instance of thread.lock
        :param value: new value
        :return: None
        """
        thread_lock.acquire()
        current_connection[key] = value
        thread_lock.release()

    def hash_value(self, value):
        """
        This method takes a string and returns a SHA256 hash of the string
        :param value: String to be hashed
        :return: string, SHA256 hash
        """
        h = hashlib.sha256()
        h.update(str(value))
        return h.hexdigest()

    def generate_token(self):
            """
            This method generates a 20 digit token
            :return:string, 20 digit number
            """
            token = randint(100000000000000000, 999999999999999999)
            return str(token)

    def check_for_ddos_token(self, headers, current_connection, thread_lock):
        """
        This method checks if the request from the current connection includes a ddos token in the cookies,
        if it does then ddos_token_received is updated to true. If however no ddos token is included and it
        is not the first request then 100 is deducted from the score.  If a DDoS token is included in a latter
        request a 100 points are added to the score.
        :param headers: dict, the http headers from the current request
        :param current_connection: list containing current connection data
        :param thread_lock: instance of thread.lock
        :return: None
        """
        ddos_token = self.hash_value(current_connection['ddos_token'])  # create SHA256 hash of DDoS_Token
        try:  # try to get cookies
            cookies = headers['Cookie']
            #  if DDoS token found and DDoS token has not already been recived
            if cookies.find(ddos_token) > 0 and current_connection['ddos_token_received'] is False:
                print('DDoS token received')
                if current_connection['ddos_token_penalty'] is True:
                    self.update_score(current_connection, 100, thread_lock)
                    current_connection['ddos_token_penalty'] = False
                current_connection['ddos_token_received'] = True
                print("ddos_token_received changed to %s" % current_connection['ddos_token_received'])
            #  if DDoS Token is not received, it is not the first request from the client
            elif current_connection['ddos_token_penalty'] is False and \
                    current_connection['ddos_token_received'] is False and \
                    len(current_connection['connection_times']) > 1:
                print('DDoS token not found')
                self.update_score(current_connection, -100, thread_lock)
                print('No DDoS token received')
                self.update_connection_cache(current_connection, 'ddos_token_penalty', thread_lock)
                print('ddoS_token_penalty updated to: %s' % current_connection['ddos_token_penalty'])
        except KeyError:  # if the headers contain no cookies and it is not the first request
            if len(current_connection['connection_times']) > 1 and current_connection['ddos_token_penalty'] is False:
                print('DDoS token not found')
                self.update_score(current_connection, -100, thread_lock)
                print('No DDoS token received')
                self.update_connection_cache(current_connection, 'ddos_token_penalty', thread_lock)
                print('ddoS_token_penalty updated to: %s' % current_connection['ddos_token_penalty'])


    def calculate_request_interval_average(self, current_connection):
        """
        This method calculates the average interval between requests.
        The lower avg that is returned the quicker the requests are coming
        the below example shows on average there is
        1 request every 2 seconds being received by the server from the host
        1.23, 1.24, 1.27, 1.30, 1.31
        1, 3, 3 ,1 = 2
        :param current_connection for the current connection
        :return: float, average interval between connections
        """
        connection_times = current_connection['connection_times']
        connection_times.append(time.time())
        previous_connection_time = 0
        connection_intervals = list()  # list containing the interval between consecutive connections
        not_first_iteration = False
        for con in connection_times:
            if not_first_iteration:
                connection_intervals.append(con - previous_connection_time)
            previous_connection_time = con
            not_first_iteration = True
        if connection_intervals:
            avg = get_mean(connection_intervals)
            return avg

    def get_request_velocity_threshold(self):
        """
        This method gets the highest recorded request velocity from max_request_velocity.txt, adds 20% and returns
        the values
        :return: float, max request velocity
        """
        try:
            f = open('resources/max_request_velocity.txt', 'r')
            max_request_velocity = float(f.readline())
            max_request_velocity *= 1.20
        except IOError:
            max_request_velocity = 10
            print("No max_request_velocity.txt file found download rate set at %s, you should run ddosw_baseline first!"
                  % max_request_velocity)
        return max_request_velocity

    def calculate_request_threshold(self, requests_per_second):
        """
        This method calculates the request threshold based on how many requests
        per second will be tolerated before marking the connection as suspicious
        :param requests_per_second: integer
        :return: request_threshold float
        """
        request_threshold = 1.0 / float(requests_per_second)
        return request_threshold

    def time_since_first_request(self, current_connection):
        """
        Calculates the amount of time between the current request and the first request made by
        the client
        :param current_connection: the connection cache dict for the current connection
        :return: float, time elapsed since first request
        """
        connection_times = current_connection['connection_times']
        time_elapsed = connection_times[len(connection_times)-1] - connection_times[0]
        return time_elapsed


    def check_request_velocity(self, current_connection, thread_lock):
        """
        This method checks if the frequency of request from the current connection
        is above the threshold and if so deducts 100 from the connection score
        If the threshold is set at 0.1 this means 10 requests per second will be
        tolerated before marking connection as suspicious.
        We don't start calculating until 1 minutes has passed since initial request from the client
        :param current_connection: the connection cache dict for the current connection
        :return: none
        """
        min_time = 60.0
        max_connections_per_second = self.get_request_velocity_threshold()
        threshold = self.calculate_request_threshold(max_connections_per_second)
        interval_average = self.calculate_request_interval_average(current_connection)
        if interval_average is not None and self.time_since_first_request(current_connection) > min_time:
            if interval_average < threshold and current_connection['request_velocity_penalty'] is False:
                self.update_score(current_connection, -100, thread_lock)
                print('request velocity over threshold 100 deducted from connection score')
                self.update_connection_cache(current_connection, 'request_velocity_penalty', thread_lock)
                print('Request_velocity_penalty updated to: %s' % current_connection['request_velocity_penalty'])

    def get_current_connection(self, ip_address, connection_cache):
        """
        This Method gets the current connection from the connection cache.  If the connection does not already have an
        entry it returns None
        :param ip_address: The ip_address of the current connection
        :return: dict for current connection
        """

        try:  # Try to find the current connection in the connection cache and return the score.
            current_connection = (item for item in connection_cache if item['ip_address'] == ip_address).next()
            return current_connection
        except StopIteration:  # If the IP address is not found in the connection cache add entry with score of 0.
            return None

    def add_connection_cache_entry(self, ip_address, thread_lock, connection_cache):
        """
        This method creates a new entry in the connection cache
        :param ip_address: string, ip address of connecting host
        :param thread_lock: instance of thread.lock
        :return: None
        """
        thread_lock.acquire()
        connection_cache.append({'ip_address': ip_address,
                                 'score': 0,
                                 'connection_times': [],
                                 'download_data': [],
                                 'user_agent_penalty': False,
                                 'request_velocity_penalty': False,
                                 'ddos_token_penalty': False,
                                 'ddos_token_received': False,
                                 'ddos_token': '12345',
                                 'download_rate_penalty': False,
                                 'request_profile_penalty': False,
                                 'additional_resource_request_received': False,
                                 'next_resource': []})
        thread_lock.release()

    def test_connection_score(self, current_connection):
        """
        This method test if the connection should be blocked based on th current system status
        :return: none
        """
        orange_score = int(Setup.orange_score)
        red_score = int(Setup.red_score)
        if Setup.system_status == 'orange':
            if current_connection['score'] <= int(orange_score):
                self.block_ip_address(current_connection['ip_address'])
        elif Setup.system_status == 'red':
            if current_connection['score'] <= red_score:
                self.block_ip_address(current_connection['ip_address'])

    def process_request(self, ip_address, headers, path):
        """
        This method check if current connection has an entry in the connection cache and
        if not creates one.  It then runs the anomaly detection algorithms which updates
        the connection score, if the score falls below threshold for the current state
        of the system the connection is blocked.
        :param ip_address: string, IP address of current connection
        :param user_agent: string, User Agent string of the current connection
        :return: None
        """
        thread_lock = threading.Lock()
        connection_cache = Setup.connection_cache
        current_connection = self.get_current_connection(ip_address, connection_cache)
        if current_connection is None:
            self.add_connection_cache_entry(ip_address, thread_lock, connection_cache)
            current_connection = self.get_current_connection(ip_address, connection_cache)
        self.check_user_agent_string(headers, current_connection, thread_lock)
        self.check_request_velocity(current_connection, thread_lock)
        self.check_for_ddos_token(headers, current_connection, thread_lock)
        if not current_connection['additional_resource_request_received']:
            self.check_request_profile(current_connection, path, thread_lock)
            self.update_next_page(current_connection, path)
        self.test_connection_score(current_connection)

    def process_response(self, ip_address, headers):
        thread_lock = threading.Lock()
        connection_cache = Setup.connection_cache
        current_connection = self.get_current_connection(ip_address, connection_cache)
        self.check_download_rate(thread_lock, current_connection, headers)
        self.test_connection_score(current_connection)

def start_ddos_wall():
    """This method starts DDoS wall running"""

    if Setup.parse_options()['setup'] or Setup.parse_options()['reset']:
        Setup.write_firewall_script()
    httpd = SocketServer.ThreadingTCPServer(('', Setup.parse_options()['port']), Proxy)
    print('Proxy is running on port ', Setup.parse_options()['port'])
    monitor = Monitoring()
    monitor.start()
    httpd.serve_forever()

if __name__ == '__main__':
    start_ddos_wall()




