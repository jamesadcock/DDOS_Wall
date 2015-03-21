#!/usr/bin/python

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


if __name__ == '__main__':
    description = """DDoS_Wall is designed to stop common types of DDoS attacks.  It offers system
     monitoring and will enable TCP cookies if the system is potentially under attack, this helps
     mitigate SYN flood attacks.  It also provide protection against HTTP based attacks which it
     will automatically attempt to detect.  The offending IP addresses will be blocked.  """

    parser = optparse.OptionParser(description=description)
    parser.add_option('-c', '--cpu_orange', default=0, help='orange threshold for CPU utilisation')
    parser.add_option('-C', '--cpu_red', default=0, help='red threshold for CPU utilisation')
    parser.add_option('-m', '--memory_orange', default=0, help='orange threshold for RAM usage')
    parser.add_option('-M', '--memory_red', default=0, help='red threshold for RAM usage')
    parser.add_option('-n', '--network_orange', default=0, help='orange threshold for Network usage')
    parser.add_option('-N', '--network_red', default=0, help='red threshold for Network usage')
    parser.add_option('-p', '--port', default=1234, help='port that proxy listens on')
    parser.add_option('-a', '--ip_address', help='MANDATORY - ip address of server')
    parser.add_option('-I', '--interface', default='eth0', help='the interface forwarding traffic')
    parser.add_option('-t', '--time', default=10, help='the number of minutes that threshold is calculated over')
    parser.add_option('-i', '--interval', default=10, help='the interval between polling th server')
    parser.add_option('-s', '--setup', action='store_true', default=False,
                      help='should be used when first running DDoS_Wall')
    parser.add_option('-r', '--reset', action='store_true', default=False, help='resets DDoS_Wall')

    opts, args = parser.parse_args()

    # IP address must be supplied
    if opts.ip_address is None:
        print("Please supply an IP Address for the server e.g --ip_address 10.10.10.10")
        exit(-1)

    PORT = opts.port  # port that proxy listens on
    SERVER_IP = opts.ip_address  # IP address of server
    INTERFACE = opts.interface  # the network interface
    CPU_ORANGE_THRESHOLD = opts.cpu_orange
    CPU_RED_THRESHOLD = opts.cpu_red
    RAM_ORANGE_THRESHOLD = opts.memory_orange
    RAM_RED_THRESHOLD = opts.memory_red
    NETWORK_ORANGE_THRESHOLD = opts.network_orange
    NETWORK_RED_THRESHOLD = opts.network_red
    TIME_PERIOD = opts.time  # how long in minutes the running average for the monitoring should be
    INTERVAL = opts.interval  # length of tim in seconds between polling resource
    SETUP = opts.setup  # If setup needs running
    RESET = opts.reset  # Reset DDoS_Wall
    system_status = 'green'  # The current state that the system is in
    syn_cookies = 0
    initial_score = 0
    orange_score = -200
    red_score = -100
    connection_cache = list()



def write_firewall_script():
    """
    This method creates an iptables script which redirects all traffic for port 80 and port 443
    to DDoS_Wall on the user supplied port.
    """
    firewall_script = """#!/bin/bash\n
    iptables -F\n
    iptables -t nat -A PREROUTING -p tcp -i %s -d %s --dport 80 -j DNAT --to %s:%s\n
    iptables -t nat -A PREROUTING -p tcp -i %s -d %s --dport 443 -j DNAT --to %s:%s\n
    iptables -A FORWARD -p tcp -i %s -d %s --dport %s -j ACCEPT\n
    \n
    #automatically generated rules\n """ % (INTERFACE, SERVER_IP, SERVER_IP, PORT, INTERFACE,
                                            SERVER_IP, SERVER_IP, PORT, INTERFACE, SERVER_IP, PORT)

    rules = file('rules.sh', 'w')
    rules.write(firewall_script)
    rules.close()
    subprocess.call(["chmod", "755", "rules.sh"])
    subprocess.call("./rules.sh")


class Monitoring(threading.Thread):
    """This class contains methods for monitoring the system and turning on SYN Cookies """
    def calculate_thresholds(self):
        """
        This method calculates default threshold values which are used if non are specified when DDoS_Wall
        is started.  The default values use the MAX CPU data.  The orange threshold is set at 50% higher than
        the CPU max value in the server_stats.txt and the red threshold is set a 75% higher
        :return: dict, containing thresholds
        """
        try:
            f = open('server_stats.txt', 'r')
        except IOError:
            print("server_stats.txt does not exist please run ddosw_baseline")
            sys.exit()

        #  extract the value rom server_stats.txt
        stats = f.readlines()
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
        global system_status
        global syn_cookies
        #  Check which resources should be monitored
        if CPU_ORANGE_THRESHOLD > 0:
            resource = "cpu"
            print("CPU is being monitored, orange threshold set at %0.2f, red threshold set to %0.2f"
                  % (CPU_ORANGE_THRESHOLD, CPU_RED_THRESHOLD))
            resource_orange_threshold = float(CPU_ORANGE_THRESHOLD)
            resource_red_threshold = float(CPU_RED_THRESHOLD)
        elif NETWORK_ORANGE_THRESHOLD > 0:
            resource = "network"
            print("Network usage is being monitored, orange threshold set at %0.2f, red threshold set to %0.2f"
                  % (NETWORK_ORANGE_THRESHOLD, NETWORK_RED_THRESHOLD))
            resource_orange_threshold = float(NETWORK_ORANGE_THRESHOLD)
            resource_red_threshold = float(NETWORK_RED_THRESHOLD)
        elif RAM_ORANGE_THRESHOLD > 0:
            resource = "memory"
            print("Memory is being monitored, orange threshold set at %0.2f , red threshold set to %0.2f"
                  % (RAM_ORANGE_THRESHOLD, RAM_RED_THRESHOLD))
            resource_orange_threshold = float(RAM_ORANGE_THRESHOLD)
            resource_red_threshold = float(RAM_RED_THRESHOLD)
        else:
            resource = "cpu"
            resource_orange_threshold = float(self.calculate_thresholds()['orange_cpu_threshold'])
            resource_red_threshold = float(self.calculate_thresholds()['red_cpu_threshold'])
            print("CPU is being monitored, orange threshold set at %0.2f, red threshold set to %0.2f"
                  % (resource_orange_threshold, resource_red_threshold))
        stats = self.get_system_load(INTERVAL, TIME_PERIOD, resource)
        print("System monitor engaged")
        while True:
            system_load = float(get_mean(stats))
            print "System load is %0.2f" % system_load
            #  If system load below orange threshold change status to green
            if system_load < resource_orange_threshold and system_status != 'green':
                system_status = 'green'
                print("ALERT: System status green")
            #  If system load exceeds orange threshold change status to orange
            elif system_load  >= resource_orange_threshold  \
                    and system_load < resource_red_threshold and system_status != 'orange':
                system_status = 'orange'
                print("ALERT: System status updated to orange")
                if syn_cookies == 0:
                    print("Turning on SYN Cookies")
                    #  self.turn_on_syn_cookies()
                    syn_cookies = 1
            #  If system load exceeds red threshold change system status to red
            elif system_load > resource_red_threshold and system_status != 'red':
                system_status = 'red'
                print("WARNING: System status updated to Red")
            else:
                print("No conditions met")
                print("Status: %s, System_load: %0.2f, Orange_threshold: %0.2f, Red_threshold: %0.2f" %
                      (system_status, system_load, resource_orange_threshold, resource_red_threshold))

            stats = self.update_system_load(INTERVAL, stats, resource)


class Proxy(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        """
        This method intercepts the HTTP request and forwards it to server.  Any methods that
        perform checks on the request should be called from this method
        """
        uri = "http://" + SERVER_IP + self.path
        response = urllib.urlopen(uri)
        self.copyfile(response, self.wfile)
        print self.headers
        headers = self.generate_header_dic(self.headers.headers)
        ip_address = self.client_address[0]  # get client iP address
        global connection_cache
        self.process_connection(ip_address, headers)

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

        rule = "\niptables -A INPUT -s " + ip_address + " -j DROP"
        rules = open('rules.sh', 'r')
        regex = re.compile(ip_address, re.MULTILINE)
        match = regex.search(rules.read())
        rules.close()
        # check if a rule to block this ip has already been written, this can happen due to forking
        if not match:
            rules = open("rules.sh", "a")
            rules.write(rule)
            rules.close()
            subprocess.call(["chmod", "755", "rules.sh"])
            subprocess.call("./rules.sh")
            print("IP address " + ip_address + " blocked")


    def check_associated_resource_requests(self):
        """
        This method checks that the connecting client has also requested any resources that are referenced
        by the page.  The may be css, javascript, images, etc.
        :return:
        """


    def check_user_agent_string(self, headers, current_connection, thread_lock):
        """ This method check if the current connection has provided a user agent string if it has not 100
         point are deducted from the current connections score
        :param user_agent: The user agent string of the current connection
        :return: updated score
        """
        try:
            user_agent = headers['User-Agent']
        except KeyError:
            if current_connection['user_agent_penalty'] is False:
                self.update_score(current_connection, -100, thread_lock)
                self.update_connection_cache(current_connection, 'user_agent_penalty', thread_lock)
                print('No user agent string 100 deducted from connection score')
                print('user_agent_penalty updated to: %s' % current_connection['user_agent_penalty'])

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
        ddos_token = '2f77668a9dfbf8d5848b9eeb4a7145ca94c6ed9236e4a773f6dcafa5132b2f91'
        try:
            cookies = headers['Cookie']
            if cookies.find(ddos_token) > 0 and current_connection['ddos_token_received'] is False:
                print('DDoS token received')
                if current_connection['ddos_token_penalty'] is True:
                    self.update_score(current_connection, 100, thread_lock)
                    current_connection['ddos_token_penalty'] = False

                current_connection['ddos_token_received'] = True
                print("ddos_token_received changed to %s" % current_connection['ddos_token_received'])

            elif current_connection['ddos_token_penalty'] is False and \
                    current_connection['ddos_token_received'] is False:
                print('DDoS token not found')
                self.update_score(current_connection, -100, thread_lock)
                print('No DDoS token received')
                self.update_connection_cache(current_connection, 'ddos_token_penalty', thread_lock)
                print('ddoS_token_penalty updated to: %s' % current_connection['ddos_token_penalty'])
        except KeyError:
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
        global connection_cache
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
        max_connections_per_second = 10
        threshold = self.calculate_request_threshold(max_connections_per_second)
        interval_average = self.calculate_request_interval_average(current_connection)
        if interval_average is not None and self.time_since_first_request(current_connection) > min_time:
            if interval_average < threshold and current_connection['request_velocity_penalty'] is False:
                self.update_score(current_connection, -100, thread_lock)
                print('request velocity over threshold 100 deducted from connection score')
                self.update_connection_cache(current_connection, 'request_velocity_penalty', thread_lock)
                print('Request_velocity_penalty updated to: %s' % current_connection['request_velocity_penalty'])

    def get_current_connection(self, ip_address):
        """
        This Method gets the current connection from the connection cache.  If the connection does not already have an
        entry it returns None
        :param ip_address: The ip_address of the current connection
        :return: dict for current connection
        """
        global connection_cache
        try:  # Try to find the current connection in the connection cache and return the score.
            current_connection = (item for item in connection_cache if item['ip_address'] == ip_address).next()
            return current_connection
        except StopIteration:  # If the IP address is not found in the connection cache add entry with score of 0.
            return None

    def add_connection_cache_entry(self, ip_address, thread_lock):
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
                                 'user_agent_penalty': False,
                                 'request_velocity_penalty': False,
                                 'ddos_token_penalty': False,
                                 'ddos_token_received': False})
        thread_lock.release()

    def test_connection_score(self, current_connection):
        """
        This method test if the connection should be blocked based on th current system status
        :return: none
        """
        global connection_cache
        global red_score
        global orange_score
        global system_status

        if system_status == 'orange':
            if current_connection['score'] <= orange_score:
                self.block_ip_address(current_connection['ip_address'])
        elif system_status == 'red':
            if current_connection['score'] <= red_score:
                self.block_ip_address(current_connection['ip_address'])


    def process_connection(self, ip_address, headers):
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
        current_connection = self.get_current_connection(ip_address)
        if current_connection is None:
            self.add_connection_cache_entry(ip_address, thread_lock)
            current_connection = self.get_current_connection(ip_address)
        self.check_user_agent_string(headers, current_connection, thread_lock)
        self.check_request_velocity(current_connection, thread_lock)
        self.check_for_ddos_token(headers, current_connection, thread_lock)
        self.test_connection_score(current_connection)

def start_ddos_wall():
    """This method starts DDoS wall running"""
    if SETUP or RESET:
        write_firewall_script()
    httpd = SocketServer.ThreadingTCPServer(('', PORT), Proxy)
    print('Proxy is running on port ', PORT)
    monitor = Monitoring()
    monitor.start()
    httpd.serve_forever()

if __name__ == '__main__':
    start_ddos_wall()




