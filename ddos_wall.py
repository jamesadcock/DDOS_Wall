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


if __name__ == '__main__':
    description = """DDoS_Wall is designed to stop common types of DDoS attacks.  It offers system
     monitoring and will enable TCP cookies if the system is potentially under attack, this helps
     mitigate SYN flood attacks.  It also provide protection against HTTP based attacks which it
     will automatically attempt to detect.  The offending IP addresses will be blocked.  """

    parser = optparse.OptionParser(description=description)
    parser.add_option('-c', '--cpu_orange', default=0, help='orange threshold for CPU utilisation')
    parser.add_option('-C', '--cpu_red', default=0, help='red threshold for CPU utilisation')
    parser.add_option('-m', '--memory', default=0, help='threshold for RAM usage')
    parser.add_option('-n', '--network', default=0, help='threshold for Network usage')
    parser.add_option('-p', '--port', default=1234, help='port that proxy listens on')
    parser.add_option('-a', '--ip_address', help='MANDATORY - ip address of server')
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
    CPU_ORANGE_THRESHOLD = opts.cpu_orange
    CPU_RED_THRESHOLD = opts.cpu_red
    RAM_THRESHOLD = opts.memory
    NETWORK_THRESHOLD = opts.network
    TIME_PERIOD = opts.time  # how long in minutes the running average for the monitoring should be
    INTERVAL = opts.interval  # length of tim in seconds between polling resource
    SETUP = opts.setup  # If setup needs running
    RESET = opts.reset  # Reset DDoS_Wall
    system_status = 'green'  # The current state that the system is in
    syn_cookies = 0
    initial_score = 0
    orange_score = -500
    red_score = -200
    connection_cache = list()



def write_firewall_script():
    """
    This method creates an iptables script which redirects all traffic for port 80 and port 443
    to DDoS_Wall on the user supplied port.
    """
    firewall_script = """#!/bin/bash\n
    iptables -F\n
    iptables -t nat -A PREROUTING -p tcp -i eth0 -d %s --dport 80 -j DNAT --to %s:%s\n
    iptables -t nat -A PREROUTING -p tcp -i eth0 -d %s --dport 443 -j DNAT --to %s:%s\n
    iptables -A FORWARD -p tcp -i eth0 -d %s --dport %s -j ACCEPT\n
    \n
    #automatically generated rules\n """ % (SERVER_IP, SERVER_IP, PORT, SERVER_IP, SERVER_IP, PORT, SERVER_IP, PORT)

    rules = file('rules.sh', 'w')
    rules.write(firewall_script)
    rules.close()
    subprocess.call(["chmod", "755", "rules.sh"])
    subprocess.call("./rules.sh")


class Monitoring(threading.Thread):
    """This class contains methods for monitoring the system and turning on SYN Cookies """
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
            subprocess.call(["bash", "%s_stats.sh" % resource])
            time.sleep(interval)
            f = open("%s_stats.txt" % resource, 'r')
            stats.append(str(f.read()).rstrip())
            i += 1
        f.close()
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
        subprocess.call(["bash", "%s_stats.sh" % resource])
        time.sleep(interval)
        f = open("%s_stats.txt" % resource, 'r')
        del stats[0]
        latest_reading = str(f.read()).rstrip()
        stats.append(latest_reading)
        print("Latest %s reading is %s " % (resource, latest_reading))
        f.close()
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
            print("CPU is being monitored, orange threshold set at %s, red threshold set to %s"
                  % (CPU_ORANGE_THRESHOLD, CPU_RED_THRESHOLD))
            resource_orange_threshold = float(CPU_ORANGE_THRESHOLD)
            resource_red_threshold = float(CPU_RED_THRESHOLD)
        elif NETWORK_THRESHOLD > 0:
            resource = "network"
            print("Network usage is being monitored, threshold set at %s" % NETWORK_THRESHOLD)
            resource_threshold = NETWORK_THRESHOLD
        elif RAM_THRESHOLD > 0:
            resource = "memory"
            print("Memory is being monitored, threshold set at %s" % RAM_THRESHOLD)
            resource_threshold = RAM_THRESHOLD
        else:
            print('No threshold value supplied, system monitor will not be started')
            return
        stats = self.get_system_load(INTERVAL, TIME_PERIOD, resource)
        print("System monitor engaged")
        while True:
            system_load = float(get_mean(stats))
            print "System load is %s" % system_load
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
                    self.turn_on_syn_cookies()
                    syn_cookies = 1
            #  If system load exceeds red threshold change system status to red
            elif system_load > resource_red_threshold and system_status != 'red':
                system_status = 'red'
                print("WARNING: System status updated to Red")
            else:
                print("No conditions met")
                print("Status: %s, System_load: %s, Orange_threshold: %s, Red_threshold: %s " %
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
        try:
            user_agent = self.headers.headers[1]  # get user agent string
        except:
            user_agent = ""
        ip_address = self.client_address[0]  # get client iP address
        if user_agent == "":
            print("No user agent")
        else:
            print(user_agent)
        global connection_cache
        print("connection_cache before processing: ", connection_cache)
        self.process_connection(ip_address, user_agent)
        print("connection_cache after processing: ", connection_cache)


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
            print("IP address " + ip_address + " blocked, no user agent string")

    def check_user_agent_string(self, user_agent, score):
        """ This method check if the current connection has provided a user agent string if it has not 100
         point are deducted from the current connections score
        :param user_agent: The user agent string of the current connecection
        :param score: The score of the current connection
        :return: updated score
        """
        if user_agent == "":
            score -= 100
        return score

    def get_current_connection_score(self, ip_address, thread_lock):
        """
        This Method get the score of the current connection.  If the connection does not already have n entry
        in the connection cache then a entry is added.
        :param ip_address: The ip_address of the current connection
        :param thread_lock: instance of threading.lock
        :return: the current connections score
        """
        global connection_cache
        try:  # Try to find the current connection in the connection cache and return the score.
            current_connection = (item for item in connection_cache if item['ip_address'] == ip_address).next()
            return current_connection['score']
        except StopIteration:  # If the IP address is not found in the connection cache add entry with score of 0.
            thread_lock.acquire()
            connection_cache.append({'ip_address': ip_address, 'score': 0})
            thread_lock.release()
            return 0

    def update_current_connection_score(self, ip_address, score, thread_lock):
        """
        Thus method updates the current connections score with an new score.  It also 
        :param ip_address: IP address of the current connection
        :param score:  The new score to update the original score with
        :param thread_lock: instance of threading.lock
        :return: none
        """
        global connection_cache
        global red_score
        global orange_score
        global system_status

        try:  #  try to find the current connection in the coonection  cache
            current_connection = (item for item in connection_cache if item['ip_address'] == ip_address).next()
            thread_lock.acquire()
            current_connection['score'] = score
            thread_lock.release()
            if system_status == 'orange':
                if score <= orange_score:
                    self.block_ip_address(current_connection['ip_address'])
            elif system_status == 'red':
                if score <= red_score:
                    self.block_ip_address(current_connection['ip_address'])
        except StopIteration:
            print("Something went wrong unable to find ip address %s" % ip_address)
            print(connection_cache)

    def process_connection(self, ip_address, user_agent):
        thread_lock = threading.Lock()
        score = self.get_current_connection_score(ip_address, thread_lock)
        score = self.check_user_agent_string(user_agent, score)
        self.update_current_connection_score(ip_address, score, thread_lock)


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




