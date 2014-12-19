#!/usr/bin/python

import SocketServer
import SimpleHTTPServer
import urllib
import subprocess
import re


PORT = 1234  # port that proxy listens on
SERVER_IP = "192.168.0.4"  # IP address of server

#  Intercept the HTTP request and forward to server
class Proxy(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        uri = "http://" + SERVER_IP + self.path
        response = urllib.urlopen(uri)
        self.copyfile(response, self.wfile)
        try:
            user_agent = self.headers.headers[1]  # get user agent string
        except:
            user_agent = ""
        ip_address = self.client_address[0]  # get client iP address
        print(user_agent)
        self.check_user_agent_string(ip_address, user_agent)

    # Check the user agent string and block requesting IP address if any anomalies found
    def check_user_agent_string(self, ip_address, user_agent):
        if user_agent == "":  # if no user agent string sent block IP address
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

httpd = SocketServer.ForkingTCPServer(('', PORT), Proxy)
print('Proxy is running on port ', PORT)
httpd.serve_forever()






