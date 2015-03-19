"""
This module output statistics regarding a system current load.  It is designed to run on a Linux based system
and has been tested on Ubuntu 14.04LTS.  It returns of outputs the CPU utilisation over a specified period of
time.   The amount of data in bytes passing through a network card in a specified period of time.  The amount of
RAM that is currently in use by the system and the amount that is currently free.
"""

#  Author James Adcock

__version__ = "1.0"

import time
import re
import optparse

def get_cpu_utilisation(sleep_time=1):
    """
    This method calculates and returns the system's CPU utilisation. It does this by reading CPU
    the idle time from the /proc/stat file, waiting for the amount of time specified by
    sleep_time and then taking another reading.  The following calculation is then
    performed:
    Utilisation + (1st idle reading - 2nd idle reading) / (1st total  running time - 2nd total  running time))

    :param sleep_time: int, the number of seconds the utilisation is calculated over
    :return: float, CPU utilisation
    """
    f = open('/proc/stat', 'r')  # this file contains data regarding the CPU

    # get first reading
    cpu_stats = f.readline().split()  # get cpu stats
    idle_reading_1 = float(cpu_stats[4])
    total_reading_1 = float(cpu_stats[1]) + float(cpu_stats[2]) + float(cpu_stats[3]) \
                      + float(cpu_stats[4]) + float(cpu_stats[5])

    # wait for specified period of time
    time.sleep(sleep_time)
    f.seek(0)  # return to first line of file

    # get second reading
    cpu_stats = f.readline().split()  # get cpu stats
    idle_reading_2 = float(cpu_stats[4])
    total_reading_2 = float(cpu_stats[1]) + float(cpu_stats[2]) + float(cpu_stats[3])\
                      + float(cpu_stats[4]) + float(cpu_stats[5])
    f.close()

    # calculate the amount of time that the CPU has spent idle between the first and second reading convert it
    # into a decimal
    cpu_utilisation = 1 - (idle_reading_2 - idle_reading_1) / (total_reading_2 - total_reading_1)
    return cpu_utilisation


def get_network_interface_traffic(interface, sleep_time=1):
    """
    This method calculates and returns the number of bytes passing through an interface in the specified number
    of seconds.  It does this by reading the total number of bytes that has passed through the network
    adaptor since start up from the /proc/net/dev file.  It then waits for the specified number of seconds,
    takes another reading and performs the following calculation:
    total bytes per x seconds = second reading - first reading
    :param interface: string, the network interface
    :param sleep_time: int, number of seconds to wait between readings
    :return: int, bytes per seconds
    """
    f = open('/proc/net/dev', 'r')  # this file contains network data

    # get first reading
    network_stats = f.readlines()  # get network stats
    for line in network_stats:
        if re.search(interface, line):
            network_stats = line.split()
    interface_reading_1 = int(network_stats[9])

    # wait for specified period of time
    time.sleep(sleep_time)
    f.seek(0)  # return to first line of file

    # get second reading
    network_stats = f.readlines()
    for line in network_stats:
        if re.search(interface, line):
            network_stats = line.split()
    interface_reading_2 = int(network_stats[9])

    f.close()

    # calculate the amount of data in bytes that has passed through the
    # network card between the first and second reading
    bytes_per_seconds = interface_reading_2 - interface_reading_1  # number of bytes between reading
    return bytes_per_seconds

def get_memory_usage():
    """
    This method returns a dictionary containing the amount of RAM that is in use and the amount of free RAM.  It does
    this by reading the values from the /proc/meminfo file.  To calculate the total RAM the following calculation is
    performed
    RAM in use = total RAM - Free RAM
    :return: dict: RAM in use, Free RAM
    """
    f = open('/proc/meminfo', 'r')  # this file contains data regarding memory usage

    memory_stats = f.readlines()
    for line in memory_stats:
        if re.search('MemTotal:', line):  # find total RAM
            total_memory = line.split()
        if re.search('MemFree', line):  # find free RAM
            free_memory = line.split()

    #  calculate the amount of memory that is currently being used and add it to dictionary.  Add the amount of
    #  memory that is currently free to dictionary
    memory_usage = {'memory_in_use': int(total_memory[1]) - int(free_memory[1]), 'free_memory': int(free_memory[1])}
    return memory_usage  # return to RAM in use and Free RAM

def print_stats(network_adaptor):
    """
    This method prints the current CPU utilisation, the data passed though the network adaptor each second and the
    free RAM and the amount of RAM in use
    :param: Network adaptor: String, the network adaptor to monitor
    :return: None
    """
    cpu_utilisation = get_cpu_utilisation()*100
    memory_used = float(get_memory_usage()['memory_in_use'])/1000.0  # get total used convert to MB
    free_memory = float(get_memory_usage()['free_memory'])/1000.0  # get total free memory and convert to MB

    print('Current System Status is:\nCPU Utilisation: %0.2f% % \nNetwork Interface load: %s'
          ' bytes per second\nMemory in use: %s MB\nMemory free: %s MB' %
          (cpu_utilisation, get_network_interface_traffic(network_adaptor), memory_used, free_memory))

if __name__ == '__main__':
    description = """SysMon, returns the following system stats CPU utilisation (over 1 second), the
                     amount of data that has passed through te network adaptor (over 1 second), and
                     the current memory in use and the current free memory"""

    parser = optparse.OptionParser(description=description)
    parser.add_option('-a', '--adaptor', default='wlan0', help="Network adaptor to monitor")
    opts, args = parser.parse_args()
    network_adaptor = opts.adaptor
    print_stats(network_adaptor)