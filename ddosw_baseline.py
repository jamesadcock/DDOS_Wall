import time
import optparse
import sysmon
import log_scraper

if __name__ == '__main__':
    description = """ddosw_baseline should be used to generate a baseline of the server's performance.
                     Ran without any options it displays the last report, if the -g option is passed a
                     new report is generated.  It generates the mean and max values for CPU utilisation,
                     RAM utilisation and mb/s network usage.  Make sure you run as root!!!"""

    parser = optparse.OptionParser(description=description)

    parser.add_option('-t', '--time', default=1, help="The number of minutes to run")
    parser.add_option('-i', '--interval', default=10, help="The interval between polling server")
    parser.add_option('-g', '--generate_report', action='store_true', default=False,
                      help="add this option to generate a new report")
    parser.add_option('-a', '--adaptor', default='wlan0', help="The network interface to monitor")
    parser.add_option('-r', '--rolling', default='1', help="Minutes rolling average should be calculated over")

    opts, args = parser.parse_args()

    RUNNING_TIME = opts.time
    INTERVAL = opts.interval
    GENERATE_REPORT = opts.generate_report
    NETWORK_ADAPTOR = opts.adaptor
    ROLLING_AVERAGE_PERIOD = opts.rolling


def create_baseline(running_time, interval, max_average_time_period=1):
    """
    This method calculates the average cpu utilisation, network usage and memory usage over the period that
    ddow_baseline is ran for.  It also calculates the maximum values for the  cpu utilisation, network usage
    and memory usage this is done however using a moving average over 1 minute (unless specified by user).
    :param running_time: int, number of minutes it should run for
    :param interval:int, number of seconds to wait between polling
    :param max_average_time_period: int, number of minutes moving average should be calculated over
    :return:
    """

    # get running time in minutes, div by interval plus 1 sec for network baseline
    num_of_polls = int((running_time * 60) / (interval + 1))
    max_average_num_of_polls = int((max_average_time_period * 60) / (interval + 1))
    cpu_utilisation = list()
    network_usage = list()
    memory_usage = list()
    cpu_utilisation_max = list()
    network_usage_max = list()
    memory_usage_max = list()
    i = 0
    max_cpu_average = 0
    max_network_average = 0
    max_memory_average = 0

    while i < num_of_polls:
        #  create a list containing the CPU utilisation, memory usage and network usage over the entire period the
        # baseline is ran for.
        cpu = sysmon.get_cpu_utilisation()
        network = sysmon.get_network_interface_traffic(NETWORK_ADAPTOR)
        memory = sysmon.get_memory_usage()['memory_in_use']
        cpu_utilisation.append(cpu)
        network_usage.append(network)
        memory_usage.append(memory)

        #  get the maximum values for the maximum cpu utilisation, network usage and memory usage.  These values
        #  are calculated using a move average over a specified period of time
        if i <= max_average_num_of_polls:
            cpu_utilisation_max.append(cpu)
            network_usage_max.append(network)
            memory_usage_max.append(memory)
        else:
            del cpu_utilisation_max[0]
            cpu_utilisation_max.append(cpu)
            cpu_average = get_mean(cpu_utilisation_max)
            if cpu_average > max_cpu_average:
                max_cpu_average = cpu_average
            del network_usage_max[0]
            network_usage_max.append(network)
            network_average = get_mean(network_usage_max)
            if network_average > max_network_average:
                max_network_average = network_average
            del memory_usage_max[0]
            memory_usage_max.append(memory)
            memory_average = get_mean(memory_usage_max)
            if memory_average > max_memory_average:
                max_memory_average = memory_average

        time.sleep(interval)
        i += 1

    # calculate the mean average from all the values in the list
    average_cpu_utilisation = get_mean(cpu_utilisation)
    average_network_usage = get_mean(network_usage)
    average_memory_usage = get_mean(memory_usage)

    # print the results to the console and write them to server_stats.txt
    resource_stats = "CPU Average: %0.2f %%\nCPU Max %0.2f %%\nNetwork Average: %0.2f bytes per second\n" \
                     "Network Max: %0.2f bytes per second\nMemory Average: %0.2f MB\nMemory Max: %0.2f MB" % \
                     (average_cpu_utilisation*100, max_cpu_average*100, average_network_usage,
                      max_network_average, average_memory_usage/100, max_memory_average/100)
    f = open('server_stats.txt', 'w')
    f.write(resource_stats)
    f.close()
    print_results()


def get_mean(stats):
    """
    This method returns the mean value of all the numbers within the file or list
    :param stats : A file or list containing numbers
    :return: The means value of all the values in the file or list
    """

    if type(stats) is not list:
        f = open(stats, 'r')
        num_list = f.read().splitlines()
    else:
        num_list = stats
    total = 0.0
    for num in num_list:
        total += float(num)
    mean = total / len(num_list)
    return mean


def print_results():
        f = open('server_stats.txt', 'r')
        stats = f.read()
        print("\nDDOS_Wall system statics:\n-----------------\n%s\n-------------------" % stats)
        f.close()


if __name__ == '__main__':
    if GENERATE_REPORT:
        print("Generating report this will take %s minutes" % RUNNING_TIME)
        create_baseline(int(RUNNING_TIME), int(INTERVAL), int(ROLLING_AVERAGE_PERIOD))
        log_scraper.write_max_download_to_file()

    else:
        print_results()




