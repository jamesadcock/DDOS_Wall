import subprocess
import time
import optparse

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

    opts, args = parser.parse_args()

    RUNNING_TIME = opts.time
    INTERVAL = opts.interval
    GENERATE_REPORT = opts.generate_report


def create_baseline(running_time, interval):
    """
    This method runs a bash script that records the CPU, RAM and network usage of the system.
    :param running_time: The length of time in minutes which system should be polled for.
    :param interval: The interval in seconds between polling
    """

    # get running time in minutes, div by interval plus 1 sec for network baseline
    num_of_polls = int((running_time * 60) / (interval + 1))
    i = 0
    while i < num_of_polls:
        subprocess.call(["bash", "baseline.sh"])
        time.sleep(interval)
        i += 1


def get_sever_stats():
    """
    This method print the maximum and average CPU, RAM, Network usage
    """
    print("Average CPU load: %.2f" % get_mean('cpu_baseline.txt'))
    print("Maximum CPU load: %s " % get_max('cpu_baseline.txt'))
    print('-----------------------------------')
    print("Average memory load: %.2f" % get_mean('memory_baseline.txt'))
    print("Maximum memory load: %s " % get_max('memory_baseline.txt'))
    print('-----------------------------------')
    print("Average network load: %.2f" % get_mean('network_baseline.txt'))
    print("Maximum network load: %s\n\n " % get_max('network_baseline.txt'))


def get_max(stat_file):
    """
    This method returns the highest value contained within the supplied file
    :param stat_file: A file containing numbers
    :return: the maximum value contained within the file
    """
    f = open(stat_file, 'r')
    num_list = f.read().splitlines()
    return max(num_list)


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

if __name__ == '__main__':
    if GENERATE_REPORT:
        print("Generating report this will take %s minutes" % RUNNING_TIME)
        create_baseline(int(RUNNING_TIME), int(INTERVAL))
        print("Report generated:\n\n")
        get_sever_stats()
    else:
        print("\n\nLast report below, to genrate a new report run with option -g set:\n\n")
        get_sever_stats()






