import re
import time
import datetime
from datetime import timedelta
import apache_log_parser

client_data = list()


def add_client_data(ip_address):
        global client_data
        client_data.append({'ip_address': ip_address,
                            'download_data': [],
                            })


def get_current_client_data(ip_address):
    """
    This Method gets the data pertaining to the supplied ip address.  If the connection does not already have an
    entry it returns None
    :param ip_address: string, ip address
    :return: dict for client
    """
    global client_data
    try:  # Try to find the client data
        client = (item for item in client_data if item['ip_address'] == ip_address).next()
        return client
    except StopIteration:
        return None


def update_client_data():
    """
    This method updates the client_data with the time and size of the response
    :return: None
    """
    logs = apache_log_parser.parse_access_logs()
    for log in logs:
        current_client = get_current_client_data(log['host'])
        if current_client is None:
            add_client_data(log['host'])
            current_client = get_current_client_data(log['host'])
        current_client['download_data'].append({'size': log['size'], 'time': int(log['time'].strftime("%s"))})


def get_maximum_download():
    global client_data
    update_client_data()
    try:
        start_time = int(client_data[0]['download_data'][0]['time'])
    except IndexError:
        print 'No log data'
        exit()
    end_time = start_time + 60
    maximum = 0
    for connection in client_data:
        download_data_length = len(connection['download_data'])
        i = 0
        while i <= download_data_length:
            total = 0
            for response in connection['download_data']:
                if response['time'] >= start_time + i and response['time'] <= end_time + i:
                    total += float(response['size'])
                avg = total / 60.0
                if avg > maximum:
                    maximum = avg
            i += 1

    write_to_file('max_download.txt', maximum)
    return maximum

def get_maximum_request_velocity():
    global client_data
    update_client_data()
    moving_average_period = 60.0
    try:
        start_time = int(client_data[0]['download_data'][0]['time'])
    except IndexError:
        print 'No log data'
        exit()
    end_time = start_time + moving_average_period
    maximum = 0
    for connection in client_data:
        download_data_length = len(connection['download_data'])
        i = 0
        while i <= download_data_length:
            total = 0
            for response in connection['download_data']:
                if response['time'] >= start_time + i and response['time'] <= end_time + i:
                    total += 1.0
                avg = total / moving_average_period
                if avg > maximum:
                    maximum = avg
            i += 1

    write_to_file('max_request_velocity.txt', maximum)
    return maximum


def write_to_file(file_name, data):
    """
    This method gets the maximum download value and writes it to a file max_download.txt
    :return:
    """
    f = open(file_name, 'w')
    f.write(str(data))
    f.close()


if __name__ == '__main__':
    get_maximum_download()
    get_maximum_request_velocity()
