import apache_log_parser
import os

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
    moving_average_period = 60.0
    try:
        start_time = int(client_data[0]['download_data'][0]['time'])
    except IndexError:
        print 'No log data'
        exit()
    end_time = start_time + moving_average_period
    maximum = 0
    for client in client_data:
        first_request_time = client['download_data'][0]['time']  # the first time the client made a request
        last_request_time = client['download_data'][len(client['download_data'])-1]['time']  # last client request time
        request_duration = last_request_time - first_request_time  # number of seconds between first and last request
        i = 0
        # while less than the number of seconds between the first and last request keep iterating and incrementing i by
        # 1.
        while i <= request_duration:
            total = 0
            # check if each time is between that start time and end time for the moving average period and if it is
            # add the amount of data sent in the response to the total.  Then calculate the
            # current average by dividing the total amount of data by the moving average time period
            # e.g. if moving time period is 60 seconds andi n the last 60 seconds the client has downloaded
            # 1000 byes the average would be 50 bytes per second
            # if this the highest value encountered so far it is stored in the maximum variable
            for response in client['download_data']:
                if response['time'] >= start_time + i and response['time'] <= end_time + i:
                    total += float(response['size'])
                avg = total / moving_average_period
                if avg > maximum:
                    maximum = avg
            i += 1

    write_to_file('resources/max_download.txt', maximum)
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
    for client in client_data:
        first_request_time = client['download_data'][0]['time']  # the first time the client made a request
        last_request_time = client['download_data'][len(client['download_data'])-1]['time']  # last client request time
        request_duration = last_request_time - first_request_time  # number of seconds between first and last request
        i = 0
        # while less than the number of seconds between the first and last request keep iterating and incrementing i by
        # 1.
        while i <= request_duration:
            total = 0
            # check if each time is between that start time and end time for the moving average period and if it is
            # increment the total variable by 1 to indicate another request in this time period.  Then calculate the
            # current average by dividing the total requests by the moving average time period e.g. if moving time
            # period is 60 seconds and in the last 60 seconds the client has made 20  requests the average
            # would be 0.33 requests per second if this the highest value encountered so far it is stored
            # in the maximum variable
            for response in client['download_data']:
                if response['time'] >= start_time + i and response['time'] <= end_time + i:
                    total += 1.0
                avg = total / moving_average_period
                if avg > maximum:
                    maximum = avg
            i += 1

    write_to_file('resources/max_request_velocity.txt', maximum)
    return maximum


def write_to_file(file_name, data):
    """
    This method gets the maximum download value and writes it to a file max_download.txt
    :return:
    """
    directory = "resources"
    if not os.path.exists(directory):
        os.makedirs(directory)
    f = open(file_name, 'w')
    f.write(str(data))
    f.close()


if __name__ == '__main__':
    print get_maximum_download()
    print get_maximum_request_velocity()
