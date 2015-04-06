"""
This module spider the servers publicly available documents and creates a dictionary object for each
document.  The dictionary object has the following structure:
{page_name: page_name, resources: [resource1, resource2, ...] }
"""


__author__ = 'James Adcock'

__version__ = "1.0"


import BeautifulSoup
import urllib2
import re
import urlparse


def create_page_profile(base_url):
    """
    This method spiders the servers publicly available documents and creates a dictionary object for each
    document
    :param base_url: The base url for the server
    :return: page_profile, list {page_name: page_name, resources: [resource1, resource2, ...] }
    """
    page_name = '/'
    url = base_url + page_name  # url of home page
    links = list()
    links.append(url)
    page_profile = list()

    index = 0
    while True:  # continue to spider site
        resources = list()  # list of external page resources, CSS, JavaScript, images
        try:
            page_object = BeautifulSoup.BeautifulSoup(urllib2.urlopen(links[index]).read())
            resources = get_resources(resources, page_object, base_url)  # get page resources
            links = get_links(links, page_object, base_url)  # get a list of all the links on th page
            links = remove_duplicates(links)  # remove any duplicate link for the list
            page_profile.append({'page_name': convert_to_relative_path(links[index]), 'resources': resources})
            if len(links) - 1 == index:  # keep spidering until end of links list
                break
            index += 1
        except urllib2.HTTPError:  # if 404 page not found
            del links[index]  # delete path
            index -= 1
            if len(links) - 1 == index:  # keep spidering until end of links list
                break

    return page_profile


def convert_to_absolute_path(path, base_url):
    """
    This method take a relative path and converts it to a absolute path.  If a absolute path is provided
    it is just returned
    :param path: string, the path to be converted
    :param base_url: string, the base URL, used to create absolute path
    :return:  String, the absolute path
    """
    match = re.search(r'^http', path)
    if match:  # if path is already absolute then return as ia
        return path
    else:  # if it is relative path use ase_url to convert to an absolute path
        url = urlparse.urlparse(base_url)
        path = path.replace('/', '')
        path = url.scheme + '://' + url.hostname + '/' + path + url.query
        return path


def convert_to_relative_path(path):
    """
    This method takes absolute path and converts it to a relative path.  If a relative path is provided
    it is just returned
    :param path: string, the path to be converted
    :param base_url: string, the base URL, used to create absolute path
    :return:  String, the absolute path
    """
    match = re.search(r'^http', path)
    if not match:  # if path is already relative then return as ia
        return path
    else:  # if it is relative path use ase_url to convert to an absolute path
        url = urlparse.urlparse(path)
        path = url.path
        return path


def remove_duplicates(item_list):
    """
    Removes any duplicate entries from the provided list
    :param item_list: list, any list
    :return: list, with duplicate entries removed
    """
    unique_list = []
    [unique_list.append(i) for i in item_list if not unique_list.count(i)]
    return unique_list


def get_resources(resources, soup, base_url):
    """
    :param resources: list of page resources
    :param soup: beutifulsoup object
    :param base_url: string, base url of site
    :return: list, updated list containing page resources
    """

    #  find <img>, <link> and <script> tags
    try:  # find <img> tags and create a list containing them
        images = soup.findAll('img')
    except:  # if none on page catch exception and do nothing
        pass
    try:   # find <link> tags (usually css) and create a list containing them
        style_sheets = soup.findAll('link')
    except:  # if none on page catch exception and do nothing
        pass
    try:  # find <script> tags (usually JS) and create a list containing them
        scripts = soup.findAll('script')
    except:  # if none on page catch exception and do nothing
        pass

    # find src attribute in img tags
    for image in images:
        try:
            resources.append(str(image['src']))
        except KeyError:  # if none found do nothing
            pass

    # find href attribute in link tags
    for style_sheet in style_sheets:
        try:
            resources.append(str(style_sheet['href']))
        except KeyError:
            pass

    # find src attribute in script tags
    for script in scripts:
        try:
            if is_non_site_link(script['src'], base_url):
                pass
            else:
                resources.append(str(script['src']))
        except KeyError:
            pass

    return resources


def get_links(links, soup, base_url):
    """
    This method returns a list of all the hyperlinks on the page
    :param links: list, current list of hyperlinks
    :param soup: beutifulsoup object
    :param base_url:  string, base URL of site
    :return:  lists of links
    """
    try:
        hyperlinks = soup.findAll('a')
        for hyperlink in hyperlinks:
            if is_non_site_link(hyperlink['href'], base_url):
                pass
            else:
                url = convert_to_absolute_path(hyperlink['href'], base_url)
                links.append(str(url))
        return links
    except:
        return links


def is_non_site_link(link, base_url):
    """
    This method checks if the provided link is an internal link of an external link and returns
    True or False
    :param link: string
    :param base_url: the base URL of the site
    :return: boolean
    """
    match = re.search(r'^http', link)
    if match:  # check if link contains http
        match = re.search(base_url, link)
        if match:  # check if link contains base URL
            return False
        else:  # if it does not it must e external
            return True
    else:  # if link does not contain http must be relative and therefore internal
        return False

if __name__ == '__main__':
    uri = raw_input("Please enter base URL, e.g. http://example.com: ")
    print create_page_profile(uri)
