import pandas as pd
from functools import cache
from tld import get_tld
from urllib.parse import urlparse
import re


def process_tld(url):
    try:
        res = get_tld(url, as_object=True, fail_silently=False, fix_protocol=True)
        pri_domain = res.parsed_url.netloc
    except:
        pri_domain = None
    return pri_domain


def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


def http_secure(url):
    htp = urlparse(url).scheme
    match = str(htp)
    if match == 'https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0


def digit_count(url):
    digits = 0
    for i in url:
        if i.isnumeric():
            digits = digits + 1
    return digits


def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters


def shortining_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0


def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4 with port
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '([0-9]+(?:\.[0-9]+){3}:[0-9]+)|'
        '((?:(?:\d|[01]?\d\d|2[0-4]\d|25[0-5])\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d|\d)(?:\/\d{1,2})?)', url)  # Ipv6
    if match:
        return 1
    else:
        return 0


@cache
def category(type_url: str):
    categories = {"benign": 0, "defacement": 1, "phishing": 2, "malware": 3}
    return categories[type_url]


def split_url(url: str):
    res = dict()

    url = url.replace('www.', '', 1)

    res['url'] = url
    res['url_len'] = len(url) / 100
    # res['domain'] = process_tld(url)

    feature = ['@', '?', '-', '=', '.', '#', '%', '+', '$', '!', '*', ',', '//']
    for a in feature:
        res[a] = url.count(a) / 5

    res['abnormal_url'] = abnormal_url(url)
    res['https'] = http_secure(url)
    res['digits'] = digit_count(url) / 10
    res['letters'] = letter_count(url) / 90
    res['shortining_service'] = shortining_service(url)
    res['having_ip_address'] = having_ip_address(url)

    return res


def convert_url(url: str):
    splited = split_url(url)
    splited.pop('url')
    return tuple(splited.values())


def main():
    file = pd.read_csv('malicious_phish.csv')

    file['category'] = 0
    file['url_len'] = 0
    file['@'] = 0
    file['?'] = 0
    file['-'] = 0
    file['='] = 0
    file['.'] = 0
    file['#'] = 0
    file['%'] = 0
    file['+'] = 0
    file['$'] = 0
    file['!'] = 0
    file['*'] = 0
    file[','] = 0
    file['//'] = 0
    file['abnormal_url'] = 0
    file['https'] = 0
    file['digits'] = 0
    file['letters'] = 0
    file['shortining_service'] = 0
    file['having_ip_address'] = 0

    for index, row in file.iterrows():

        file.at[index, 'category'] = category(row['type'])
        url = row['url']

        cats = split_url(url)
        for cat in cats.keys():
            file.at[index, cat] = cats[cat]

    file.to_csv('updated.csv', index=False)


if __name__ == '__main__':
    main()

