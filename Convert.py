#!/usr/bin/env python3
import pandas as pd
import numpy as np
from functools import cache


def get_proticol(protocol):
    if protocol is None:
        return 0
    elif protocol == 'http':
        return 2
    elif protocol == 'https':
        return 3
    else:
        return 1


def get_subdomain(subdomain):
    top = encode_top(subdomain[-1])
    if len(subdomain) == 3:
        www = 1
        sub = len(subdomain[1])
    else:
        www = 0
        sub = len(subdomain[0])
    return www, sub, top


@cache
def encode_top(top):
    code = 0
    for letter in top:
        code += ord(letter)
    return code


@cache
def get_type(url_type):
    if url_type == 'phishing':
        return 0
    elif url_type == 'benign':
        return 1
    elif url_type == 'defacement':
        return 0
    elif url_type == 'malware':
        return 0
    else:
        raise TypeError('Неизвестный тип:', url_type)


def convert_url(url):
    parts = url.split('://', 1) if '://' in url else [None, url]
    subdomain_parts = parts[1].split('/')[0].split('.')
    www, sub, top = get_subdomain(subdomain_parts)

    protocol = get_proticol(parts[0]) / 3
    www /= 3
    sub /= 233
    top /= 1000
    url_len = count_digits(url) / 100
    special_characters = count_special_characters(url) / 50
    slash = count_slash(url) / 10

    return protocol, www, sub, top, url_len, special_characters, slash


def main():
    # Открытие CSV файла
    df = pd.read_csv('malicious_phish.csv')

    # Создание новых колонок со значениями по умолчанию
    df['Protocol'] = '0'
    df['www'] = '0'
    df['Subdomain'] = '0'
    df['Top-level domain'] = '0'
    df['url len'] = '0'
    df['special_characters'] = '0'
    df['slash'] = '0'

    # Проход по всем URL в первом столбце
    for i, row in df.iterrows():
        url = row['url']  # столбец с URL называется 'url'

        df.at[i, 'type'] = get_type(row['type'])

        protocol, www, sub, top, url_len, special_characters, slash = convert_url(url)

        df.at[i, 'Protocol'] = protocol
        df.at[i, 'www'] = www
        df.at[i, 'Subdomain'] = sub
        df.at[i, 'Top-level domain'] = top
        df.at[i, 'url len'] = url_len
        df.at[i, 'special_characters'] = special_characters
        df.at[i, 'slash'] = slash

    # Сохранение обновленного CSV файла
    df.to_csv('updated.csv', index=False)


def count_digits(s):
    ans = filter(lambda x: x, (w.isdigit() for w in s))
    return len(tuple(ans))


def count_special_characters(s):
    special = '%_+-&='
    ans = filter(lambda x: x, (w in special for w in s))
    return len(tuple(ans))


def count_slash(s):
    ans = filter(lambda x: x, ((w == '/') for w in s))
    return len(tuple(ans))


if __name__ == '__main__':
    main()
    # pd.read_csv('updated.csv')
    pass
