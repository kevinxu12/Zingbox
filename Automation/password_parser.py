import re

import requests
from bs4 import BeautifulSoup


def extract(url):
    text_file = open("password_parse", "a")
    webpage = requests.get(url)
    # print webpage.content
    soup = BeautifulSoup(webpage.content, "html.parser")
    list_vendors = [vendor.text.encode('utf-8') for vendor in soup.findAll("a", href=re.compile(r'\?vendor=.*'))]
    list_vendors_format = [vendor.replace(" ", "%20") for vendor in list_vendors]
    prefix = "https://cirt.net/passwords?vendor="
    list_vendor_urls = [prefix + vendor for vendor in list_vendors_format]
    for vendor_url, vendor in zip(list_vendor_urls, list_vendors):
        dic_password = {}
        # passes = retrievepage(vendor_url)
        all_info = retrievepage(vendor_url)
        key = vendor
        # dic_password[key] = passes
        dic_password[key] = all_info
        text_file.write(str(dic_password) + "\n")
    text_file.close()


def retrievepage(url):
    webpage = requests.get(url)
    soup = BeautifulSoup(webpage.content, "html.parser")
    body = soup.findAll("table")
    title_inter = [table_header.find("b").text.encode('utf-8') for table_header in body]
    list_title = [title.replace("\xc2\xa0", "") for title in title_inter]
    tags = [text_body.findAll("tr") for text_body in body]
    # print webpage.content
    list1 = []
    for list_tag in tags:
        list2 = []
        for tag in list_tag:
            key_inter = tag.find("b", text=re.compile(r'[A-za-z0-9\,\']*(\s[A-Za-z0-9\,]+)?'))
            if key_inter is not None:
                key = key_inter.text.encode('utf')
                list2.append(key)
        list1.append(list2)

    list3 = []
    for list_tag in tags:
        list4 = []
        for tag in list_tag:
            val_inter = tag.findAll("td", {"align": "left"})
            if len(val_inter) > 0:
                val_inter = val_inter[1]
                val = val_inter.text.encode('utf')
                list4.append(val)
        list3.append(list4)
    agg_pass = []
    agg_dic = []
    for list_key, list_val, title in zip(list1, list3, list_title):
        table_JSON = {}
        inner_table = {}
        for key, val in zip(list_key, list_val):
            if val is not "":
                inner_table[key] = val
            # if key == "Password":
                # agg_pass.append(val)
        table_JSON[title] = inner_table
        agg_dic.append(table_JSON)

    # print agg_dic
    # print agg_pass
    # return agg_pass
    return agg_dic

def clear():
    open('password_parse', 'w').close()

if __name__ == '__main__':
    clear()
    extract("https://cirt.net/passwords")
    # retrievepage("https://cirt.net/passwords?vendor=2Wire,%20Inc.")
    # clear()
    # retrievepage("https://cirt.net/passwords?vendor=AWARD")
