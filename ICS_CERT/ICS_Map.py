import ast
import json
import pprint
import re
import os

from bs4 import BeautifulSoup
from lxml import html
import requests


class ParserOffline:
    count = 0

    # Instance Variables:
    #   executeURL - list of urls of new entries that need to be updated
    #   VendorMap - Map with key vendor and value list of ICS-CERT entries
    #   CVEMap - Map with key CVE and value list of ICS-CERT entries
    #   recent_id - The url of the most recent entry as of 7/9/2018. This value updates as update is called
    #   file_parsed - File containing correctly parsed entries
    #   file_unparsed - File containing incorrectly parsed entries for further analysis
    def __init__(self):
        self.VendorMap = {}
        self.CVEMap = {}
        # self.recent_id = "https://ics-cert.us-cert.gov/advisories/ICSA-18-184-01"
        # self.file_parsed = open("parsed_correct.txt", 'r')
        self.file_parsed = ""
        self.file_unparsed = ""
        self.recent_id = ""
        # self.file_unparsed = open("parsed_incorrect.txt", 'w')

    def getCVEProductDic(self):
        print self.CVEMap

    # see at a quick glance the ratio between correctly parsed: incorrectly parsed
    def getCorrectLength(self):
        count = 0
        file_parsed = open('parsed_correct.txt', 'r')
        for line in file_parsed:
            count = count + 1
        print "correctly parsed count is " + str(count)
        print "incorrectly parsed count is " + str(256 - count)

    # clears all
    def clear(self):
        self.file_parsed = open('parsed_correct.txt', 'w').close()
        self.file_unparsed = open('parsed_incorrect.txt', 'w').close()
        self.recent_id = ""


    # The update function should refresh for new entries in ICS-CERT. The function avoids re-downloading the
    # entire depository. The function will only work if all the new alerts can be found on the home page. If there
    # are like 35 new alerts, an out of bounds execption will occur
    def update(self, url):
        self.recent_id = self.getMostRecentURL()
        self.file_parsed = open("parsed_correct.txt", 'a')
        self.file_unparsed = open("parsed_incorrect.txt", 'a')
        # extracts most recent urls from the ICS-CERT repository
        execute_URL_New = self.aggWebPage(url)['Execute URL']
        execute_URL = []
        i = 0
        new_recent_id = execute_URL_New[0]

        # adds new urls to a list
        while self.changeString(execute_URL_New[i]) != self.recent_id:
            # print execute_URL_New[i]
            execute_URL.append(execute_URL_New[i])
            i = i + 1

        self.recent_id = new_recent_id
        # update files
        for url in execute_URL:
            self.retrieveURLWeb(url)
        self.file_parsed.close()
        self.file_unparsed.close()

    # gets the url of the most recent entry
    def getMostRecentURL(self):
        self.file_parsed = open('parsed_correct.txt', 'r')
        for line in self.file_parsed:
            pass
        last_line = line
        if last_line != "":
            id = self.changeString(re.search(r'[A-Z]+-[0-9]*-[0-9]*-[0-9A-Z]+', line).group(0))
            url = "https://ics-cert.us-cert.gov/advisories/" + id
            self.file_parsed.close()
            return url
        self.file_parsed.close()
        return "https://ics-cert.us-cert.gov/advisories/ICSA-18-184-01"

    # Agg page zips through a web page collecting all of the web page's hyper links. It outputs these links into a
    # list of 3 elements. The first element, execute urls, is a list of links to entries. The second element,
    # page urls, is a list of links to other advisory pages. The third element, list url, includes all
    # other urls
    def aggWebPage(self, url):
        # replace url retrieval with local retrieval
        input = requests.get(url)
        soup = BeautifulSoup(input.content, "html.parser")
        list_ICS = soup.find_all("a", href=re.compile("^/advisories"))

        # get all the relevant urls on the web page
        list_url = []
        execute_url = []
        page_url = []

        for ICS in list_ICS:
            id = ICS['href']
            link = "https://ics-cert.us-cert.gov" + id
            if "/advisories?" in str(id):
                page_url.append(link)
            elif "/advisories/ICS" in str(id):
                execute_url.append(link)
            else:
                list_url.append(link)
        all_urls = {}
        all_urls["Execute URL"] = execute_url
        all_urls["Page URL"] = page_url
        all_urls["Other URL"] = list_url
        # print all_urls['Execute URL']
        return all_urls
        # for ICS in list_ICS:`

    # given a URL, retrieveURLWeb will extract all information and write it into either the correctly parsed text
    # document or the incorrectly parsed text document
    def retrieveURLWeb(self, url):
        file = requests.get(url)
        soup = BeautifulSoup(file.content, "html.parser")
        self.retrieveURLHelper(soup, url)

    # extract takes all the html files that have been downloaded into the ICS local respository and parses them.
    # It then sorts them into correctly and incorrectly sorted files.
    # Extract is used to avoid the ICS-CERT websites rate limiting. You should first use a bash script to
    # download entries into the ICS repository. Extract will read and write them.
    def extract(self):
        self.file_parsed = open("parsed_correct.txt", 'a')
        self.file_unparsed = open("parsed_incorrect.txt", 'a')
        # your local repository containing the html files from the bash script
        pref_dir = "/home/kevinxuzingboxcom/PycharmProjects/parser/CERT_PARSE/ICS/"
        # file containing all unique ids
        file = open("ids.txt", 'r')
        list_uniq_ids = [line.replace("\n", "").strip() + ".html" for line in file]
        list_ids = [pref_dir + uniq_id for uniq_id in list_uniq_ids]
        for html in list_ids:
            self.retrieveURL(html)
        self.file_parsed.close()
        self.file_unparsed.close()
        self.moveFirstLineEnd("parsed_correct.txt")

    def moveFirstLineEnd(self, intended_file):
        instance_variable = open(intended_file, 'r')
        first_line = instance_variable.readline()
        instance_variable.close()
        instance_variable = open(intended_file, 'a')
        instance_variable.write(first_line)
        instance_variable.close()

    # Given an html file, retrieveURL will extract l extract all information and write it into either
    # the correctly parsed text document or the incorrectly parsed text document
    def retrieveURL(self, html_file):
        text = open(html_file, 'r')
        soup = BeautifulSoup(text, "html.parser")
        self.retrieveURLHelper(soup, html_file)

    # retrieveURLHelper should extract three categories of information that are input into a JSON object.
    # Category 1: Executive Summary
    #   This includes the subject, vulnerabilities, vendor, and difficulty of the attack
    # Category 2: Affected Products
    #   This lists all products affected
    # Category 3: CVE Map
    #   This lists the names of vulnerabilities and the corresponding CVEs
    def retrieveURLHelper(self, soup, input):

        # Printing/Testing Out Soup
        id_text = self.changeString(soup.findAll("h1", text=re.compile('\((.+)\)'))[0].text)
        self.id = id_text
        subject = self.changeString(soup.findAll("h2", id=True)[0].text)
        release_date = self.changeString(soup.findAll(lambda tag: tag.name == "footer" and len(tag.attrs) == 1)[0].text)
        exec_Summary_test = soup.findAll("div", {"class", "field-item even"})[0]

        # retrieve executive summary e.g. vendor/cvs
        exec_Summary = self.retrieveExec(exec_Summary_test)
        # retrieve affected products
        affected_products = self.findAffectedProducts(exec_Summary_test)
        # retrieve CVE Map
        CVE_Map = self.retrieveCVEMapOld(exec_Summary_test)

        #if the template is an old one, retrieve exec summary another way
        if not exec_Summary:
            exec_Summary_old = self.retrieveExecOld(exec_Summary_test)
            if exec_Summary_old:
                info = exec_Summary_old
            else:
                info = "False"
        else:
            info = exec_Summary

        # print CVE_Map_old
        # print CVE_Map
        # print exec_Summary_old
        # print att
        # print affected_products
        # print vuln
        # print part
        # print list_products
        # print exec_Summary
        # print retrieveCVEMap(exec_Summary)
        # print test_id_text

        # create the JSON object
        dic = {}
        exec_info = {}
        # info = exec_Summary
        exec_info["subject"] = subject
        exec_info["release date "] = release_date
        exec_info["executive summary"] = info
        exec_info["affected products:"] = affected_products
        exec_info["Vulnerability Overview"] = CVE_Map
        dic[id_text] = exec_info


        #read the jsons into the correct or incorrectly parsed files
        if not exec_Summary and not exec_Summary_old and len(CVE_Map) < 1:
            if input.startswith("/home"):
                unique_id = input.replace("/home/kevinxuzingboxcom/PycharmProjects/parser/CERT_PARSE/ICS/", "")
                unique_id = unique_id.replace(".html", "")
                url = "https://ics-cert.us-cert.gov/advisories/" + unique_id
            else:
                url = input
            dic[id_text] = "Element in the ICS-CERT Database is not a product. Here is the url: " + url
            str_dic = json.dumps(dic)
            dic = str_dic.replace("'", "\"")
            self.file_unparsed.write(dic)
            self.file_unparsed.write("\n")
        else:
            str_dic = json.dumps(dic)
            dic = str_dic.replace("'", "\"")
            self.file_parsed.write(dic)
            self.file_parsed.write("\n")
        # pprint.pprint(dic)

        # print testh1
        # print testh2
        # print filtered_ReleaseDate
        # print filtered_ReleaseDateText

    # retrieveExecOld retrieves the executive summary information in entries that use the old template. This method works
    # by finding the tag Affected Products and working backwords.
    def retrieveExecOld(self, exec_Summary_test):
        aff_product = exec_Summary_test.find(text=re.compile('(.*?)AFFECTED PRODUCTS'))
        dic = {}
        if aff_product is not None:
            elements = list(reversed(aff_product.find_all_previous("strong")))
            keys = [a.text for a in elements]
            text = [a.next_sibling for a in elements]
            # print list
            # print keys
            # print text
            for a, b in zip(keys, text):
                key = self.changeString(a)
                val = self.changeString(b)
                if key == 'Vulnerabilit':
                    continue
                if 'y: ' in key:
                    key = 'Vulnerability: '

                if 'CVSS' in key and val == 'None':
                    val = key.replace('CVSS ', "")
                    key = 'CVSS'
                dic[key] = val
            if len(dic) == 0:
                return False
            return dic
        return False

    # retrieveExec retrieves executive information for entires that follow a newer template. It finds all information
    # in the section labeled 'Executive Summary'
    def retrieveExec(self, exec_Summary_test):
        es = exec_Summary_test.find(text=re.compile('(.*?)EXECUTIVE SUMMARY'))
        dic = {}
        if es is not None:
            list = es.find_next("ul")
            elements = list.find_all("strong")
            # print elements
            keys = [a.text for a in elements]
            text = [a.next_sibling for a in elements]
            # print list
            # print keys
            # print text
            for a, b in zip(keys, text):
                key = self.changeString(a)
                val = self.changeString(b)
                if 'CVSS' in key and val == 'None':
                    val = key.replace('CVSS ', "")
                    key = 'CVSS'
                dic[key] = val
            if len(dic) == 0:
                return False
            return dic

        return False

    # findAffectedProducts finds products that are affected
    def findAffectedProducts(self, exec_Summary_test):
        az = exec_Summary_test.find(text=re.compile('(.*?)AFFECTED PRODUCTS'))
        if az is not None:
            affected_product = az.find_next("ul")
            affected_products = [self.changeString(a.text) for a in affected_product.find_all("li")]
            list_products_filter = []
            for a in affected_products:
                a.strip();
                if ", and" in a:
                    list_products_filter.append(a.replace(", and", ""))
                elif "," in a:
                    list_products_filter.append(a.replace(",", ""))
                else:
                    list_products_filter.append(a)
            # print list_products_filter
            return list_products_filter
        return False

    # changeString converts the unicode text into string formatting
    def changeString(self, uni_text):
        if uni_text is not None:
            return uni_text.encode('utf-8')
        return "None"

    # retrieveCVEMapOld retrieves the CVE Map
    def retrieveCVEMapOld(self, exec_Summary_test):
        #All CVEs should be located between section vulnerability and researcher
        locate = exec_Summary_test.find(text=re.compile('(.*?)VULNERABILITY'))
        researcher = exec_Summary_test.find(text=re.compile('(.*?)RESEARCHER'))
        dic = {}

        # returns a list of Vulnerability names followed by CVE code. Filters out the :/:/ formatted stuff
        def findUntilNextSection(locate, researcher):
            list = []
            nextA = locate.find_next("a")
            lastA = researcher.find_next("a")
            while nextA.text != lastA.text:
                numColon = self.changeString(nextA.text).count(":")
                if numColon < 3:
                    list.append(nextA)
                nextA = nextA.find_next("a")
            return list

        if researcher is None:
            researcher = exec_Summary_test.find(text=re.compile('(.*?)MITIGATION'))

        if researcher is not None:
            list_stuff = findUntilNextSection(locate, researcher)
            # print list_stuff
            i = 0
            while i + 1 < len(list_stuff):
                key = self.changeString(list_stuff[i].text)
                if 'CWE' not in key:
                    i = i + 1
                    continue
                val = self.changeString(list_stuff[i + 1].text)
                i = i + 1
                # no CVE for a vulnerability
                if 'CVE' not in val:
                    val = "None"

                else:
                    # multiple CVEs for a vulnerability
                    if i + 1 < len(list_stuff) and 'CVE' in self.changeString(list_stuff[i + 1].text):
                        CVE_list = []
                        CVE_list.append(val)
                        i = i + 1
                        while i < len(list_stuff) and 'CVE' in self.changeString(list_stuff[i].text):
                            next_CVE = list_stuff[i].text
                            if not isinstance(val, list):
                                CVE_list.append(self.changeString(next_CVE))
                            i = i + 1
                        i = i - 1
                        val = CVE_list
                    i = i + 1

                # check if key has been used
                if key in dic:
                    # print "dup"
                    exist_val = dic[key]
                    if isinstance(exist_val, list):
                        exist_val.append(val)
                        dic[key] = exist_val
                    else:
                        list_val = []
                        list_val.append(exist_val)
                        list_val.append(val)
                        dic[key] = list_val
                else:
                    dic[key] = [val]
                    # self.createCVEProductEntry(val, self.id)
            # print dic
            return dic
        return "No CVE!"

    # generates mapping for vendor - ics map and CVE - ics map
    def genImportantMap(self):
        self.genVendorMap()
        self.genCVEMap()

    def genVendorMap(self):
        self.file_parsed = open("parsed_correct.txt", 'r')
        for line in self.file_parsed:
            key = "Vendor"
            multiple = line.find("Vendors")
            start = line.find(key)
            if multiple == -1:
                end = line.find('\',', start)
                unfiltered_vendor = line[start + len(key):end]
                vendor = self.changeString(re.search(r'[A-Za-z0-9/,]+(\s[A-Za-z0-9/,]+)*', unfiltered_vendor).group(0))
                self.productDicHelp(vendor, line, self.VendorMap)
            elif multiple > 0:
                end = line.find('\',', multiple)
                unfiltered_vendor = line[start + len("Vendors"):end]
                vendor = self.changeString(re.search(r'[A-Za-z0-9/,]+(\s[A-Za-z0-9/,]+)*', unfiltered_vendor).group(0))
                self.productDicHelp(vendor, line, self.VendorMap)
        # about 10 or 15 are not read right. Are filtered out in the next step
        self.VendorMap['isory'] = "none"
        pprint.pprint(self.VendorMap)
        #  if CVE_Vendor_dic.get()
        # self.file_parsed.find()

    def genCVEMap(self):
        self.file_parsed = open("parsed_correct.txt", 'r')
        for line in self.file_parsed:
            pos_vuln = line.find("Vulnerability Overview")
            trim_line = line[pos_vuln:]
            pos_CVE = [m.group(0) for m in re.finditer('CVE-[0-9]+-[0-9]+', trim_line)]
            for CVE in pos_CVE:
                self.productDicHelp(CVE, line, self.CVEMap)
        pprint.pprint(self.CVEMap)

    def productDicHelp(self, key, line, map):
        if map.get(key, 0) == 0:
            new_ids = []
            new_ids.append(line)
            map[key] = new_ids
        else:
            existing_ids = map.get(key)
            if line not in existing_ids:
                existing_ids.append(line)
            map[key] = existing_ids

if __name__ == '__main__':
    ob = ParserOffline()
    ob.clear()
    ob.extract()
    # ob.update("https://ics-cert.us-cert.gov/advisories")

