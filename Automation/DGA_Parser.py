import argparse
import datetime
import io
import json
import os
import pprint
import re
import urllib2
import bs4
from bs4 import BeautifulSoup
from time import strftime, localtime, gmtime

import requests


class DGAParser:
    def __init__(self, flags=None, default_batch_size=None, unique_batch_flags=None, expir=None):
        self.dic = {}
        self.flags = flags if flags is not None else []
        self.default_batch_size = default_batch_size if default_batch_size is not None else 100
        self.unique_batch_flags = json.load(unique_batch_flags.read()) if unique_batch_flags is not None else {}
        self.expiration_date = expir if expir is not None else 3
        self.time_dic = {}

    def extractTexts(self):
        approp_entry = {}
        # get list of flags
        url = requests.get("http://data.netlab.360.com/dga/")
        soup = BeautifulSoup(url.content, "html.parser")
        families = soup.findAll("div", {"class": "family"})
        txts_raw = [family.find("a", href=re.compile("/feeds/dga/*")) for family in families]
        txts = [texts.text for texts in txts_raw if texts is not None]

        now = datetime.datetime.utcnow()
        day_before = now - datetime.timedelta(1)
        time_now = str(now.month) + "-" + str(now.day) + "-" + str(now.year)
        time_before = str(day_before.month) + "-" + str(day_before.day) + "-" + str(day_before.year)

        # choose which keys are nonexpired
        list_approp_dates = self.genRelevantDates()

        current_path = os.getcwd()
        new_filename = current_path + "/Logs/" + time_now + ".txt"
        old_filename = current_path + "/Logs/" + time_before + ".txt"

        # process the file from the day before
        if os.path.exists(old_filename):
            existing_file = open(old_filename, "r")
            dic = existing_file.read()
            self.time_dic = json.loads(dic)
            existing_file.close()
            
            # remove the keys that are expired
            for key in self.time_dic:
                if key.encode('utf-8') not in list_approp_dates:
                    if "REMOVED" not in key:
                        removed = self.time_dic.pop(key)
                        self.time_dic["REMOVED-" + key] = removed                        
            open(old_filename).close()
            updated_existing_file = open(old_filename, "w")
            updated_existing_file.write(json.dumps(self.time_dic))
            updated_existing_file.close()
            
            # stores values from the day before to avoid and check for duplicates
            for key in self.time_dic:
                if "REMOVED-" not in key:
                    flag_domains = self.time_dic[key]
                    for flag in flag_domains:
                        if flag in self.dic:
                            self.dic[flag] = self.dic[flag] + flag_domains[flag]
                        else:
                            self.dic[flag] = flag_domains[flag]
                    approp_entry[key] = self.time_dic[key]

            pref = "a"
        else:
            pref = "w"

        # Check if site is up. If not, method will write copy of day before. 
        if self.testUp("banjori") is True:
            # Adds specified batches from file to log
            if len(self.unique_batch_flags) > 0:
                for flag in self.unique_batch_flags:
                    if flag not in self.flags:
                        self.flags.add(flag)
                        
            # Only extract domains for flags that are specified if any flags are specified
            if len(self.flags) > 0:
                for text in txts:
                    if text.replace(".txt", "") in self.flags:
                            self.extractDomains(text)
                            
            # Extract domains for all flags if none are specified
            else:
                for text in txts:
                    self.extractDomains(text)

        dga_file = open(new_filename, pref)

        # writing non-expired entries to the daily file
        approp_entry[time_now] = self.dic
        json_approp = json.dumps(approp_entry)
        dga_file.write(json_approp)
        
        dga_file.close()
    # Calls the main helper method that extracts domains
    def extractDomains(self, txt):
        txt = re.search(r'[a-z]+', txt).group(0)
        self.extractDomainsHelper(txt)
        
    # This helper method does the actual extraction of domains by reading the .txt files.
    def extractDomainsHelper(self, txt):
        url = "http://data.netlab.360.com/feeds/dga/" + txt + ".txt"
        # page_content = urllib2.urlopen(url)
        page_content = io.StringIO(requests.get(url).text)
        if txt in self.dic:
            existing_domains = self.dic[txt]
        else:
            existing_domains = []
        domains = set()
        count = 0

        # determining number of domains to extract. Default is 100
        if txt in self.unique_batch_flags:
            det_count = int(self.unique_batch_flags[txt])
        else:
            det_count = self.default_batch_size

        while count < det_count:
            # for line in page_content:
            line = page_content.readline()
            if not "#" in line:
                isolated_domain = re.search(r'[a-z0-9\.]+', line)
                if isolated_domain is None:
                    count = count + 1
                    # continue
                else:
                    isolated_domain = isolated_domain.group(0)
                    if isolated_domain not in existing_domains:
                        domains.add(isolated_domain)
                        print "added"
                        count = count + 1
        list_domains = list(domains)
        self.dic[txt] = list_domains
        
    # returns a list of dates that are acceptable given the expiration date.
    def genRelevantDates(self):
        now = datetime.datetime.utcnow()
        list_times = []

        def genString(time):
            return str(time.month) + "-" + str(time.day) + "-" + str(time.year)

        while self.expiration_date > -1:
            earliest_time = now - datetime.timedelta(self.expiration_date)
            list_times.append(genString(earliest_time))
            self.expiration_date = self.expiration_date - 1

        return list_times
        
    # test if the website is up. Return true if the website is up. If not, print the exception and return false
    def testUp(self, txt):
        url = "http://data.netlab.360.com/feeds/dga/" + txt + ".txt"
        try:
            requests.get(url)
            return True
        except requests.exceptions.RequestException as e:
            print e
            return False

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Get the most recent DGA domains")
    parser.add_argument('-b', dest="batch_size", nargs="?", type=int, default=100,
                        help='set the size of a download batch (default %(default)s)')
    parser.add_argument("-l", dest="list_flag", nargs="+",
                        help='explicitly list which flags you want to refresh domains for: -l <flag1>  '
                             '<flag2> <flag3> etc')
    parser.add_argument("-e", dest="expiration_date", type=int, default=3, help="set the expiration date in days")
    # fix the functionality below
    parser.add_argument("-f", dest="file_batch", nargs="?", type=file,
                        help='upload a textfile that follows the format {<flag1>:<max domain flag1>, <flag2>:<max '
                             'domain flag2>} if you want to specify a batch size for each flag')
    options = parser.parse_args()
    batch_size = options.batch_size
    flags = options.list_flag
    expir = options.expiration_date
    unique_batch_flags = options.file_batch
    now = datetime.datetime.utcnow()

    # debugging purposes
    print unique_batch_flags
    print flags
    print "batch size: " + str(batch_size)
    print "expiration date: " + str(expir)
    
    bob = DGAParser(flags, batch_size, unique_batch_flags, expir)
    bob.extractTexts()
