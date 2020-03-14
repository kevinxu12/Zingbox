#!/usr/bin/python

#automation@offline-analytics:~/jxia$ more parse_events_json.py

import argparse
import sys
import os
import json
import datetime
import time
from datetime import datetime, timedelta
import dateutil.parser

tenantList={}

def usage():
    print (sys.argv[0] + " -i <infile> -o <outfile> -H [utc-diff]")
    print ("    For example, PST is -8, or PDT in is -7" )

def customer2tenantid(customer) :
    if not customer in tenantJson["customer"].keys():
        print ("Error: wrong customer name, %s" % (customer) )
        return "NA"
    else :
        return tenantJson["customer"][customer]["tenantid"]

def tenantid2customer(tenantid) :
    if not tenantid in tenantJson["tenantid"].keys():
        print ("Error: wrong tenantid name, %s" % (tenantid) )
        return "NA"
    else :
        return tenantJson["tenantid"][tenantid]["customer"]



if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--infile", help="input file")
    parser.add_argument("-o", "--outfile", help="output file")
    parser.add_argument("-H", "--utcDiff", type=int, help="UTC Differene")
    args = parser.parse_args()

    if not (args.outfile and args.infile) :
        usage()
        sys.exit(1)

    utcDiff = 0
    if args.utcDiff : 
        utcDiff = 0 + args.utcDiff

    with open('./customer-tenantid-mapping.json') as data_file:
        tenantJson = json.load(data_file)

    with open(args.outfile, "w") as outf:
        with open(args.infile, "r") as inf:
            for line in inf:
                validFlag = 0
                tmp = json.loads(line)
                if "_source" in tmp.keys() :
                    validFlag = 1
                if validFlag==1 :
                    entry = 0
                    evtType = tmp['_source']['evtType']
                    if evtType == "evt_ttsd" :
                        for x in tmp["_source"]["evtContent"]["access_list"] :
                            entry = entry + 1
                            x["_id"] = "JXID-"+tmp["_id"]+"-JXSE-%d-END" % entry
                            for keyList in [ "evtSource", "evtType", "iotDevid", "routerid", "tenantid"] :
                                x[keyList] = tmp["_source"][keyList]
                            x["customer"] = tenantid2customer(x["tenantid"])
                            x['date'] = datetime.fromtimestamp(int(x['ts'])/1000 + 3600*utcDiff).strftime("%Y-%m-%d")
                            x['time'] = datetime.fromtimestamp(int(x['ts'])/1000 + 3600*utcDiff).strftime("%H:%M:%S")
                            x['evtType'] = evtType
                            json.dump(x, outf, sort_keys=True)
                            outf.write('\n')
                    elif evtType in ["evt_arp_stats", "evt_dns_stats", "evt_connect", "evt_network", "evt_alert", "evt_upload", "evt_protocol_stats"] :
                            x = tmp["_source"]["evtContent"]
                            entry=1
                            x["_id"] = "JXID-"+tmp["_id"]+"-JXSE-%d-END" % entry
                            for keyList in [ "evtSource", "evtType", "iotDevid", "routerid", "tenantid"] :
                                x[keyList] = tmp["_source"][keyList]
                            x["customer"] = tenantid2customer(x["tenantid"])
                            x['ts'] = tmp["_source"]["@timestamp"]
                            x['date'] = datetime.fromtimestamp(int(x['ts'])/1000 + 3600*utcDiff).strftime("%Y-%m-%d")
                            x['time'] = datetime.fromtimestamp(int(x['ts'])/1000 + 3600*utcDiff).strftime("%H:%M:%S")
                            x['evtType'] = evtType
                            json.dump(x, outf, sort_keys=True)
                            outf.write('\n')
                    elif evtType in ["evt_router_log", "evt_router_hello"] :
                        pass
    
                    else :
                        print ("Warning: wrong data : %s \n" % line)
