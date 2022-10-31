# coding: utf-8
#!/usr/bin/env python3
import logging
import signal
import coloredlogs
import argparse
import requests
import json
import os
import pandas as pd
from pyfiglet import Figlet
from sys import exit
from threading import Thread
from queue	import Queue 

logger = logging.getLogger(__name__)
def banner():
	figlet = Figlet(font='slant')
	print(figlet.renderText("Mass IP Info Extractor"))

def signal_handler(sig, frame):
	print('You pressed Ctrl+C!')
	global stop_requested 
	stop_requested = True
	exit(0)


def readcsvs(path_to_dir, suffix, ipcolumns):
	allcsvs = []
	for (root,dirs,files) in os.walk(path_to_dir, topdown= True):
		allcsvs.extend([ os.path.join(root,filename) for filename in files if filename.endswith( suffix ) ])

	allcsvs = list(set(allcsvs))

	ips = []
	for csvfile in allcsvs:
		ips.extend(readcsv(csvfile, ipcolumns))

	return list(set(ips))


def readcsv(csvfile, ipcolumns):
	global logger
	ips = []
	with open(csvfile, "r") as f:
		df = pd.read_csv(f)
		for col in ipcolumns:
			try:
				ips.extend(list(df[col]))
			except:
				logging.critical(f"Column {col} not found in csv {csvfile}")
		

	return list(set(ips)) 


def conver_to_excel(path_to_file,outfile):
	data = None
	with open(path_to_file, "r") as f:
		data = json.load(f)
		df_nested_list = pd.json_normalize(data)
		df_nested_list.to_excel(outfile)



def readjson(path_to_file):
	data = None
	if os.path.exists(path_to_file):
		with open(path_to_file, "r") as file:
			data = list(json.load(file))
	else:
		return []

	return data


def writejson(path_to_file,json_data):
	if os.path.exists(path_to_file):
		data = readjson(path_to_file)
		logger.debug({f"Existing IP Read: {len(data)}"})
		data.extend(json_data)
		logger.debug({f"Final IP Wrote: {len(data)}"})
		with open(path_to_file, "w") as file:
			json.dump(data, file, indent=4)
	else:
		with open(path_to_file, "w") as file:
			json.dump(json_data, file, indent=4)





def ipgeoloc(IP,serno):
	global logger
	logger.info(f'Start fetching data queue number {serno + 1}...{IP}')
	try:
		try:
			URL = "https://api.ipgeolocation.io/ipgeo"
			API_KEY = "" 

			
			del_key = [
				"continent_code",
				"country_code3",
				"country_capital",
				"is_eu",
				"calling_code",
				"country_tld",
				"languages",
				"country_flag",
				"geoname_id",
			]

			IP = IP.replace('\n', '')
			IP = IP.strip()

			# get ip's data
			PARAMS = {'apiKey':API_KEY, 'ip':IP}
			r = requests.get(url = URL, params = PARAMS) 
			data = r.json()
			return {key: value for key, value in data.items() if key not in del_key}
		except:
			logger.warning("Failed to fetch data from primary source. ")
			URL2 = "http://ip-api.com/json/"
			r = requests.get(URL2 + IP + '?fields=continent,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,proxy,hosting,query')
			data = r.json()
			data['ip'] = data['query']
			data.pop('query')
			return data

		# alldata.append(data)
	except Exception as e:
			logger.error(e)

	return {}

	


def get_existing_ips(path_to_file,ips):
	filtered = ips.copy()
	data = readjson(path_to_file)
	for d in data:
		if 'ip' in d.keys():
			if d['ip'] in ips:
				filtered.remove(d['ip'])

	return filtered


def run(q, results):
	global logger
	while not q.empty():
		ip = q.get()
		try:
			data = ipgeoloc(ip[1], ip[0])
			results[ip[0]] = data
			logger.debug(data)

		except Exception as e:
			logger.error(e)

		finally:
			q.task_done()
	return True


def args_parse():
	parser = argparse.ArgumentParser(description="Mass IP Address Info Extractor")
	file_group = parser.add_mutually_exclusive_group(required=True)
	file_group.add_argument('-p', '--folderpath', type=str,help='Path for all CSV files to read, nested folders will also be accessed.')
	file_group.add_argument('-f', '--csvfile', type=str, help='Read CSV File.')

	parser.add_argument('-c', '--ipcolumns', type=str, help='Column Names listed as IP addresses, multiple columns can be comma seperated', required=True)


	parser.add_argument('-t', '--threads', type=int , help='Number of concurrent scans of IP addresses', default=10)
	parser.add_argument('-d', '--loglevel', type=str, help="d Level Setup.", default='INFO', choices=['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'])
	parser.add_argument('-o', '--outputfile', type=str, help="Output file name with path, existing file will be read and records will be appended out if not already exists", default="output.json")
	parser.add_argument('-x', '--xlsx', help='Convert outputed json file to normalized xlsx')
	parser.add_argument('-l', '--logfile', help='log to file', dest='logfile', default=None)  

	args = parser.parse_args()
	return args


def get_args(args):
	global logger
	dargs = {}
	loglevel = ""

	if args.loglevel:
		if args.loglevel == 'INFO':
			loglevel = logging.INFO
		if args.loglevel == 'CRITICAL':
			loglevel = logging.CRITICAL
		if args.loglevel == 'ERROR':
			loglevel = logging.ERROR
		if args.loglevel == 'WARNING':
			loglevel = logging.WARNING
		if args.loglevel == 'DEBUG':
			loglevel = logging.DEBUG

		logger.setLevel(level=loglevel)
		stream_formatter = logging.Formatter('%(levelname)s - %(message)s')

		console_handler = logging.StreamHandler()
		console_handler.setLevel(level=loglevel)
		console_handler.setFormatter(stream_formatter)
		logger.addHandler(console_handler)

		if args.logfile:
			file_formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
			file_handler = logging.FileHandler(args.logfile)
			file_handler.setLevel(level=loglevel)
			file_handler.setFormatter(file_formatter)
			logger.addHandler(file_handler)

		coloredlogs.install(logger=logger, level=loglevel)

	if args.outputfile:
		dargs['outputfile'] = args.outputfile

		if args.xlsx:
			dargs['xlsx'] = dargs['outputfile'].split('.')[0] + ".xlsx"
	

	if args.csvfile:
		column_names = args.ipcolumns.split(',')
		dargs['ips'] = readcsv(args.csvfile, column_names)

	if args.folderpath:
		column_names = args.ipcolumns.split(',')
		dargs['ips'] = readcsvs(args.folderpath, '.csv', column_names)

	if args.threads:
		if args.threads > 40  or args.threads < 1:
			logger.error("Threads value must be between 1 or 40")
			exit(1)
		else:
			if len(dargs['ips']) < 10:
				dargs['threads'] = len(dargs['ips'])
			else:
				dargs['threads'] = args.threads
			logger.debug(f"Thread value : {args.threads}")


	return dargs

	
def main():
	banner()
	signal.signal(signal.SIGINT, signal_handler)

	args = args_parse()
	dargs = get_args(args)

	if not dargs['ips']:
		logger.critical("No IPs found in file")
		exit(1)

	logger.info(f"Total IPs identified. {len(dargs['ips'])}")

	filtered = get_existing_ips(dargs['outputfile'],dargs['ips'])
	logger.info(f"Identified IPs in Input: {len(dargs['ips'])}, Not found in existing file {len(filtered)}")


	q = Queue(maxsize=0)
	results = None

	if filtered:
		num_threads = min(10,len(filtered))
		results = [{} for x in filtered]

		for i in range(len(filtered)):
			q.put((i,filtered[i]))
			# data = ipgeoloc(filtered)
	# else:
	# 	logger.debug(f'Starting Non Filtered Threads')
	# 	num_threads = min(10,len(dargs['ips']))
	# 	results = [{} for x in dargs['ips']]

	# 	for i in range(len(dargs['ips'])):
	# 		q.put((i,dargs['ips'][i]))
		# data = ipgeoloc(IPS)

		for i in range(num_threads):
			worker = Thread(target=run, args=(q,results))
			worker.daemon = True
			worker.start()

	q.join()

	# logger.debug(json.dumps(results, indent=4))

	if filtered:
		if dargs['outputfile']:
			writejson(dargs['outputfile'], results)
			if 'xlsx' in dargs.keys():
				conver_to_excel(dargs['outputfile'], dargs['xlsx'])

	else:
		logger.warning("No new IP identified hence no new Information is found/ written.")

if __name__ == '__main__':
	main()