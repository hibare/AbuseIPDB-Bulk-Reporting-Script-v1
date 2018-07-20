#!/usr/bin/python3

""" 
	Python script in report bad IPs to AbuseIPDB in bulk
"""
__author__ = "Shubham Hibare"
__version__ = "1.2"
__maintainer__ = "Shubham Hibare"
__email__ = "shubham@hibare.in"
__status__ = "Production"

import requests
import json
import csv
import sys
import os
import argparse
import ipaddress

# function to validate an IP address
def validateIP(ipaddressToValidate):
	try:
		ipaddress.ip_address(ipaddressToValidate)
		return True
	except Exception as e:
		return False

# main function to report IPs to abuseIPDB
def postIP(APIKey, inputFileName, category, comment):
	ipCounter = 0
	failedIP = []
	submissionStatus = ''
	outputFileName = 'AbuseIPDB_Submission_Status.csv'
	fields = ['IP', 'Status'] 

	try:
		#open input file
		inputFile = open(inputFileName, 'r')

		#open output file
		outputFile = open(outputFileName, 'w')

		#get a csv writer
		writer = csv.DictWriter(outputFile, fieldnames=fields)

		#write header to csv file
		writer.writeheader()

		#loop through the input file
		for ip in inputFile.readlines():

			#strip new line character from the input
			ip = ip.rstrip('\n')

			#if not a blank line
			if ip:

				print("[{0}] Processing IP : {1}".format(ipCounter+1, ip), end=' ... ')

				if validateIP(ip):
					
					#make request to geoplugin
					payload = {'key': APIKey, 'category': category, 'comment': comment, 'ip': ip}
					url = 'https://www.abuseipdb.com/report/json'

					# make request
					abuseipdbRequest = requests.post(url, params=payload)
					
					# parse JSON data
					datastore = json.loads(abuseipdbRequest.text)

					#increment IP counter
					ipCounter = ipCounter + 1

					# check submission status
					if datastore['success']:
						submissionStatus = 'Success'
					else:
						submissionStatus = 'Failed'
						failedIP.append(ip)

				else:
					submissionStatus = 'Invalid IP'
					failedIP.append(ip)

				# write output
				print("[{0}]".format(submissionStatus))
				writer.writerow({'IP':ip, 'Status': submissionStatus})


		#print total number of IPs processed
		print("\nTotal IPs processed : {0}".format(ipCounter))

		# check for failed IPs and print them
		if len(failedIP) > 0:
			print("\nError occurred for following IPs [{0}]".format(len(failedIP)))
			for ip in failedIP:
				print(ip)

	except Exception as e:
		print("Exception : "+str(e))
		print("\nNumber of processed IPs : {0}".format(ipCounter))
		print("Last processing IP : {0}".format(ip))

	finally:
		#Close input file
		inputFile.close()

		#close output file
		outputFile.close()


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-k', '--APIKey', type=str, metavar='<AbuseIPDB API key>', help='Enter AbuseIPDB API key', required=True)
	parser.add_argument('-f', '--inputfilename', type=str, metavar='<input filename>', help='Input file name', required=True)
	args = parser.parse_args()
	
	# check if file exists and readable
	if os.path.isfile(args.inputfilename) and os.access(args.inputfilename, os.R_OK):
		reportingCategories = {3: 'Fraud Orders', 
								4: 'DDoS Attack', 
								5: 'FTP Brute-Force', 
								6: 'Ping of Death', 
								7: 'Phishing', 
								8: 'Fraud VoIP', 
								9: 'Open Proxy', 
								10: 'Web Spam', 
								11: 'Email Spam', 
								12: 'Blog Spam', 
								13: 'VPN IP', 
								14: 'Port Scan', 
								15: 'Hacking', 
								16: 'SQL Injection', 
								17: 'Spoofing', 
								18: 'Brute-Force', 
								19: 'Bad Web Bot', 
								20: 'Exploited Host', 
								21: 'Web App Attack', 
								22: 'SSH', 
								23: 'IoT Targeted'}
		
		# read category
		for key, value in reportingCategories.items():
			print("{0} -> {1}".format(key,value))

		category = input('Enter category separated by comma [ex: 18,22]: ')

		#validate input categories
		splitCategory = category.split(",")
		for cat in splitCategory:
			if cat.isdigit() and int(cat) >= 3 and int(cat)<=23:
				pass
			else:
				print("Invalid category : {0}".format(cat))
				sys.exit()


		# read comment
		comment = input('\nEnter comment : ')

		print("\nPlease verify:")
		print("Category: {0}".format(category))
		print("comment: {0}".format(comment))
		proced = input("\nContinue [y/n]? ")

		if proced == "y":
			#call getIPDetails function
			postIP(args.APIKey, args.inputfilename, category, comment)
		else:
			print("abort")
	else:
		print("Error : either the file [{0}] does not exists or is not readable".format(args.inputfilename))
	
