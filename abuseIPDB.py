#!/usr/bin/python3

""" 
	Python script to report bad IPs to AbuseIPDB in bulk
"""

__author__ = "Shubham Hibare"
__version__ = "1.4"
__maintainer__ = "Shubham Hibare"
__email__ = "shubham@hibare.in"

import requests
import json
import csv
import sys
import os
import argparse
import ipaddress
import time
import threading

# function to validate an IP address
def validateIP(ipaddressToValidate):
	"""
		Description: validates an IP address
		Input: IP to be validated (string)
		Return: True or False (boolean)
	"""
	try:
		ipaddress.ip_address(ipaddressToValidate)
		return True
	except Exception as e:
		return False

# main function to report IPs to abuseIPDB
def postIP(APIKey, inputFileName, category, comment):
	"""
		Description: post IPs to abuseIPDB
		Input: APIKey 		 - abuseIPDB API key (string)
			   inputFileName - input file containing IPs, one per line (string)
			   category 	 - IP submission category (string)
			   comment 	 - comment for IP (string)
		Return: none
	"""
	ipCounter = 0
	failedIP = []
	inputIPList = []
	submissionStatus = ''
	outputFileName = 'AbuseIPDB_Submission_Status.csv'
	fields = ['IP', 'Status'] 

	try:
		# open input file and read all IPs in a list
		inputFile = open(inputFileName, 'r')
		inputIPList = inputFile.readlines()
		inputFile.close()

		# remove duplicates
		inputIPList = set(inputIPList)

		# open output file
		outputFile = open(outputFileName, 'w')

		# get a csv writer
		writer = csv.DictWriter(outputFile, fieldnames=fields)

		# write header to csv file
		writer.writeheader()

		# loop through the input file
		for ip in inputIPList:

			# strip new line character from the input
			ip = ip.rstrip('\n')

			# if not a blank line
			if ip:

				# increment IP counter
				ipCounter += 1

				print("[{0}] Processing IP: {1}".format(ipCounter, ip), end=' ... ')

				if validateIP(ip):
					# make request to geoplugin
					payload = {'key': APIKey, 'category': category, 'comment': comment, 'ip': ip}
					url = 'https://www.abuseipdb.com/report/json'

					try:
						# make request to abuseIPDB API
						abuseipdbRequest = requests.post(url, params=payload)
						
						if abuseipdbRequest.ok:
							# parse JSON data
							datastore = json.loads(abuseipdbRequest.text)
							
							# check submission status
							if datastore.get('success'):
								submissionStatus = 'Success'
							else:
								submissionStatus = 'Failed'
								failedIP.append(ip)
						else:
							submissionStatus = 'Request failed'
							failedIP.append(ip)
					
					except Exception as e:
						submissionStatus = "Error - {}".format(e)
						print("[{0}]".format(submissionStatus))
						failedIP.append(ip)
						time.sleep(60)
						continue

				else:
					submissionStatus = 'Invalid IP'
					failedIP.append(ip)

				# write output
				print("[{0}]".format(submissionStatus))
				writer.writerow({'IP': ip, 'Status': submissionStatus})


		# print total number of IPs processed
		print("\nTotal IPs processed: {0}".format(ipCounter))

		# check for failed IPs and print them
		if len(failedIP) > 0:
			print("\nError occurred for following IPs [{0}]".format(len(failedIP)))
			for ip in failedIP:
				print(ip)

	except Exception as e:
		print("Exception : "+str(e))
		print("\nNumber of processed IPs: {0}".format(ipCounter))
		print("Last processing IP: {0}".format(ip))

	finally:
		# close output file
		outputFile.close()


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-k', '--APIKey', type=str, metavar='<AbuseIPDB API key>', help='Enter AbuseIPDB API key', required=True)
	parser.add_argument('-f', '--inputfilename', type=str, metavar='<input filename>', help='Input file name', required=True)
	args = parser.parse_args()
	
	# check if file exists and readable
	if os.path.isfile(args.inputfilename) and os.access(args.inputfilename, os.R_OK):
		reportingCategories = {
						3: 'Fraud Orders', 
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
						23: 'IoT Targeted'
					}
		
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
				print("Invalid category: {0}".format(cat))
				sys.exit()


		# read comment
		comment = input('\nEnter comment: ')

		print("\nPlease verify:")
		print("Category: {0}".format(category))
		print("comment: {0}".format(comment))
		proced = input("\nContinue [y/n]? ")

		if proced == "y":
			# call getIPDetails function
			postIP(args.APIKey, args.inputfilename, category, comment)
		else:
			print("abort")
	else:
		print("Error : either the file [{0}] does not exists or is not readable".format(args.inputfilename))
	
