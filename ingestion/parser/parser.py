import sys, gzip, json
import os
import re
from pygrok import Grok
from datetime import datetime

ftp_matcher = [Grok(ftp_pat) for ftp_pat in ftp_patterns]

def parse_as_ftp(string):
	for matcher in ftp_matcher:
		match = matcher.match(line.decode())
		if match != None:
			ftp = match
			timestamp = ftp['timestamp']
			ip = ftp['ip']
			del(ftp['timestamp'])
			del(ftp['ip'])
			return {
				"_index": "ftp-{}".format(timestamp[:7].replace("-", ".")),
				"_type": "ftp",
				"_source": {
					"ftp": ftp,
					"ip": ip,
					"@timestamp": timestamp
				},
			}

def parse_as_ssh(string):
	ssh = json.loads(string)
	ssh["ip"] = ssh["src_ip"]
	ssh["@timestamp"] = ssh["timestamp"]
	del(ssh["src_ip"])
	del(ssh["timestamp"])
	return {
		"_index": "ssh-{}".format(ssh['@timestamp'][:7].replace("-", ".")),
		"_type": "ssh",
		"_source": ssh
	}

postfix_prefix = "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST} %{DATA:program}(?:\[%{POSINT}\])?: %{GREEDYDATA:message}"
postfix_patterns = [
	#POSTFIX_QMGR_EXPIRED 
	"%{WORD:postfix_queueid}: from=<%{DATA:postfix_from}>, status=%{WORD:postfix_status}, returned to sender",
]
postfix_matcher = [Grok(postfix_prefix) for postfix_pat in postfix_patterns]

def parse_as_postfix(string):
	for matcher in postfix_matcher:
		match = matcher.match(line.decode())
		print(match)
		if match != None:
			print(match)

def parse_file_as_ftp(fname):
	f = gzip.open(fname, 'rb')
	for line in f:
		parse_as_ftp(line)
	f.close()

def parse_file_as_ssh(fname):
	f = gzip.open(fname, 'rb')
	for line in f:
		parse_as_ssh(line)
	f.close()