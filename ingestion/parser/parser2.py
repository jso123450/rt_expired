import sys, gzip
from pygrok import Grok
from datetime import datetime

import grokpatterns

HTTP_METHODS = {
	"GET", 
	"POST",
	"PROPFIND",
}

telnet_pattern = Grok(grokpatterns.telnet[0])
nginx_access_patterns = []
for pattern in grokpatterns.nginx_access:
	nginx_access_patterns.append(Grok(pattern))
nginx_error_pattern = Grok(grokpatterns.nginx_error[0])

########################################################################

def createBasicESEntry(log_line, container_id, container_path):
	return {
		"_source": {
			"log": {
				"container": container_id,
				"path": container_path,
				"line": log_line
			},
			"geoip" : {
				"parsed using python-geoip-geolite2"
			}
		}
	}

def createTelnetEntry(grok, log_line, container_id, container_path):
	entry = createBasicESEntry(log_line, container_id, container_path)

	entry["_source"]["@timestamp"] = datetime.strptime(grok['timestamp'], "%Y-%m-%d %H:%M:%S").isoformat() + "Z"
	entry["_source"]["_index"] = "telnet-" + grok['timestamp'][0:4] + "." + grok['timestamp'][5:7]
	entry["_source"]["_type"] = "ftp"
	entry["_source"]["ftp"] = { "user": grok['user'], "password": grok['password'] }
	return entry

def createNginxEntry(grok, type, log_line, container_id, container_path):
	entry = createBasicESEntry(log_line, container_id, container_path)

	entry["_index"] = "nginx-"
	if type == "error":
		entry["_index"] = "bad-" + entry["_index"]
	entry["_index"] += type + "-" + grok['timestamp'][0:4] + "." + grok['timestamp'][5:7]
	entry["_type"] = "nginx-" + type

	if type == "access":
		entry["_source"]["nginx"] = \
		{
			"method": grok["method"] if "method" in grok else "",
			"user_name": grok["user_name"],
			"path": container_path,
			"response_code": grok["response_code"],
			"response_size": grok["response_size"],
			"referrer": grok["referrer"],
			"user_agent": {
				"parsed user agent using uap-python"
			}
		}
	else: 
		entry["_source"]["error"] = \
		{
			"level": grok["level"],
			"pid": grok["pid"],
			"tid": grok["tid"],
			"connection_id": grok["connection_id"],
			"message": grok["message"],
		}
	return entry

########################################################################

def parseTelnet(filename):
    f = gzip.open(filename, 'rb')
    container_id = 0
    for line_num, line in enumerate(f, start=0):
        data = telnet_pattern.match(line.decode())
        if data is not None:
            yield createTelnetEntry(data, line_num, container_id, filename)
    f.close()
    
def parseNginx(filename):
    f = gzip.open(filename, 'rb')
    nginx_type = "access" if "access" in sys.argv[1] else "error"
    if nginx_type == "access":
        for line_num, line in enumerate(f, start=0):
            data = None
            for pattern in nginx_access_patterns:
                data = pattern.match(line.decode())

                if data is None or \
					("method" in data and data["method"] not in HTTP_METHODS):
                    continue
            
            if data is not None:
                yield createNginxEntry(data, "access", line_num, 1, "asdf")
    else: 
        for line_num, line in enumerate(f, start=0):
            data = nginx_error_pattern.match(line.decode())
            
            if data is not None:
                yield createNginxEntry(data, "error", line_num, 1, "asdf")
    f.close()
