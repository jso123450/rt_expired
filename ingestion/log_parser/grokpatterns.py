from pygrok import Grok

########################################################

NGINX_ACCESS_PATTERNS = [
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # normal
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:method} %{DATA:url} HTTP\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # normal w/o http version
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{IPORHOST:name} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:name} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{IPORHOST:name} \"%{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:name} \"%{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{GREEDYDATA:http_string}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # no method no name
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] %{GREEDYDATA:unknown_message_pattern}",  # unknown nginx message pattern
	#%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{GREEDYDATA:other} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" \|\|\|\| %{NUMBER:response_code} \|\|\|\| %{NUMBER:bytes} %{GREEDYDATA:other_2} \"%{DATA:referrer}\" \|\|\|\| \"%{DATA:agent}\" # pipe pattern
]

NGINX_ERROR_PATTERNS = [
	"%{DATA:[nginx][error][time]} \[%{DATA:[nginx][error][level]}\] %{NUMBER:[nginx][error][pid]}#%{NUMBER:[nginx][error][tid]}: (\*%{NUMBER:[nginx][error][connection_id]} )?%{GREEDYDATA:[nginx][error][message]}"
]

TELNET_PATTERNS = [
	"%{GREEDYDATA:timestamp} : %{IP:ip} : %{GREEDYDATA:user} : %{GREEDYDATA:password}",
	"%{WORD:timestamp} : %{IP:ip} : %{WORD:user} : %{WORD:password}"
]

FTP_PATTERNS = [
	"%{GREEDYDATA:timestamp} : %{IP:ip} : %{GREEDYDATA:user} : %{GREEDYDATA:password}",
]

POSTFIX_PREFIX = "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST} %{DATA:program}(?:\[%{POSINT}\])?: %{GREEDYDATA:message}"
POSTFIX_PATTERNS = [
	"%{WORD:postfix_queueid}: from=<%{DATA:postfix_from}>, status=%{WORD:postfix_status}, returned to sender",
]

########################################################

TELNET_MATCHER = [Grok(ptrn) for ptrn in TELNET_PATTERNS]
NGINX_ACCESS_MATCHER = [Grok(ptrn) for ptrn in NGINX_ACCESS_PATTERNS]
NGINX_ERROR_MATCHER = [Grok(ptrn) for ptrn in NGINX_ERROR_PATTERNS]
FTP_MATCHER = [Grok(ftp_pat) for ftp_pat in FTP_PATTERNS]
POSTFIX_MATCHER = [Grok(POSTFIX_PREFIX) for postfix_pat in POSTFIX_PATTERNS]