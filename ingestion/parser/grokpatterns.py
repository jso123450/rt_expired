nginx_access = [
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] \"%{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # normal
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] \"%{IPORHOST:name} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:agent}\" \"%{DATA:referrer}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] \"%{WORD:name} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:agent}\" \"%{DATA:referrer}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] \"%{IPORHOST:name} \"%{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:agent}\" \"%{DATA:referrer}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] \"%{WORD:name} \"%{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:agent}\" \"%{DATA:referrer}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:time}\] \"%{GREEDYDATA:http_string}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:agent}\" \"%{DATA:referrer}\"",  # no method no name
]

nginx_error = [
	"%{DATA:[nginx][error][time]} \[%{DATA:[nginx][error][level]}\] %{NUMBER:[nginx][error][pid]}#%{NUMBER:[nginx][error][tid]}: (\*%{NUMBER:[nginx][error][connection_id]} )?%{GREEDYDATA:[nginx][error][message]}"
]

telnet = [
	"%{GREEDYDATA:timestamp} : %{IP:ip} : %{GREEDYDATA:user} : %{GREEDYDATA:password}",
	"%{WORD:timestamp} : %{IP:ip} : %{WORD:user} : %{WORD:password}\n"
]

ftp_patterns = [
	"%{GREEDYDATA:timestamp} : %{IP:ip} : %{GREEDYDATA:user} : %{GREEDYDATA:password}",
]