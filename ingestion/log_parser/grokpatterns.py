from pygrok import Grok
from korg import PatternRepo, LineGrokker
########################################################

NGINX_ACCESS_PATTERNS = [
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # normal
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:method} %{DATA:url} HTTP\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # normal w/o http version
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{IPORHOST:name} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:name} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{IPORHOST:name} \"%{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{WORD:name} \"%{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # weird normal + name(ip/host)
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{GREEDYDATA:http_string}\" %{NUMBER:response_code} %{NUMBER:bytes} \"%{DATA:referrer}\" \"%{DATA:agent}\"",  # no method no name
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{GREEDYDATA:pipe_header} %{WORD:method} %{DATA:url} HTTP/%{NUMBER:http_version}\" |||| %{NUMBER:response_code} |||| %{NUMBER:bytes} %{GREEDYDATA:pipe_header_2} \"%{DATA:referrer}\" |||| \"%{DATA:pipe_number}\"", # pipe pattern
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] \"%{GREEDYDATA:pipe_header} %{WORD:method} %{DATA:url} HTTP\" |||| %{NUMBER:response_code} |||| %{NUMBER:bytes} %{GREEDYDATA:pipe_header_2} \"%{DATA:referrer}\" |||| \"%{DATA:pipe_number}\"", # pipe pattern w/o http version
	"%{IPORHOST:remote_ip} - %{DATA:user_name} \[%{HTTPDATE:timestamp}\] %{GREEDYDATA:unknown_message_pattern}",  # unknown nginx message pattern
]

NGINX_ERROR_PATTERNS = [
	"%{DATA:timestamp} \[%{DATA:level}\] %{NUMBER:pid}#%{NUMBER:tid}: (\*%{NUMBER:connection_id} )?%{GREEDYDATA:message}"
]

TELNET_PATTERNS = [
	"%{GREEDYDATA:timestamp} : %{IP:ip} : %{GREEDYDATA:user} : %{GREEDYDATA:password}",
	"%{WORD:timestamp} : %{IP:ip} : %{WORD:user} : %{WORD:password}"
]

FTP_PATTERNS = [
	"%{GREEDYDATA:timestamp} : %{IP:ip} : %{GREEDYDATA:user} : %{GREEDYDATA:password}",
]

POSTFIX_PREFIX_PATTERN = "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST} %{DATA:program}(?:\[%{POSINT}\])?: %{GREEDYDATA:message}"

########################################################

TELNET_MATCHER = [Grok(ptrn) for ptrn in TELNET_PATTERNS]
NGINX_ACCESS_MATCHER = [Grok(ptrn) for ptrn in NGINX_ACCESS_PATTERNS]
NGINX_ERROR_MATCHER = [Grok(ptrn) for ptrn in NGINX_ERROR_PATTERNS]
FTP_MATCHER = [Grok(ftp_pat) for ftp_pat in FTP_PATTERNS]
POSTFIX_PREFIX_MATCHER = Grok(POSTFIX_PREFIX_PATTERN)
POSTFIX_PATTERN_REPO = PatternRepo()
POSTFIX_MESSAGE_MATCHER = {
    'postfix/smtp': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_SMTPD_CONNECT}|%{POSTFIX_SMTPD_DISCONNECT}|' +
                    '%{POSTFIX_SMTPD_LOSTCONN}|%{POSTFIX_SMTPD_NOQUEUE}|%{POSTFIX_SMTPD_PIPELINING}|%{POSTFIX_TLSCONN}|' + 
                    '%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}|%{POSTFIX_SMTPD_PROXY}|%{POSTFIX_KEYVALUE}').split('|')],
    'postfix/cleanup': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_CLEANUP_MESSAGEID}|%{POSTFIX_CLEANUP_MILTER}|'+
                    '%{POSTFIX_CLEANUP_PREPEND}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}|%{POSTFIX_KEYVALUE}').split('|')],
    'postfix/qmgr': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_QMGR_REMOVED}|%{POSTFIX_QMGR_ACTIVE}|'+
                    '%{POSTFIX_QMGR_EXPIRED}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/pipe': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_PIPE}').split('|')],
    'postfix/postscreen': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_PS_CONNECT}|%{POSTFIX_PS_ACCESS}|'+
                    '%{POSTFIX_PS_NOQUEUE}|%{POSTFIX_PS_TOOBUSY}|%{POSTFIX_PS_CACHE}|%{POSTFIX_PS_DNSBL}|%{POSTFIX_PS_VIOLATIONS}|'+
                    '%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/dnsblog': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_DNSBLOG_LISTING}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/anvil': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_ANVIL_CONN_RATE}|%{POSTFIX_ANVIL_CONN_CACHE}|'+
                    '%{POSTFIX_ANVIL_CONN_COUNT}').split('|')],
    'postfix/smtp': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_SMTP_DELIVERY}|%{POSTFIX_SMTP_CONNERR}|'+
                    '%{POSTFIX_SMTP_SSLCONNERR}|%{POSTFIX_SMTP_LOSTCONN}|%{POSTFIX_SMTP_TIMEOUT}|%{POSTFIX_SMTP_RELAYERR}|'+
                    '%{POSTFIX_TLSCONN}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}|'+
                    '%{POSTFIX_SMTP_UTF8}|%{POSTFIX_TLSVERIFICATION}').split('|')],
    'postfix/discard': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_DISCARD_ANY}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/lmtp': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_SMTPD_CONNECT}|%{POSTFIX_SMTPD_DISCONNECT}|' +
                    '%{POSTFIX_SMTPD_LOSTCONN}|%{POSTFIX_SMTPD_NOQUEUE}|%{POSTFIX_SMTPD_PIPELINING}|%{POSTFIX_TLSCONN}|' + 
                    '%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}|%{POSTFIX_SMTPD_PROXY}|%{POSTFIX_KEYVALUE}').split('|')],
    'postfix/pickup': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_KEYVALUE}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/tlsproxy': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_TLSPROXY_CONN}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/master': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_MASTER_START}|%{POSTFIX_MASTER_EXIT}|'+
                    '%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/bounce': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_BOUNCE_NOTIFICATION}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/sendmail': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/postdrop': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/scache': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_SCACHE_LOOKUPS}|%{POSTFIX_SCACHE_SIMULTANEOUS}|'+
                    '%{POSTFIX_SCACHE_TIMESTAMP}').split('|')],
    'postfix/trivial-rewrite': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/tlsmgr': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/local': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_KEYVALUE}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/virtual': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_SMTP_DELIVERY}').split('|')],
    'postfix/error': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_ERROR_ANY}|%{POSTFIX_WARNING_WITH_KV}|%{POSTFIX_WARNING_WITHOUT_KV}').split('|')],
    'postfix/postsuper': [LineGrokker(subpattern, POSTFIX_PATTERN_REPO) for subpattern in ('%{POSTFIX_POSTSUPER_ACTION}|%{POSTFIX_POSTSUPER_SUMMARY}').split('|')],
}