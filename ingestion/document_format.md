# Log Document Format

## common
```json
{
    "_source" : {
        "@timestamp": "...",
        "log": {
            "container": "{id}",
            "path": "{path}",
            "line": 42
        },
        "ip" : "...",
        "geoip" : {
            "parsed using python-geoip-geolite2"
        }
    }
}
```

## nginx
```json
{
    "_index" : "{bad-}nginx-{access/error}-YYYY.MM",
    "_type" : "nginx-{access/error}",
    "_source" : {
        "nginx": {
            "access" : {
                "method" : "{GET/POST/...}",
                "user_name" : "...",
                "path" : "...",
                "response_code" : "...",
                "response_size" : "...",
                "referrer" : "...",
                "user_agent" : {
                    "parsed user agent using uap-python"
                }
            },
            "error" : {
                "level": "...",
                "pid": "...",
                "tid": "...",
                "connection_id": "...",
                "message": "..."
            }
        }
        
    }
}
```

## telnet
```json
{
    "_index" : "telnet-YYYY.MM",
    "_type" : "ftp",
    "_source" : {
        "ftp": {
            "user": "...",
            "password": "..."
        }
    }
}
```

## ftp
```json
{
    "_index" : "ftp-YYYY.MM",
    "_type" : "ftp",
    "_source" : {
        "ftp": {
            "user": "...",
            "password": "..."
        }
    }
}
```

## ssh
```json
{
    "_index" : "ssh-YYYY.MM",
    "_type" : "ssh",
    "_source" : {
        "cowrie_log"
    }
}
```

## postfix
Mirror the structure from the `postfix` Logstash grok patterns.