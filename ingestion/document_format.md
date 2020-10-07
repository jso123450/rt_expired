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
        }
    }
}
```

## nginx
```json
{
    "_index" : "nginx-{access/error}-YYYY-MM-{bad}",
    "_source" : {
        "access" : {
            "ip" : "...",
            "method" : "{GET/POST/...}",
            "user_name" : "...",
            "path" : "...",
            "response_code" : "...",
            "response_size" : "...",
            "referrer" : "...",
            "agent" : "..."
        },
        "error" : {

        }
    }
}
```

## telnet

## ftp

## ssh

## smtp