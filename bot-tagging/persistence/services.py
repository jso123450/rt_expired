from elasticsearch_dsl import Document, InnerDoc, Object, Keyword, Text, Ip, GeoPoint, Integer, Date

SRVC_WEB = "nginx-access"
SRVC_FTP = "ftp"
SRVC_TELNET = "telnet"
SRVC_SSH = "ssh"

NONBOT_PREFIX = "nonbot"
NB_IDX_WEB = f"{NONBOT_PREFIX}-{SRVC_WEB}"


class LogInfoDoc(InnerDoc):
    container = Keyword()
    line = Integer()
    path = Text(fields={"keyword": Keyword()})


class NginxDoc(Document):
    class Index:
        name = SRVC_WEB

    method = Keyword()
    user_name = Text(fields={"keyword": Keyword()})
    response_code = Integer()
    response_size = Integer()
    referrer = Text(fields={"keyword": Keyword()})
    user_agent = Text(fields={"keyword": Keyword()})
    http_version = Text(fields={"keyword": Keyword()})
    http_string = Text(fields={"keyword": Keyword()})
    scheme = Keyword()
    http_host = Text(fields={"keyword": Keyword()})


class NonBotNginxDoc(Document):
    class Index:
        name = NB_IDX_WEB