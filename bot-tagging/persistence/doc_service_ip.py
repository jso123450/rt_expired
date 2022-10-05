from elasticsearch_dsl import Document, InnerDoc, Object, Keyword, Text, Ip, GeoPoint, Integer

SRVC_WEB = "nginx-access"
SRVC_FTP = "ftp"
SRVC_TELNET = "telnet"
SRVC_SSH = "ssh"

IP_PREFIX = "ips"
IP_IDX_WEB = f"{IP_PREFIX}-{SRVC_WEB}"
IP_IDX_FTP = f"{IP_PREFIX}-{SRVC_FTP}"
IP_IDX_TELNET = f"{IP_PREFIX}-{SRVC_TELNET}"
IP_IDX_SSH = f"{IP_PREFIX}-{SRVC_SSH}"
IP_IDX_MIRAI = f"{IP_PREFIX}-mirai"
IP_IDX_FP = f"{IP_PREFIX}-fp"

PLACEBO_IP_PREFIX = "placebo-ips"
PLACEBO_IP_IDX_WEB = f"{PLACEBO_IP_PREFIX}-{SRVC_WEB}"


class GeoIpDoc(InnerDoc):
    ip = Ip()
    country_iso_code = Keyword()
    country_name = Text(fields={"keyword": Keyword()})
    region_iso_code = Keyword()
    region_name = Text(fields={"keyword": Keyword()})
    city_name = Text(fields={"keyword": Keyword()})
    timezone = Text(fields={"keyword": Keyword()})
    asn = Integer
    organization_name = Text(fields={"keyword": Keyword()})
    location = GeoPoint()


class ServiceIpDoc(Document):
    class Index:
        name = "ips-*"  # pass index kwarg to .save() operations

    ip = Ip()
    bot_filter_tags = Text(fields={"keyword": Keyword()})
    user_filter_tags = Text(fields={"keyword": Keyword()})
    other_tags = Text(fields={"keyword": Keyword()})
    geoip = Object(GeoIpDoc)

    def save(self, **kwargs):
        return super().save(**kwargs)


class WebIpDoc(ServiceIpDoc):
    class Index:
        name = IP_IDX_WEB


class FtpIpDoc(ServiceIpDoc):
    class Index:
        name = IP_IDX_FTP


class TelnetIpDoc(ServiceIpDoc):
    class Index:
        name = IP_IDX_TELNET


class SshIpDoc(ServiceIpDoc):
    class Index:
        name = IP_IDX_SSH


class MiraiIpDoc(ServiceIpDoc):
    class Index:
        name = IP_IDX_MIRAI


class FingerprintIpDoc(ServiceIpDoc):
    class Index:
        name = IP_IDX_FP


IP_INDEX_DOC_MAPPING = {
    "nginx-access-*": WebIpDoc,
    "ftp-*": FtpIpDoc,
    "telnet-*": TelnetIpDoc,
    "ssh-*": SshIpDoc,
    "fp-*": FingerprintIpDoc,
}


class PlaceboWebIpDoc(ServiceIpDoc):
    class Index:
        name = PLACEBO_IP_IDX_WEB


PLACEBO_IP_INDEX_DOC_MAPPING = {
    "nginx-access-*": PlaceboWebIpDoc,
}


def get_ip_idx_doc(idx_ptrn):
    return IP_INDEX_DOC_MAPPING[idx_ptrn]


def get_placebo_ip_idx_doc(idx_ptrn):
    return PLACEBO_IP_INDEX_DOC_MAPPING[idx_ptrn]