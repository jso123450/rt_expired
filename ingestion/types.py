from enum import Enum, unique, auto


@unique
class LogType(Enum):
    NGINX = "NGINX"
    TELNET = "TELNET"
    SSH = "SSH"
    FTP = "FTP"
    SMTP = "SMTP"

    @classmethod
    def get_type(cls, filename):
        if "nginx" in filename:
            return LogType.NGINX
        elif "telnet" in filename:
            return LogType.TELNET
        elif "cowrie" in filename:
            return LogType.SSH
        elif "mail" in filename:
            return LogType.SMTP