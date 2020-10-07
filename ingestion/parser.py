from enum_types import LogType


def _parse_nginx(line):
    pass


def _parse_telnet(line):
    pass


def _parse_ftp(line):
    pass


def _parse_ssh(line):
    pass


def _parse_smtp(line):
    pass


LOG_TYPE_PARSER = {
    LogType.NGINX: _parse_nginx,
    LogType.TELNET: _parse_telnet,
    LogType.FTP: _parse_ftp,
    LogType.SSH: _parse_ssh,
    LogType.SMTP: _parse_smtp,
}


def parse(filename):
    """Parses a log file and returns a generator that yields the parsed documents.
    These documents should be ready to index into Elasticsearch.

    Parameters
    ----------
    filename : str or Path

    Returns
    -------
    doc_generator : generator
        generator that yields documents for es.bulk
        {
            '_index': '{service}-YYYY-MM',
            '_source': {
                "title": "Hello World!",
                "body": "..."
            }
        }
    """
    log_type = LogType.get_type(filename)
    with open(filename, "r") as f:
        for line in f:
            yield LOG_TYPE_PARSER[log_type](line)