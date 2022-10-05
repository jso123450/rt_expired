from enum import Enum, unique


@unique
class QueryEnum(Enum):
    SEARCH = "s"
    UBQ = "ubq"


@unique
class TagEnum(Enum):
    BOT = "bot"
    USER = "user"
    OTHER = "other"
    UNTAGGED = "untagged"