from enum import Enum, unique


@unique
class QueryEnum(Enum):
    SEARCH = "s"
    UBQ = "ubq"