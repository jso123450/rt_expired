import es_utils
import utils

###############################################################################


LOGGER = utils.get_logger("ssh", "./logs/ssh.log")

SSH_IDX_PTRN = "ssh-*"

###############################################################################


def tag(_tags, init=False):
    if init:
        es_utils.init_ip_index(SSH_IDX_PTRN)