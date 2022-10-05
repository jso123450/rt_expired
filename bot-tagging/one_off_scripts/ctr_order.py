%load_ext autotime

import utils
sorted_ctrs = utils.get_sorted_containers()
nonplacebos = utils.get_nonplacebos()
s_ctrs = [_id for _id in sorted_ctrs if int(_id) in nonplacebos]
r_ctrs = list(reversed(s_ctrs))