file1 = ""
file2 = ""
old_sep = "|"
new_sep = "|||||"

bad_lines = []
with open(file1, "r") as f:
    for idx, line in enumerate(f):
        if len(line.split("|")) > 6:
            bad_lines.append(idx)

set_bad_lines = set(bad_lines)
# replace_bad = "^^^^^"
out_f = open(file2, "w+")
with open(file1, "r") as f:
    for idx, line in enumerate(f):
        parts = line.split(old_sep)
        pieces = []
        if idx in set_bad_lines:
            pieces = [parts[0], parts[3]]
            bad_piece = old_sep.join(parts[4:-1])
            count = parts[-1]
            pieces.extend([bad_piece, count])
        else:
            pieces = [parts[0], *parts[3:]]
        new_str = new_sep.join(pieces)
        out_f.write(new_str)
out_f.close()

# FTP_1_DF = Path("/mnt/analysis_artifacts/ftp-telnet/es/ftp-1.csv")
# TELNET_1_DF = Path("/mnt/analysis_artifacts/ftp-telnet/es/telnet-1.csv")
# _FILES = [FTP_1_DF, TELNET_1_DF]
# NEW_FILES = {FTP_1_DF: FTP_DF, TELNET_1_DF: TELNET_DF}
# bad_lines = defaultdict(set)
# old_sep = "|"
# new_sep = "|||||"
# for _file in _FILES:
#     with open(_file, "r") as f:
#         for idx, line in enumerate(f):
#             if len(line.split(old_sep)) > 7:
#                 bad_lines[str(_file)].add(idx)
#     out_f = open(NEW_FILES[_file], "w+")
#     with open(_file, "r") as f:
#         for idx, line in enumerate(f):
#             parts = line.split(old_sep)
#             pieces = [parts[0], *parts[3:]]
#             new_str = new_sep.join(pieces)
#             out_f.write(new_str)
#     out_f.close()
                