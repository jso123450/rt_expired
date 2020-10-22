import pandas as pd

def stacked_bars_ips(final, filtered_out):
    tmp = final.groupby(["id", "idx_ptrn"]).agg(ip_count=("client_ip","count")).reset_index()
    tmp = tmp.assign(FilterLvl=len(filtered_out))
    tmps = [tmp]
    for idx, filtered_out_df in enumerate(filtered_out):
        tmp2 = filtered_out_df.groupby(["id", "idx_ptrn"]).agg(ip_count=("client_ip","count")).reset_index()
        tmp2 = tmp2.assign(FilterLvl=idx)
        tmps.append(tmp2)
    tmp = pd.concat(tmps)