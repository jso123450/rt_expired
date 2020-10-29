import pandas as pd
import matplotlib.pyplot as plt
import plotly.graph_objects as go

# def stacked_bars_ips(final, filtered_out):
#     tmp = final.groupby(["id", "idx_ptrn"]).agg(ip_count=("client_ip","count")).reset_index()
#     tmp = tmp.assign(FilterLvl=len(filtered_out))
#     tmps = [tmp]
#     for idx, filtered_out_df in enumerate(filtered_out):
#         tmp2 = filtered_out_df.groupby(["id", "idx_ptrn"]).agg(ip_count=("client_ip","count")).reset_index()
#         tmp2 = tmp2.assign(FilterLvl=idx)
#         tmps.append(tmp2)
#     tmp = pd.concat(tmps)

def plot_stacked_bar(df, legend, _file):
    ax = df.plot.bar(x="identifier", stacked=True)
    fig = plt.gcf()
    fig.set_size_inches(48, 10)
    fig.patch.set_facecolor("white")
    fig.subplots_adjust(left=0.1,right=0.9,bottom=0.25)
    ax.set_yscale("log")
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.yaxis.set_ticks_position('none')
    ax.xaxis.set_ticks_position('none')
    ax.grid(axis = 'y', color ='white', linestyle='-')

    plt.xticks(rotation=90,fontsize=10)
    plt.ylabel("Number of Unique Client IPs")
    plt.xlabel("CTID Domain")
    plt.title(f"Filtering Level Effects on Unique Client IPs")
    plt.legend(legend, fontsize=16)
    plt.savefig(_file)
    plt.close(fig)
    print("Finished plotting.")


def plot_ip_counts(dfs, legend, _file):
    tmp = dfs[0][["id", "domain"]]
    for idx, filtered_df in enumerate(dfs):
        tmp2 = filtered_df.groupby(["id", "domain"]).agg(ip_count=("client_ip", "nunique")).reset_index()
        tmp2 = tmp2.rename(columns={"ip_count": f"ip_count_{idx+1}"})
        tmp = tmp.merge(tmp2, on=["id", "domain"], how="outer")
    tmp = tmp.drop_duplicates().fillna({f"ip_count_{idx+1}":0 for idx in range(len(dfs))})
    tmp["id_str"] = tmp["id"].apply(lambda x: str(x))
    tmp["identifier"] = tmp["id_str"] + " " + tmp["domain"]
    tmp = tmp.drop(columns=["id"])
    tmp = tmp.sort_values(by=[f"ip_count_{idx+1}" for idx in range(len(dfs))], ascending=[True for _ in range(len(dfs))])

    plot_stacked_bar(tmp, legend, _file)
    return tmp


def plot_sankey_filters(plot_ip_tmp, filter_lvl_labels, node_labels, _file):
    cols = [f"ip_count_{idx+1}" for idx in range(len(filter_lvl_labels))]
    sums = [plot_ip_tmp[col].sum() for col in cols]
    sums = list(reversed(sums))
    total_sums = []
    for idx in range(len(sums)):
        partial = sum(sums[idx+1:])
        total_sums.append(sums[idx] + partial)
    source_target_values = []
    for idx in range(len(total_sums)-1):
        src = idx*2
        filtered_out = idx*2+1
        kept = idx*2+2
        filtered_out_val = total_sums[idx] - total_sums[idx+1]
        kept_val = total_sums[idx+1]
        source_target_values.append((src,filtered_out,filtered_out_val))
        source_target_values.append((src,kept,kept_val))
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad = 15,
            thickness = 20,
            line = dict(color="black", width=0.5),
            label = node_labels,
            color = "blue",
        ),
        link=dict(
            source = [_tuple[0] for _tuple in source_target_values],
            target = [_tuple[1] for _tuple in source_target_values],
            value = [_tuple[2] for _tuple in source_target_values],
        )
    )])
    fig.update_layout(title_text="Filtering Level Effects on Unique Client IPs", font_size=10)
    fig.write_html(str(_file))
    # fig.write_image(str(_file))