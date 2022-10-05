import plotly.graph_objects as go


def style_grid(ax, spines=False, ticks=False, grid=True):
    ax.spines["top"].set_visible(spines)
    ax.spines["right"].set_visible(spines)
    if not ticks:
        ax.yaxis.set_ticks_position("none")
        ax.xaxis.set_ticks_position("none")
    if grid:
        ax.grid(axis="y", color="white", linestyle="-")


def plot_sankey(
    node_labels, data_tuples, _file, pos=[], title="Filtering Level Effects on Unique Client IPs"
):
    fig = go.Figure(
        data=[
            go.Sankey(
                arrangement="snap",
                node=dict(
                    pad=5,
                    thickness=10,
                    line=dict(color="black", width=0.5),
                    label=node_labels,
                    x=[xy[0] for xy in pos],
                    y=[xy[1] for xy in pos],
                    color="blue",
                ),
                link=dict(
                    source=[_tuple[0] for _tuple in data_tuples],
                    target=[_tuple[1] for _tuple in data_tuples],
                    value=[_tuple[2] for _tuple in data_tuples],
                    label=[_tuple[2] for _tuple in data_tuples],
                ),
            )
        ]
    )
    fig.update_layout(title_text=title, font_size=10)
    fig.write_html(str(_file))
    return fig