from langgraph.graph import StateGraph, START, END
from lib.state import State
from langgraph.checkpoint.memory import MemorySaver
from lib.nodes.reviewer import reviewer
from lib.nodes.writer import writer
from lib.nodes.fixer import fixer
from lib.nodes.human import human
from lib.nodes.gate import gate


def router(state: State):
    if state["task"] == "review":
        return "reviewer"
    elif state["task"] == "write":
        return "writer"
    else:
        return 'gate'


def review_router(state: State):
    if state['is_correct']:
        return 'end'
    if state['task']=='write':
        return 'fixer'
    if state['task']=='fix':
        return 'fixer'
    return 'human'


def human_route(state: State):
    if state["humman_approval"]:
        return "fixer"

    return "end"


builder = StateGraph(State)

# Nodes
builder.add_node("reviewer", reviewer)
builder.add_node("writer", writer)
builder.add_node("fixer", fixer)
builder.add_node("human", human)
builder.add_node('gate',gate)

# Writer -> Reviewer
builder.add_edge("writer", "reviewer")


# START -> Writer OR Reviewer
builder.add_conditional_edges(
    START,
    router,
    {
        "writer": "writer",
        "reviewer": "reviewer",
        'gate':'gate'
    }
)


# Reviewer -> END OR Human
builder.add_conditional_edges(
    "reviewer",
    review_router,
    {
        "end": END,
        "human": "human",
        'fixer':'fixer'
    }
)


# Human -> Fixer OR END
builder.add_conditional_edges(
    "human",
    human_route,
    {
        "end": END,
        "fixer": "fixer",
    }
)



# Fixer -> END
builder.add_edge("fixer", 'reviewer')

memory=MemorySaver()
graph = builder.compile(checkpointer=memory)


# Generate PNG
png_bytes = graph.get_graph().draw_mermaid_png()

with open("workflow.png", "wb") as f:
    f.write(png_bytes)