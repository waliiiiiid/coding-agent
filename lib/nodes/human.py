from lib.model import model
from lib.state import State
from langgraph.types import interrupt

def human(state:State):
    answer=interrupt("I Found Errors In The Code Do You Want Me To Fix Them ")
    return{
        "humman_approval":answer
    }