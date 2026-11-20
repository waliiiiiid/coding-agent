from typing import TypedDict

class State(TypedDict):
    task:str
    request:str
    code:str
    review:str
    is_correct:bool
    humman_approval:bool
    stdout:str
    stderr:str
    returncode:int
    instructions:str
    inst_safe:bool
    inst_rev:str
