from lib.model import model
from lib.state import State

def writer(state:State):
    prompt=f"""
You are an expert software engineer.
user request:{state['request']}
previous code:{state['code']}
user instructions {state['instructions']}

Your task is to write a code acccording to the user request.
If the user did not specify the programming language, write the code in python.
if user instructions are provided follow it.
Return ONLY the code.

"""
    response=model.invoke(prompt)
    return {
        "code":response.content
    }