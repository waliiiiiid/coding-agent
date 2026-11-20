from lib.model import model
from lib.state import State

def reviewer(state:State):
    prompt = f"""
You are an expert software engineer and code reviewer.

Review the code based on:
1. The code itself — syntax, logic, and whether it satisfies the user request.
2. The execution results as supporting evidence.

IMPORTANT:
- A failed execution does NOT automatically mean the code is wrong.
- If failure is caused by missing user input, sandbox/environment limitations,
  missing files, dependencies, or configuration, do NOT mark the code incorrect.
- For example, input() without provided stdin causing EOFError is an environment
  issue, not necessarily a code error.
- Only mark NO when the problem is actually caused by the code.

Return ONLY:
correct: YES <explanation>
or
correct: NO <explanation>

code:
{state['code']}

user instructions:
{state['instructions']}

user request:
{state['request']}

standard output:
{state['stdout']}

standard error:
{state['stderr']}

return code:
{state['returncode']}
"""
    response=model.invoke(prompt)
    return{
        "review":response.content,
        "is_correct": "correct: YES" in response.content,
    }