from lib.model import model
from lib.state import State

def fixer(state:State):
    prompt=f"""
    You are an expert software engineer.
    review:{state['review']}
    code:{state['code']}
Your task is to fix the provided code according to the review.
Return ONLY the code 
"""
    response=model.invoke(prompt)
    return{
        "code":response.content,
        "task":"fix"
    }