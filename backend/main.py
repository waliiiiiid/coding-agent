from lib.workflow import graph
from fastapi import FastAPI,File,UploadFile
from pydantic import BaseModel
from lib.excuter import run_in_sandbox


app=FastAPI()
config={
    "configurable":{
        "thread_id":"user_1"
    }
}

instructions_text=None

class GenerateRequest(BaseModel):
    request:str
class ReviewRequest(BaseModel):
    code:str


@app.get("/")
def home():
    return {"message":"running"}


@app.post("/inst")
async def receive_inst(file:UploadFile =File(...)):
    global instructions_text
    content=await file.read()
    temp=content.decode("utf-8")
    response=graph.invoke({
        'code':"",
        'humman_approval':False,
        'is_correct':False,
        'request':'',
        'returncode':'',
        'review':'',
        'stderr':'',
        'stdout':'',
        "task":'gate',
        'instructions':temp,
        'inst_rev':'',
        'inst_safe':''
    },config=config)
    if response['inst_safe']:
        instructions_text=temp
        return{
            "message":"Instructions Uploaded Successfully",
            "inst_rev":response['inst_rev'],
            "inst_safe":response['inst_safe']
        }
    return{
        "message":"Can Not Load Instructions!",
        "inst_rev":response['inst_rev'],
         "inst_safe":response['inst_safe']
    }
    


@app.get("/inst")

async def get_inst():
    if instructions_text is not None:
        return{
            "instructions":instructions_text
        }
    return {
        "instructions":"No Custom Instructions Uploaded"
    }



@app.post("/generate")
async def generate(data:GenerateRequest):
    result=graph.invoke({
        'code':"",
        'humman_approval':False,
        'is_correct':False,
        'request':data.request,
        'returncode':'',
        'review':'',
        'stderr':'',
        'stdout':'',
        "task":'write',
        'instructions':instructions_text,
        'inst_rev':'',
        'inst_safe':''
    },config=config)

    return {
        "code":result['code'],
        "review":result['review']
    }


@app.post("/review")
async def review(code:ReviewRequest):
    excute=run_in_sandbox(code.code)
    result=graph.invoke({
        'code':code.code,
        'humman_approval':False,
        'is_correct':False,
        'request':'',
        'returncode':excute['returncode'],
        'review':'',
        'stderr':excute['stderr'],
        'stdout':excute['stdout'],
        'task':'review',
        'instructions':instructions_text,
        'inst_rev':'',
        'inst_safe':''
    },config=config)

    return{
        "review":result['review'],
        'is_correct':result['is_correct'],
        'stdout':result['stdout'],
        'stderr':result['stderr'],
        'returncode':result['returncode']
    }

