import streamlit as st
import requests
st.set_page_config(
    page_title="Code Agent",
    page_icon="🤖",
    layout="wide"
)

st.subheader("Customize The Agent")

instructions=st.file_uploader(
    "Upload custom instructions",
    type=['txt']
)

if instructions is not None:
    with st.spinner("Reading instructions..."):
        response=requests.post(
            "http://127.0.0.1:8000/inst",
            files={
                "file":(
                    instructions.name,
                    instructions.getvalue(),
                    "text/plain"
                )
            }
        )
        if response.status_code ==200:
            data=response.json()
            st.write(data['inst_rev'])
            if data['inst_safe']:
                st.success('inst loaded')
            else:
                st.error('cant load instructions')
        else:
            st.error("Somthing went wrong")



col1 , col2 =st.columns(2)

with col1:
    if st.button('current instructions'):
        response=requests.get(
            "http://127.0.0.1:8000/inst",
        )
        if response.status_code==200:
            data=response.json()
            instructions=data['instructions']
            st.write(instructions)

with col2 :
    if st.button('Delete All'):
        pass


