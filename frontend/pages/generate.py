import streamlit as st
import requests
st.set_page_config(
    page_title="Code Agent",
    page_icon="🤖",
    layout="wide"
)

st.subheader("Start Building")

request=st.text_area("Tell the agent what you want to build and we'll take it from there.",placeholder="Simple Calculator Using Python")

if st.button("Generate",use_container_width=True):
    if request:
        with st.spinner("Loading..."):
            response=requests.post(
                "http://127.0.0.1:8000/generate",
                json={
                    "request":request
                }
            )
            if response.status_code == 200:
                result=response.json()
                st.code(result['code'])
                st.write(result['review'])
    else:
        st.warning("Enter a Request!")