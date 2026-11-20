import streamlit as st
import requests
import os
import shutil
import zipfile
import io


# ============================================================
# STREAMLIT CONFIG
# ============================================================

st.set_page_config(
    page_title="Code Agent",
    page_icon="🤖",
    layout="wide"
)


# ============================================================
# PROJECT DIRECTORY
# ============================================================

PROJECT_DIR = "uploaded_project"


# ============================================================
# INITIALIZE WORKSPACE
# ============================================================

if "workspace_initialized" not in st.session_state:

    if os.path.exists(PROJECT_DIR):
        shutil.rmtree(PROJECT_DIR)

    os.makedirs(PROJECT_DIR)

    st.session_state.workspace_initialized = True
    st.session_state.selected_file = None
    st.session_state.project_loaded = False


# ============================================================
# WORKSPACE FUNCTIONS
# ============================================================

def clear_workspace():

    if os.path.exists(PROJECT_DIR):
        shutil.rmtree(PROJECT_DIR)

    os.makedirs(PROJECT_DIR)

    st.session_state.selected_file = None


# ============================================================
# ZIP FUNCTIONS
# ============================================================

def extract_zip(uploaded_file):

    clear_workspace()

    with zipfile.ZipFile(uploaded_file, "r") as zip_ref:
        zip_ref.extractall(PROJECT_DIR)


# ============================================================
# GITHUB FUNCTIONS
# ============================================================

def download_github_repo(repo_url):

    """
    Download a public GitHub repository without requiring Git.

    The repository is downloaded as a ZIP archive and extracted
    into PROJECT_DIR.
    """

    repo_url = repo_url.strip().rstrip("/")

    # --------------------------------------------------------
    # Validate GitHub URL
    # --------------------------------------------------------

    parts = repo_url.split("/")

    if (
        len(parts) < 5
        or parts[0] != "https:"
        or parts[1] != ""
        or parts[2].lower() != "github.com"
    ):

        raise ValueError(
            "Invalid GitHub repository URL."
        )

    owner = parts[3]
    repo = parts[4]

    # Remove .git if the user entered it
    if repo.endswith(".git"):
        repo = repo[:-4]

    if not owner or not repo:
        raise ValueError(
            "Invalid GitHub repository URL."
        )

    # --------------------------------------------------------
    # Try main branch
    # --------------------------------------------------------

    zip_url = (
        f"https://github.com/{owner}/{repo}"
        f"/archive/refs/heads/main.zip"
    )

    response = requests.get(
        zip_url,
        timeout=30
    )

    # --------------------------------------------------------
    # Try master branch if main doesn't exist
    # --------------------------------------------------------

    if response.status_code != 200:

        zip_url = (
            f"https://github.com/{owner}/{repo}"
            f"/archive/refs/heads/master.zip"
        )

        response = requests.get(
            zip_url,
            timeout=30
        )

    # --------------------------------------------------------
    # Check download result
    # --------------------------------------------------------

    if response.status_code != 200:

        raise ValueError(
            "Could not download repository. "
            "Make sure the repository is public and "
            "the URL is correct."
        )

    # --------------------------------------------------------
    # Clear previous project
    # --------------------------------------------------------

    clear_workspace()

    # --------------------------------------------------------
    # Open downloaded ZIP from memory
    # --------------------------------------------------------

    with zipfile.ZipFile(
        io.BytesIO(response.content),
        "r"
    ) as zip_ref:

        zip_ref.extractall(PROJECT_DIR)

    # --------------------------------------------------------
    # GitHub ZIP structure is usually:
    #
    # uploaded_project/
    #     repository-main/
    #         file1.py
    #         file2.py
    #
    # We move the contents of repository-main directly
    # into uploaded_project.
    # --------------------------------------------------------

    extracted_items = os.listdir(PROJECT_DIR)

    if len(extracted_items) == 1:

        root_folder = os.path.join(
            PROJECT_DIR,
            extracted_items[0]
        )

        if os.path.isdir(root_folder):

            for item in os.listdir(root_folder):

                source = os.path.join(
                    root_folder,
                    item
                )

                destination = os.path.join(
                    PROJECT_DIR,
                    item
                )

                shutil.move(
                    source,
                    destination
                )

            os.rmdir(root_folder)


# ============================================================
# FILE EXPLORER
# ============================================================

def show_file_explorer(directory):

    for root, dirs, files in os.walk(directory):

        dirs.sort()
        files.sort()

        relative_root = os.path.relpath(
            root,
            directory
        )

        # Calculate folder depth
        if relative_root == ".":
            depth = 0
        else:
            depth = relative_root.count(os.sep) + 1

        # ----------------------------------------------------
        # FOLDER
        # ----------------------------------------------------

        if relative_root != ".":

            folder_name = os.path.basename(root)

            indentation = "&nbsp;" * (depth * 4)

            st.sidebar.markdown(
                f"{indentation}📁 **{folder_name}**",
                unsafe_allow_html=True
            )

        # ----------------------------------------------------
        # FILES
        # ----------------------------------------------------

        for file in files:

            file_path = os.path.join(
                root,
                file
            )

            relative_path = os.path.relpath(
                file_path,
                directory
            )

            if st.sidebar.button(
                f"📄 {file}",
                key=f"file_{relative_path}",
                use_container_width=True
            ):

                st.session_state.selected_file = file_path


# ============================================================
# READ SELECTED FILE
# ============================================================

def get_selected_file_content():

    file_path = st.session_state.get(
        "selected_file"
    )

    if not file_path:
        return None

    # --------------------------------------------------------
    # Check that file still exists
    # --------------------------------------------------------

    if not os.path.exists(file_path):

        st.error(
            "The selected file no longer exists."
        )

        st.session_state.selected_file = None

        return None

    # --------------------------------------------------------
    # SECURITY CHECK
    # --------------------------------------------------------

    project_root = os.path.abspath(
        PROJECT_DIR
    )

    selected_path = os.path.abspath(
        file_path
    )

    if not selected_path.startswith(
        project_root
    ):

        st.error(
            "Invalid file location."
        )

        st.session_state.selected_file = None

        return None

    # --------------------------------------------------------
    # READ FILE
    # --------------------------------------------------------

    try:

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as f:

            content = f.read()

        return content

    except UnicodeDecodeError:

        st.warning(
            "This file is not a text file."
        )

        return None

    except Exception as e:

        st.error(
            f"Could not read file: {e}"
        )

        return None


# ============================================================
# DISPLAY SELECTED FILE
# ============================================================

def display_selected_file():

    file_path = st.session_state.get(
        "selected_file"
    )

    if not file_path:
        return None

    content = get_selected_file_content()

    if content is None:
        return None

    relative_path = os.path.relpath(
        file_path,
        PROJECT_DIR
    )

    st.subheader(
        f"📄 {relative_path}"
    )

    st.code(
        content
    )

    return content


# ============================================================
# REVIEW CODE
# ============================================================

def review_code(code):

    if not code or not code.strip():

        st.warning(
            "There is no code to review."
        )

        return

    with st.spinner("Reading Code..."):

        try:

            response = requests.post(
                "http://127.0.0.1:8000/review",
                json={
                    "code": code
                }
            )

            if response.status_code == 200:

                result = response.json()

                # ------------------------------------------------
                # RESULTS
                # ------------------------------------------------

                col1, col2 = st.columns(2)

                # ------------------------------------------------
                # AGENT FEEDBACK
                # ------------------------------------------------

                with col1:

                    st.subheader(
                        "Agent Feedback",
                        text_alignment="center"
                    )

                    if result["is_correct"]:

                        st.success(
                            "No Errors Were Found!"
                        )

                    else:

                        st.error(
                            "Errors Were Found!"
                        )

                    st.write(
                        result["review"]
                    )

                # ------------------------------------------------
                # EXECUTION RESULTS
                # ------------------------------------------------

                with col2:

                    st.subheader(
                        "Execution Results",
                        text_alignment="center"
                    )

                    st.write(
                        "Standard Output:"
                    )

                    st.code(
                        result["stdout"]
                    )

                    st.write(
                        "Standard Error:"
                    )

                    st.code(
                        result["stderr"]
                    )

                    st.write(
                        "Return Code:"
                    )

                    st.write(
                        result["returncode"]
                    )

            else:

                st.error(
                    f"Backend error: {response.status_code}"
                )

                st.write(
                    response.text
                )

        except requests.exceptions.ConnectionError:

            st.error(
                "Could not connect to the backend. "
                "Make sure FastAPI is running on port 8000."
            )

        except Exception as e:

            st.error(
                f"Something went wrong: {e}"
            )


# ============================================================
# PAGE HEADER
# ============================================================

st.subheader(
    "Put Your Code to The Test"
)

st.write(
    "Let The Agent find and fix issues in your code"
)


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.subheader(
    "Upload Your Files"
)


# ============================================================
# ZIP UPLOAD
# ============================================================

uploaded_file = st.sidebar.file_uploader(
    "Upload Project ZIP file",
    type=["zip"]
)


if uploaded_file is not None:

    if st.sidebar.button(
        "Load ZIP",
        use_container_width=True
    ):

        try:

            extract_zip(
                uploaded_file
            )

            st.session_state.project_loaded = True
            st.session_state.selected_file = None

            st.rerun()

        except zipfile.BadZipFile:

            st.sidebar.error(
                "The uploaded file is not a valid ZIP file."
            )

        except Exception as e:

            st.sidebar.error(
                f"Could not load project: {e}"
            )


# ============================================================
# GITHUB REPOSITORY
# ============================================================

st.sidebar.divider()

st.sidebar.subheader(
    "GitHub Repository"
)

repo = st.sidebar.text_input(
    "Repository URL",
    placeholder="https://github.com/user/repository"
)


if st.sidebar.button(
    "Load GitHub Repository",
    use_container_width=True
):

    if not repo.strip():

        st.sidebar.error(
            "Please enter a GitHub repository URL."
        )

    else:

        try:

            with st.spinner(
                "Downloading repository..."
            ):

                download_github_repo(repo)

            st.session_state.project_loaded = True
            st.session_state.selected_file = None

            st.rerun()

        except requests.exceptions.Timeout:

            st.sidebar.error(
                "The GitHub request timed out."
            )

        except requests.exceptions.ConnectionError:

            st.sidebar.error(
                "Could not connect to GitHub."
            )

        except Exception as e:

            st.sidebar.error(
                f"Could not load repository: {e}"
            )


# ============================================================
# FILE EXPLORER
# ============================================================

if st.session_state.get(
    "project_loaded",
    False
):

    st.sidebar.divider()

    st.sidebar.subheader(
        "Project Files"
    )

    show_file_explorer(
        PROJECT_DIR
    )


# ============================================================
# MAIN CONTENT
# ============================================================

selected_file = st.session_state.get(
    "selected_file"
)


# ============================================================
# FILE MODE
# ============================================================

if selected_file:

    # --------------------------------------------------------
    # Back to manual mode
    # --------------------------------------------------------

    if st.button(
        "← Back to Manual Code",
        use_container_width=True
    ):

        st.session_state.selected_file = None

        st.rerun()

    # --------------------------------------------------------
    # Display selected file
    # --------------------------------------------------------

    code = display_selected_file()

    st.divider()

    # --------------------------------------------------------
    # Review selected file
    # --------------------------------------------------------

    if st.button(
        "Review Selected File",
        use_container_width=True
    ):

        review_code(code)


# ============================================================
# MANUAL MODE
# ============================================================

else:

    st.subheader(
        "Manual Code Review"
    )

    code = st.text_area(
        "Paste Your Code Here",
        height=400
    )

    if st.button(
        "Review My Code",
        use_container_width=True
    ):

        review_code(code)