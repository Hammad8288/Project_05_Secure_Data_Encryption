
import streamlit as st
from auth import register_user, login_user
from data_handler import load_data
from crypto_utils import encrypt_data_ui, decrypt_data_ui

st.set_page_config(page_title="🔐 Secure Data System", layout="centered")
st.title("🔐 Secure Data Encryption System")

if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

stored_data = load_data()

menu = ["Login", "Register", "Encrypt", "Decrypt"]
choice = st.sidebar.radio("Navigation", menu)

if choice == "Register":
    register_user(stored_data)
elif choice == "Login":
    login_user(stored_data)
elif choice == "Encrypt":
    encrypt_data_ui(stored_data)
elif choice == "Decrypt":
    decrypt_data_ui(stored_data)
