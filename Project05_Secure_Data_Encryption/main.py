
import streamlit as st
from auth import register_user, login_user
from crypto_utils import encrypt_data_ui, decrypt_data_ui
from data_handler import load_data

# Session setup
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

st.title("🛡️ Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
choice = st.sidebar.selectbox("Navigation", menu)

stored_data = load_data()

if choice == "Home":
    st.subheader("✨ Welcome to the 🔐 Secure Data Encryption System!")
    st.markdown("""
    This system lets you:
    - 🔑 Register/Login securely
    - 💾 Store encrypted data
    - 🔍 Retrieve & decrypt your data
    """)

elif choice == "Register":
    register_user(stored_data)

elif choice == "Login":
    login_user(stored_data)

elif choice == "Store Data":
    encrypt_data_ui(stored_data)

elif choice == "Retrieve Data":
    decrypt_data_ui(stored_data)
