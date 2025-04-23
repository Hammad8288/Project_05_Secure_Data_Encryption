import streamlit as st
import time
from hashlib import pbkdf2_hmac
import json
from data_handler import save_data

SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60

def hash_password(password):
    return pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

def register_user(stored_data):
    st.subheader("✍ Register New User 🧑")
    with st.form("register_form"):
        username = st.text_input("Choose Username")
        password = st.text_input("Choose Password", type="password")
        confirm = st.text_input("Confirm Password", type="password")
        submitted = st.form_submit_button("Register")

        if submitted:
            if not username or not password:
                st.error("⚠️ Please fill in all fields!")
            elif password != confirm:
                st.error("⚠️ Passwords do not match!")
            elif username in stored_data:
                st.error("⚠️ Username already exists!")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "encrypted_data": []
                }
                save_data(stored_data)
                st.success("✅ User registered successfully!")

def login_user(stored_data):
    st.subheader("🔑 User Login")

    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"🕰️ Too many failed attempts! Please wait {remaining} seconds.")
        return

    with st.form("login_form"):
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"✅ Welcome {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Invalid credentials! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("🔴 Too many failed attempts! You are locked out for 60 seconds.")
                    st.stop()
