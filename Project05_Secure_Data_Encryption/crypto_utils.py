# crypto_utils.py
import streamlit as st
from base64 import urlsafe_b64encode
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac
from data_handler import save_data

SALT = b"secure_salt_value"

def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

def encrypt_text(text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.encrypt(text.encode()).decode('utf-8')
    except Exception as e:
        st.error(f"Encryption error: {str(e)}")
        return None

def decrypt_text(encrypted_text, passkey):
    try:
        key = generate_key(passkey)
        cipher = Fernet(key)
        return cipher.decrypt(encrypted_text.encode()).decode('utf-8')
    except Exception as e:
        st.error(f"Decryption error: {str(e)}")
        return None

def encrypt_data_ui(stored_data):
    if not st.session_state.authenticated_user:
        st.warning("💾 Please Login First.")
        return

    st.subheader("🛠️ Store Encrypted Data")
    data = st.text_area("Enter data to encrypt and store:")
    passkey = st.text_input("Encryption key (passphrase)", type="password")

    if st.button("Encrypt And Save"):
        if data and passkey:
            encrypted = encrypt_text(data, passkey)
            if encrypted:
                user = st.session_state.authenticated_user
                stored_data[user]["encrypted_data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and stored successfully!")
        else:
            st.error("⚠️ Please fill in all fields!")

def decrypt_data_ui(stored_data):
    if not st.session_state.authenticated_user:
        st.warning("💾 Please Login First.")
        return

    st.subheader("🔍 Retrieve Encrypted Data")
    user_data = stored_data.get(st.session_state.authenticated_user, {})

    if not user_data.get("encrypted_data"):
        st.info("No Data Found!")
        return

    for i, encrypted_item in enumerate(user_data["encrypted_data"]):
        st.code(f"Entry {i+1}: {encrypted_item}", language="text")

    st.subheader("Decrypt Data")
    encrypted_input = st.text_area("Enter Encrypted Text:")
    passkey = st.text_input("Enter Decryption key", type="password")

    if st.button("Decrypt"):
        if not encrypted_input or not passkey:
            st.error("⚠️ Please enter both encrypted text and passkey!")
        else:
            result = decrypt_text(encrypted_input, passkey)
            if result:
                st.success("✅ Decryption successful!")
                st.text_area("Decrypted Data:", value=result, height=100)
            else:
                st.error("❌ Invalid passkey or corrupted data!")
