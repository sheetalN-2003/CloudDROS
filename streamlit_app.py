import streamlit as st
from streamlit_firebase import login_user
from firebase_admin import firestore, credentials, initialize_app
import firebase_admin
import os

# Firebase Admin Initialization
if not firebase_admin._apps:
    cred = credentials.Certificate({
        "type": os.environ.get("FIREBASE_TYPE"),
        "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
        "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID"),
        "private_key": os.environ.get("FIREBASE_PRIVATE_KEY").replace("\\n", "\n"),
        "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
        "client_id": os.environ.get("FIREBASE_CLIENT_ID"),
        "auth_uri": os.environ.get("FIREBASE_AUTH_URI"),
        "token_uri": os.environ.get("FIREBASE_TOKEN_URI"),
        "auth_provider_x509_cert_url": os.environ.get("FIREBASE_AUTH_PROVIDER_CERT_URL"),
        "client_x509_cert_url": os.environ.get("FIREBASE_CLIENT_CERT_URL")
    })
    initialize_app(cred)

db = firestore.client()

# UI for Login
st.sidebar.title("Admin Login")
email = st.sidebar.text_input("Email")
password = st.sidebar.text_input("Password", type="password")

user = None
if st.sidebar.button("Login"):
    user = login_user(email, password)
    if user:
        st.session_state["user"] = user
        st.success("Logged in successfully!")
    else:
        st.error("Login failed")

# Admin Dashboard
if "user" in st.session_state:
    st.title("CloudDROS Admin Dashboard")
    doc_ref = db.collection("resources").document("main")
    data = doc_ref.get().to_dict() if doc_ref.get().exists else {}

    amb = st.number_input("Available Ambulances", value=data.get("ambulances", 0))
    kits = st.number_input("Available Food Kits", value=data.get("food_kits", 0))

    if st.button("Update Resources"):
        doc_ref.set({"ambulances": amb, "food_kits": kits})
        st.success("Resources Updated Successfully!")
