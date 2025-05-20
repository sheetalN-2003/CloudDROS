import streamlit as st
from streamlit_firebase import login_user
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

# Initialize Firebase Admin
def initialize_firebase_admin():
    if not firebase_admin._apps:
        try:
            # For Streamlit Cloud secrets
            cred_dict = {
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
            }
            
            # Validate credentials
            if not all(cred_dict.values()):
                st.error("Missing Firebase Admin credentials in environment variables")
                return None
                
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            return firestore.client()
        except Exception as e:
            st.error(f"Firebase Admin initialization failed: {str(e)}")
            return None
    return firestore.client()

# Initialize Firestore
db = initialize_firebase_admin()

# Authentication UI
def show_login():
    st.sidebar.title("Admin Login")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")
    
    if st.sidebar.button("Login"):
        user = login_user(email, password)
        if user:
            st.session_state["user"] = user
            st.session_state["user_email"] = email
            st.success("Logged in successfully!")
            st.experimental_rerun()
        else:
            st.error("Login failed. Check your credentials.")

# Main Dashboard
def show_dashboard():
    st.title("CloudDROS Admin Dashboard")
    st.write(f"Logged in as: {st.session_state.get('user_email', '')}")
    
    try:
        doc_ref = db.collection("resources").document("main")
        doc = doc_ref.get()
        
        if doc.exists:
            data = doc.to_dict()
        else:
            data = {"ambulances": 0, "food_kits": 0}
            doc_ref.set(data)
            
        col1, col2 = st.columns(2)
        with col1:
            amb = st.number_input("Available Ambulances", value=data.get("ambulances", 0), min_value=0)
        with col2:
            kits = st.number_input("Available Food Kits", value=data.get("food_kits", 0), min_value=0)
            
        if st.button("Update Resources"):
            doc_ref.update({
                "ambulances": amb,
                "food_kits": kits
            })
            st.success("Resources updated successfully!")
            
    except Exception as e:
        st.error(f"Database error: {str(e)}")

# Main App Flow
def main():
    if "user" not in st.session_state:
        show_login()
    else:
        if st.sidebar.button("Logout"):
            st.session_state.clear()
            st.experimental_rerun()
        show_dashboard()

if __name__ == "__main__":
    if db:  # Only run if Firestore initialized successfully
        main()
