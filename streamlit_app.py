import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
import os
import json

def initialize_firebase_admin():
    if not firebase_admin._apps:
        try:
            # Get private key from environment
            private_key = os.environ.get("FIREBASE_PRIVATE_KEY")
            
            # Debugging: Check if private key exists
            if st.secrets.get("DEBUG_MODE", False):
                st.write(f"Private key exists: {private_key is not None}")
            
            if not private_key:
                st.error("Firebase private key not found in environment variables")
                return None
                
            # Ensure proper newline formatting
            private_key = private_key.replace("\\n", "\n")
            
            cred_dict = {
                "type": os.environ.get("FIREBASE_TYPE", "service_account"),
                "project_id": os.environ.get("FIREBASE_PROJECT_ID"),
                "private_key_id": os.environ.get("FIREBASE_PRIVATE_KEY_ID"),
                "private_key": private_key,
                "client_email": os.environ.get("FIREBASE_CLIENT_EMAIL"),
                "client_id": os.environ.get("FIREBASE_CLIENT_ID"),
                "auth_uri": os.environ.get("FIREBASE_AUTH_URI", "https://accounts.google.com/o/oauth2/auth"),
                "token_uri": os.environ.get("FIREBASE_TOKEN_URI", "https://oauth2.googleapis.com/token"),
                "auth_provider_x509_cert_url": os.environ.get("FIREBASE_AUTH_PROVIDER_CERT_URL", "https://www.googleapis.com/oauth2/v1/certs"),
                "client_x509_cert_url": os.environ.get("FIREBASE_CLIENT_CERT_URL")
            }
            
            # Validate all required fields
            required_fields = ["project_id", "private_key", "client_email"]
            for field in required_fields:
                if not cred_dict.get(field):
                    st.error(f"Missing required Firebase credential: {field}")
                    return None
            
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            return firestore.client()
            
        except Exception as e:
            st.error(f"Firebase Admin initialization failed: {str(e)}")
            st.error("Please check your Firebase credentials configuration")
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
            st.rerun()  # Changed from experimental_rerun()
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
            st.rerun()  # Changed from experimental_rerun()
        show_dashboard()

if __name__ == "__main__":
    if db:  # Only run if Firestore initialized successfully
        main()
    else:
        st.error("Failed to initialize Firebase. Please check your configuration.")
