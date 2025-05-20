import pyrebase
import os
import streamlit as st

def initialize_firebase():
    firebaseConfig = {
        "apiKey": os.environ.get("FIREBASE_API_KEY"),
        "authDomain": f"{os.environ.get('FIREBASE_PROJECT_ID')}.firebaseapp.com",
        "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
        "storageBucket": f"{os.environ.get('FIREBASE_PROJECT_ID')}.appspot.com",
        "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
        "appId": os.environ.get("FIREBASE_APP_ID"),
        "databaseURL": ""  # Add if using Firebase Realtime Database
    }
    
    try:
        firebase = pyrebase.initialize_app(firebaseConfig)
        return firebase.auth()
    except Exception as e:
        st.error(f"Firebase initialization error: {str(e)}")
        return None

def login_user(email, password):
    auth = initialize_firebase()
    if auth is None:
        return None
    
    try:
        user = auth.sign_in_with_email_and_password(email, password)
        return user
    except Exception as e:
        st.error(f"Login failed: {str(e)}")
        return None
