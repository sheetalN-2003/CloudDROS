import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1 import SERVER_TIMESTAMP
import os
import folium
from streamlit_folium import folium_static
from geopy.geocoders import Nominatim
import pyrebase

# Initialize Firebase Admin
def initialize_firebase_admin():
    if not firebase_admin._apps:
        try:
            private_key = os.environ.get("FIREBASE_PRIVATE_KEY")
            
            if not private_key:
                st.error("Firebase private key not found")
                return None
                
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
            
            cred = credentials.Certificate(cred_dict)
            firebase_admin.initialize_app(cred)
            return firestore.client()
        except Exception as e:
            st.error(f"Firebase Admin initialization failed: {str(e)}")
            return None
    return firestore.client()

# Initialize Firebase Auth
def initialize_firebase_auth():
    firebaseConfig = {
        "apiKey": os.environ.get("FIREBASE_API_KEY"),
        "authDomain": f"{os.environ.get('FIREBASE_PROJECT_ID')}.firebaseapp.com",
        "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
        "storageBucket": f"{os.environ.get('FIREBASE_PROJECT_ID')}.appspot.com",
        "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
        "appId": os.environ.get("FIREBASE_APP_ID")
    }
    return pyrebase.initialize_app(firebaseConfig).auth()

# Initialize services
db = initialize_firebase_admin()
auth = initialize_firebase_auth()

# Login Functionality
def show_login():
    st.sidebar.title("Admin Login")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")
    
    if st.sidebar.button("Login"):
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            st.session_state["user"] = user
            st.session_state["user_email"] = email
            st.success("Logged in successfully!")
            st.rerun()
        except Exception as e:
            st.error(f"Login failed: {str(e)}")

# Disaster Manager Class (same as before)
class DisasterManager:
    @staticmethod
    def create_alert(alert_type, location, severity, description):
        try:
            geolocator = Nominatim(user_agent="clouddros")
            location_data = geolocator.geocode(location)
            
            alert_ref = db.collection("disaster_alerts").document()
            alert_ref.set({
                "alert_id": alert_ref.id,
                "type": alert_type,
                "location": location,
                "coordinates": {
                    "lat": location_data.latitude if location_data else None,
                    "lng": location_data.longitude if location_data else None
                },
                "severity": severity,
                "description": description,
                "status": "active",
                "timestamp": SERVER_TIMESTAMP,
                "resources_needed": [],
                "affected_people": 0,
                "responders": []
            })
            return True
        except Exception as e:
            st.error(f"Alert creation failed: {str(e)}")
            return False

    @staticmethod
    def get_live_alerts():
        try:
            alerts = db.collection("disaster_alerts")\
                      .where("status", "==", "active")\
                      .order_by("timestamp", direction=firestore.Query.DESCENDING)\
                      .stream()
            return [alert.to_dict() for alert in alerts]
        except Exception as e:
            st.error(f"Error fetching alerts: {str(e)}")
            return []

# Dashboard Functions (same as before)
def show_realtime_map():
    alerts = DisasterManager.get_live_alerts()
    if not alerts:
        st.warning("No active disaster alerts")
        return
    
    center = [alerts[0]['coordinates']['lat'], alerts[0]['coordinates']['lng']] if alerts[0]['coordinates']['lat'] else [20, 0]
    m = folium.Map(location=center, zoom_start=5)
    
    for alert in alerts:
        if alert['coordinates']['lat']:
            popup_html = f"""
            <b>Type:</b> {alert['type']}<br>
            <b>Severity:</b> {alert['severity']}<br>
            <b>Location:</b> {alert['location']}
            """
            folium.Marker(
                [alert['coordinates']['lat'], alert['coordinates']['lng']],
                popup=folium.Popup(popup_html, max_width=300),
                icon=folium.Icon(color='red' if alert['severity'] == 'high' else 'orange')
            ).add_to(m)
    
    folium_static(m, width=1000, height=600)

def show_dashboard():
    st.title("🌍 CloudDROS Real-Time Disaster Dashboard")
    
    st.header("Active Disaster Alerts")
    if st.button("Refresh Alerts"):
        st.rerun()
    
    show_realtime_map()
    
    with st.expander("🚨 Create New Disaster Alert", expanded=False):
        with st.form(key="new_alert_form"):
            alert_type = st.selectbox(
                "Disaster Type",
                options=["Earthquake", "Flood", "Wildfire", "Hurricane", "Tornado", "Other"]
            )
            location = st.text_input("Location")
            severity = st.select_slider(
                "Severity Level",
                options=["low", "medium", "high"]
            )
            description = st.text_area("Description")
            
            if st.form_submit_button("Create Alert"):
                if DisasterManager.create_alert(alert_type, location, severity, description):
                    st.success("Alert created successfully!")
                    st.rerun()

# Main App Flow
def main():
    if "user" not in st.session_state:
        show_login()
    else:
        if st.sidebar.button("Logout"):
            st.session_state.clear()
            st.rerun()
        
        show_dashboard()

if __name__ == "__main__":
    if db and auth:
        main()
    else:
        st.error("Failed to initialize Firebase services. Please check your configuration.")
