import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore, auth as admin_auth
from google.cloud.firestore_v1 import SERVER_TIMESTAMP
import os
import folium
from streamlit_folium import folium_static
from geopy.geocoders import Nominatim
from datetime import datetime
import requests
import json
from jose import jwt

# Initialize Firebase Admin
def initialize_firebase():
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
            st.error(f"Firebase initialization failed: {str(e)}")
            return None
    return firestore.client()

# Custom Firebase Auth Implementation
def sign_in_with_email_password(email, password):
    api_key = os.environ.get("FIREBASE_API_KEY")
    if not api_key:
        st.error("Firebase API key not configured")
        return None
        
    url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={api_key}"
    
    try:
        response = requests.post(url, json={
            "email": email,
            "password": password,
            "returnSecureToken": True
        })
        
        if response.status_code == 200:
            return response.json()
        else:
            error_msg = response.json().get("error", {}).get("message", "Unknown error")
            st.error(f"Login failed: {error_msg}")
            return None
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        return None

# Initialize services
db = initialize_firebase()

# Login Functionality
def show_login():
    st.sidebar.title("Admin Login")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")
    
    if st.sidebar.button("Login"):
        user = sign_in_with_email_password(email, password)
        if user:
            st.session_state["user"] = user
            st.session_state["user_email"] = email
            st.success("Logged in successfully!")
            st.rerun()

# Disaster Manager Class
class DisasterManager:
    @staticmethod
    def create_alert(alert_type, location, severity, description):
        try:
            geolocator = Nominatim(user_agent="clouddros")
            location_data = geolocator.geocode(location)
            
            alert_ref = db.collection("disaster_alerts").document()
            alert_data = {
                "alert_id": alert_ref.id,
                "type": alert_type,
                "location": location,
                "severity": severity,
                "description": description,
                "status": "active",
                "timestamp": SERVER_TIMESTAMP,
                "resources_needed": [],
                "affected_people": 0,
                "created_by": st.session_state.get("user_email", "unknown"),
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            
            if location_data:
                alert_data["coordinates"] = {
                    "lat": location_data.latitude,
                    "lng": location_data.longitude
                }
            
            alert_ref.set(alert_data)
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

# Dashboard Functions
def show_realtime_map():
    alerts = DisasterManager.get_live_alerts()
    if not alerts:
        st.warning("No active disaster alerts")
        return
    
    valid_coords = [alert for alert in alerts if alert.get('coordinates')]
    center = [valid_coords[0]['coordinates']['lat'], valid_coords[0]['coordinates']['lng']] if valid_coords else [20, 0]
    
    m = folium.Map(location=center, zoom_start=5)
    
    for alert in valid_coords:
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
    
    tab1, tab2 = st.tabs(["Live Alerts", "Resource Management"])
    
    with tab1:
        st.header("Active Disaster Alerts")
        if st.button("Refresh Alerts"):
            st.rerun()
        
        show_realtime_map()
        
        alerts = DisasterManager.get_live_alerts()
        if alerts:
            st.subheader("Alert Details")
            for alert in alerts[:3]:
                with st.expander(f"{alert['type']} in {alert['location']} ({alert['severity']})"):
                    st.write(f"**Description:** {alert['description']}")
                    st.write(f"**Reported at:** {alert.get('created_at', 'Unknown time')}")
                    if alert.get('resources_needed'):
                        st.write("**Resources Needed:**")
                        for resource in alert['resources_needed']:
                            st.write(f"- {resource}")

        with st.expander("Create New Alert", expanded=False):
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
                    if alert_type and location and description:
                        if DisasterManager.create_alert(alert_type, location, severity, description):
                            st.success("Alert created successfully!")
                            st.rerun()
                    else:
                        st.error("Please fill all required fields")

    with tab2:
        st.header("Resource Management")
        if db:
            doc_ref = db.collection("resources").document("main")
            data = doc_ref.get().to_dict() if doc_ref.get().exists else {}
            
            cols = st.columns(3)
            with cols[0]:
                amb = st.number_input("🚑 Ambulances", value=data.get("ambulances", 0), min_value=0)
            with cols[1]:
                med_teams = st.number_input("🏥 Medical Teams", value=data.get("medical_teams", 0), min_value=0)
            with cols[2]:
                food = st.number_input("🍞 Food Kits", value=data.get("food_kits", 0), min_value=0)
            
            if st.button("Update Resources"):
                doc_ref.set({
                    "ambulances": amb,
                    "medical_teams": med_teams,
                    "food_kits": food,
                    "last_updated": SERVER_TIMESTAMP
                })
                st.success("Resources updated successfully!")
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
    if db:
        main()
    else:
        st.error("Failed to initialize Firebase. Please check your configuration.")
