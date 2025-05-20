import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1 import SERVER_TIMESTAMP
import os
import folium
from streamlit_folium import folium_static
from geopy.geocoders import Nominatim
import pyrebase4 as pyrebase  # Changed to pyrebase4

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
            
            # Validate required fields
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
            return None
    return firestore.client()

# Initialize Firebase Auth with better error handling
def initialize_firebase_auth():
    try:
        firebaseConfig = {
            "apiKey": os.environ.get("FIREBASE_API_KEY"),
            "authDomain": f"{os.environ.get('FIREBASE_PROJECT_ID')}.firebaseapp.com",
            "projectId": os.environ.get("FIREBASE_PROJECT_ID"),
            "storageBucket": f"{os.environ.get('FIREBASE_PROJECT_ID')}.appspot.com",
            "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
            "appId": os.environ.get("FIREBASE_APP_ID"),
            "databaseURL": ""  # Add if using Realtime Database
        }
        
        # Verify required auth fields
        required_auth_fields = ["apiKey", "authDomain", "projectId"]
        for field in required_auth_fields:
            if not firebaseConfig.get(field):
                st.error(f"Missing required Firebase auth config: {field}")
                return None
                
        return pyrebase.initialize_app(firebaseConfig).auth()
    except Exception as e:
        st.error(f"Firebase Auth initialization failed: {str(e)}")
        return None

# Initialize services with validation
db = initialize_firebase_admin()
auth = initialize_firebase_auth()

# Enhanced Login Functionality
def show_login():
    st.sidebar.title("Admin Login")
    email = st.sidebar.text_input("Email")
    password = st.sidebar.text_input("Password", type="password")
    
    if st.sidebar.button("Login"):
        if not auth:
            st.error("Authentication service not available")
            return
            
        try:
            user = auth.sign_in_with_email_and_password(email, password)
            st.session_state["user"] = user
            st.session_state["user_email"] = email
            st.session_state["user_id"] = user['localId']
            st.success("Logged in successfully!")
            st.rerun()
        except Exception as e:
            error_msg = str(e)
            if "INVALID_EMAIL" in error_msg:
                st.error("Invalid email address")
            elif "INVALID_PASSWORD" in error_msg:
                st.error("Incorrect password")
            elif "TOO_MANY_ATTEMPTS" in error_msg:
                st.error("Account temporarily disabled - too many attempts")
            else:
                st.error(f"Login failed: {error_msg}")

# Disaster Manager Class with improved error handling
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

# Enhanced Dashboard Functions
def show_realtime_map():
    try:
        alerts = DisasterManager.get_live_alerts()
        if not alerts:
            st.warning("No active disaster alerts")
            return
        
        # Find center point for map
        valid_coords = [alert for alert in alerts if alert.get('coordinates')]
        if valid_coords:
            center = [valid_coords[0]['coordinates']['lat'], valid_coords[0]['coordinates']['lng']]
        else:
            center = [20, 0]  # Default center if no coordinates
            
        m = folium.Map(location=center, zoom_start=5)
        
        for alert in valid_coords:
            popup_html = f"""
            <b>Type:</b> {alert['type']}<br>
            <b>Severity:</b> {alert['severity']}<br>
            <b>Location:</b> {alert['location']}<br>
            <b>Reported by:</b> {alert.get('created_by', 'unknown')}
            """
            folium.Marker(
                [alert['coordinates']['lat'], alert['coordinates']['lng']],
                popup=folium.Popup(popup_html, max_width=300),
                icon=folium.Icon(
                    color='red' if alert['severity'] == 'high' else 
                    'orange' if alert['severity'] == 'medium' else 'green'
                )
            ).add_to(m)
        
        folium_static(m, width=1000, height=600)
    except Exception as e:
        st.error(f"Map rendering failed: {str(e)}")

def show_dashboard():
    st.title("🌍 CloudDROS Real-Time Disaster Dashboard")
    st.write(f"Welcome, {st.session_state.get('user_email', 'Administrator')}")
    
    tab1, tab2, tab3 = st.tabs(["Live Alerts", "Create Alert", "Resource Management"])
    
    with tab1:
        st.header("Active Disaster Alerts")
        if st.button("Refresh Alerts", key="refresh_alerts"):
            st.rerun()
        
        show_realtime_map()
        
        alerts = DisasterManager.get_live_alerts()
        if alerts:
            st.subheader("Alert Details")
            for alert in alerts[:3]:  # Show first 3 alerts
                with st.expander(f"{alert['type']} in {alert['location']} ({alert['severity']})"):
                    st.write(f"**Description:** {alert['description']}")
                    st.write(f"**Reported at:** {alert.get('created_at', 'Unknown time')}")
                    if alert.get('resources_needed'):
                        st.write("**Resources Needed:**")
                        for resource in alert['resources_needed']:
                            st.write(f"- {resource}")

    with tab2:
        st.header("Create New Alert")
        with st.form(key="new_alert_form"):
            alert_type = st.selectbox(
                "Disaster Type",
                options=["Earthquake", "Flood", "Wildfire", "Hurricane", "Tornado", "Other"],
                key="alert_type"
            )
            location = st.text_input("Location", key="alert_location")
            severity = st.select_slider(
                "Severity Level",
                options=["low", "medium", "high"],
                key="alert_severity"
            )
            description = st.text_area("Description", key="alert_description")
            
            if st.form_submit_button("Create Alert"):
                if alert_type and location and description:
                    if DisasterManager.create_alert(alert_type, location, severity, description):
                        st.success("Alert created successfully!")
                        st.rerun()
                else:
                    st.error("Please fill all required fields")

    with tab3:
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

# Main App Flow with session management
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
