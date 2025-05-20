import streamlit as st
import firebase_admin
from firebase_admin import credentials, firestore
from google.cloud.firestore_v1 import SERVER_TIMESTAMP
import os
import json
import folium
from streamlit_folium import folium_static
from datetime import datetime
import time
from geopy.geocoders import Nominatim
import pandas as pd
import threading

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

db = initialize_firebase_admin()

# Real-time Data Listener
def setup_realtime_listener():
    def on_snapshot(col_snapshot, changes, read_time):
        st.session_state.new_data_available = True
        
    if db:
        col_query = db.collection("disaster_alerts").where("status", "==", "active")
        query_watch = col_query.on_snapshot(on_snapshot)

# Advanced Features
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

    @staticmethod
    def update_resource_allocation(alert_id, resources):
        try:
            db.collection("disaster_alerts").document(alert_id).update({
                "resources_needed": firestore.ArrayUnion(resources),
                "last_updated": SERVER_TIMESTAMP
            })
            return True
        except Exception as e:
            st.error(f"Resource update failed: {str(e)}")
            return False

# Enhanced UI Components
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
            <b>Location:</b> {alert['location']}<br>
            <button onclick="window.parent.postMessage({{'alert_id': '{alert['alert_id']}'}}, '*')">
                View Details
            </button>
            """
            folium.Marker(
                [alert['coordinates']['lat'], alert['coordinates']['lng']],
                popup=folium.Popup(popup_html, max_width=300),
                icon=folium.Icon(color='red' if alert['severity'] == 'high' else 'orange')
            ).add_to(m)
    
    folium_static(m, width=1000, height=600)

def show_alert_details(alert_id):
    alert_ref = db.collection("disaster_alerts").document(alert_id)
    alert = alert_ref.get().to_dict()
    
    if not alert:
        st.error("Alert not found")
        return
    
    with st.expander(f"Alert Details: {alert['type']} in {alert['location']}", expanded=True):
        cols = st.columns([1, 2])
        with cols[0]:
            st.metric("Severity", alert['severity'].upper(), help="Severity level of the disaster")
            st.metric("Status", alert['status'].upper())
            st.write(f"**Reported:** {alert['timestamp'].strftime('%Y-%m-%d %H:%M')}")
        with cols[1]:
            st.write(f"**Description:** {alert['description']}")
            st.write("**Resources Needed:**")
            for resource in alert.get('resources_needed', []):
                st.write(f"- {resource}")
        
        # Resource Allocation Form
        with st.form(key=f"resource_allocation_{alert_id}"):
            resources = st.multiselect(
                "Select resources to allocate",
                options=["Ambulances", "Medical Teams", "Food Supplies", "Rescue Teams", "Shelter Kits"],
                key=f"resources_{alert_id}"
            )
            if st.form_submit_button("Allocate Resources"):
                if DisasterManager.update_resource_allocation(alert_id, resources):
                    st.success("Resources allocated successfully!")
                    st.rerun()

def show_dashboard():
    st.title("🌍 CloudDROS Real-Time Disaster Dashboard")
    
    # Real-time alerts section
    st.header("Active Disaster Alerts")
    if st.button("Refresh Alerts"):
        st.rerun()
    
    show_realtime_map()
    
    # Create new alert section
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
    
    # Resource management section
    st.header("Resource Management")
    doc_ref = db.collection("resources").document("main")
    data = doc_ref.get().to_dict() if doc_ref.get().exists else {}
    
    cols = st.columns(4)
    with cols[0]:
        amb = st.number_input("🚑 Ambulances", value=data.get("ambulances", 0), min_value=0)
    with cols[1]:
        med_teams = st.number_input("🏥 Medical Teams", value=data.get("medical_teams", 0), min_value=0)
    with cols[2]:
        food = st.number_input("🍞 Food Kits", value=data.get("food_kits", 0), min_value=0)
    with cols[3]:
        shelter = st.number_input("⛑️ Shelter Kits", value=data.get("shelter_kits", 0), min_value=0)
    
    if st.button("Update Resources"):
        doc_ref.set({
            "ambulances": amb,
            "medical_teams": med_teams,
            "food_kits": food,
            "shelter_kits": shelter,
            "last_updated": SERVER_TIMESTAMP
        })
        st.success("Resources updated successfully!")
        st.rerun()
    
    # Real-time updates section
    st.header("Live Updates")
    updates_ref = db.collection("updates").order_by("timestamp", direction=firestore.Query.DESCENDING).limit(10)
    updates = [update.to_dict() for update in updates_ref.stream()]
    
    for update in updates:
        with st.container(border=True):
            cols = st.columns([1, 4])
            with cols[0]:
                st.write(f"**{update['type'].upper()}**")
                st.write(update['timestamp'].strftime('%H:%M'))
            with cols[1]:
                st.write(update['message'])
                if update.get('alert_id'):
                    if st.button("View Alert", key=f"view_{update['id']}"):
                        st.session_state.view_alert = update['alert_id']
                        st.rerun()

# Main App Flow
def main():
    if "new_data_available" not in st.session_state:
        st.session_state.new_data_available = False
        setup_realtime_listener()
    
    if st.session_state.new_data_available:
        st.session_state.new_data_available = False
        st.rerun()
    
    if "user" not in st.session_state:
        show_login()
    else:
        if st.sidebar.button("Logout"):
            st.session_state.clear()
            st.rerun()
        
        if "view_alert" in st.session_state:
            show_alert_details(st.session_state.view_alert)
            if st.button("Back to Dashboard"):
                del st.session_state.view_alert
                st.rerun()
        else:
            show_dashboard()

if __name__ == "__main__":
    if db:
        main()
    else:
        st.error("Failed to initialize Firebase. Please check your configuration.")
