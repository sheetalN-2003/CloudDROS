import pyrebase
import os

firebaseConfig = {
  "apiKey": os.environ.get("FIREBASE_API_KEY"),
  "authDomain": os.environ.get("FIREBASE_PROJECT_ID") + ".firebaseapp.com",
  "projectId": os.environ.get("cloud-dros"),
  "storageBucket": os.environ.get("FIREBASE_PROJECT_ID") + ".appspot.com",
  "messagingSenderId": os.environ.get("FIREBASE_MESSAGING_SENDER_ID"),
  "appId": os.environ.get("FIREBASE_APP_ID")
}

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()

def login_user(email, password):
    try:
        user = auth.sign_in_with_email_and_password(email, password)
        return user
    except:
        return None
