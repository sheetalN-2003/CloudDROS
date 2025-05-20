import pyrebase

firebaseConfig = {
  "apiKey": "YOUR_API_KEY",
  "authDomain": "YOUR_PROJECT.firebaseapp.com",
  "databaseURL": "",
  "projectId": "YOUR_PROJECT",
  "storageBucket": "YOUR_PROJECT.appspot.com",
  "messagingSenderId": "...",
  "appId": "..."
}

firebase = pyrebase.initialize_app(firebaseConfig)
auth = firebase.auth()

def login_user(email, password):
    try:
        user = auth.sign_in_with_email_and_password(email, password)
        return user
    except:
        return None
