from dropbox.oauth import DropboxOAuth2FlowNoRedirect
import sys

APP_KEY = "YOUR_APP_KEY"
APP_SECRET = "YOUR_APP_SECRET"

auth_flow = DropboxOAuth2FlowNoRedirect(
    APP_KEY,
    APP_SECRET,
    token_access_type='offline'
)

authorize_url = auth_flow.start()

print("1️⃣ Go to this URL and allow access:")
print(authorize_url)

print("\n2️⃣ After allowing access, copy the authorization code here:")
auth_code = input("Enter the authorization code: ").strip()

try:
    oauth_result = auth_flow.finish(auth_code)
except Exception as e:
    print("Error:", e)
    sys.exit(1)

print("\n✅ ACCESS TOKEN  :", oauth_result.access_token)
print("✅ REFRESH TOKEN :", oauth_result.refresh_token)
print("✅ TOKEN TYPE    :", oauth_result.token_type)

print("\n✅ Save these in config.py!")
