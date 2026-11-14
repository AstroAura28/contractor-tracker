[DRIVE_SETUP.md](https://github.com/user-attachments/files/34838651/DRIVE_SETUP.md)
# Storing PDFs in Google Drive

Every time an admin saves a report, the original PDF is uploaded to one Drive folder. Saving a report again for the same date and time range replaces that same file. Removing a report from the dashboard does **not** delete its PDF from Drive.

Pick the option that matches where your folder lives. Then add the variables in Render (service > Environment) and redeploy. In the tracker, open **Manage access** and press **Test connection** on the Google Drive card.

Every option needs `GOOGLE_DRIVE_FOLDER_ID`: open the folder in Drive, and copy the last part of its address, `https://drive.google.com/drive/folders/<THIS-PART>`.

## Option A: Google Workspace with a Shared Drive (simplest, no expiring tokens)

A service account (a robot Google account) cannot store files in a normal "My Drive" folder, only in a **Shared Drive**.

1. In Google Cloud Console (console.cloud.google.com), create a project, then **APIs & Services > Library > Google Drive API > Enable**.
2. **IAM & Admin > Service Accounts > Create service account**. Open it, then **Keys > Add key > Create new key > JSON**. A file downloads.
3. In Drive, open your Shared Drive (or a folder inside it) and **Share** it with the service account's email (it looks like `name@project.iam.gserviceaccount.com`) as **Content manager**.
4. In Render add:
   - `GOOGLE_DRIVE_FOLDER_ID`: the folder ID (a folder inside the Shared Drive).
   - `GOOGLE_SERVICE_ACCOUNT_JSON`: paste the **entire contents** of the downloaded JSON file.

## Option B: a personal Google account, or a normal My Drive folder

Files are stored as you, using your own storage. This needs a one-time "refresh token".

1. In Google Cloud Console, create a project and enable the **Google Drive API** (as above).
2. **APIs & Services > OAuth consent screen**: choose **External** (or **Internal** if you have Workspace), fill in the name and your email, and add yourself as a test user. Then set the publishing status to **In production**. If you leave it on "Testing", the token stops working after 7 days.
3. **Credentials > Create credentials > OAuth client ID > Web application**. Under *Authorized redirect URIs* add `https://developers.google.com/oauthplayground`. Copy the **client ID** and **client secret**.
4. Open https://developers.google.com/oauthplayground, click the gear icon, tick **Use your own OAuth credentials**, and paste the client ID and secret.
5. In step 1 of the playground, type the scope `https://www.googleapis.com/auth/drive`, click **Authorize APIs**, sign in with the Google account that owns the folder, and accept (Google warns the app is unverified: continue).
6. In step 2, click **Exchange authorization code for tokens** and copy the **Refresh token**.
7. In Render add:
   - `GOOGLE_DRIVE_FOLDER_ID`
   - `GOOGLE_CLIENT_ID`
   - `GOOGLE_CLIENT_SECRET`
   - `GOOGLE_REFRESH_TOKEN`

## If "Test connection" fails

- *File not found*: the folder ID is wrong, or the folder is not shared with the service account (Option A).
- *Service Accounts do not have storage quota*: the folder is in a normal My Drive. Use a Shared Drive (Option A) or switch to Option B.
- *invalid_grant*: the refresh token expired or was revoked. Repeat steps 4 to 6 (and check the app is "In production").
