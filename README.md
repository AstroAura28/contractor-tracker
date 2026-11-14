[README.md](https://github.com/user-attachments/files/34838621/README.md)
# Contractor Review Tracker

Express + Postgres app serving the dashboard. PDF parsing happens in the browser; parsed reports are saved to Postgres, and the original PDFs can be stored in Google Drive.

## Files

```
server.js            API, accounts, sessions
package.json
render.yaml          Render Blueprint (web service + database)
DRIVE_SETUP.md       Google Drive setup guide
public/
  index.html         dashboard
  login.html         sign-in and password change
  admin.html         manage access (admins only)
```

## Access levels

- **Admin**: sees the dashboard, can upload and remove reports, and can manage access.
- **Contractor**: can only view the dashboard.

The server enforces this on every request, not just in the page. Admins add people in **Manage access** (email, access level, temporary password). People sign in with their email and the temporary password, and must set their own password the first time.

## First admin

On first start (no users yet) the server creates one admin from two environment variables:

- `ADMIN_EMAIL`: your email
- `APP_PASSWORD`: its password (use the one you already have in Render)

After that, add everyone else from the Manage access page. If you ever lose the admin password: set `RESET_ADMIN=true` in Render, redeploy, sign in, then **remove** `RESET_ADMIN` again (while it is set, every restart resets that admin's password to `APP_PASSWORD`).

## Environment variables

| Name | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres connection string (required) |
| `ADMIN_EMAIL`, `APP_PASSWORD` | Create the first admin (needed only while there are no users) |
| `RESET_ADMIN` | `true` to reset that admin's password on startup |
| `GOOGLE_DRIVE_FOLDER_ID` + credentials | Store PDFs in Drive, see `DRIVE_SETUP.md` |
| `PGSSL` | `true` only when using Render's external database URL |
| `PORT` | Set by Render |

## Run locally

```
npm install
DATABASE_URL=postgres://user:pass@localhost:5432/tracker ADMIN_EMAIL=you@company.com APP_PASSWORD=change-me-now npm start
```
