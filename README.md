# Arena India – own backend (Node + Postgres) for Render

Files: server.js, package.json, public/index.html

## Deploy on Render
1. Put this folder on GitHub.
2. Create a Postgres database (Render Postgres, or a free one from Neon / Supabase) and copy its connection URL.
3. Render -> New -> Web Service -> pick the repo.
   Build command: npm install      Start command: node server.js
4. Environment variables:
   DATABASE_URL = your Postgres URL
   SECRET       = a long random text (30+ characters)
   ADMIN_PHONE  = admin's 10-digit mobile number
5. Open the site and SIGN UP FIRST with the ADMIN_PHONE number. That account becomes the admin (Admin Panel appears).

Tables are created automatically on first start (2 sample tournaments are added).
