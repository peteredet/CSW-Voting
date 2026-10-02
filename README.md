# CSW 2026 "Extra Mile" vote

Static site (GitHub → Netlify) + Supabase (Postgres, Auth, Realtime).

- `index.html`: staff register (name + office email + password), confirm email, sign in, vote.
- `admin.html`: two roles, decided by the account that signs in.
  - **viewer**: live leaderboard (colleague votes only), turnout, open/close voting.
  - **owner**: everything above + self-votes, who-voted-for-whom feed, CSV export, reset.
  The database enforces this; the viewer's account cannot fetch ballot data even outside the page.
- `schema.sql`: tables, row-level security, all server-side rules.
- `staff_import.csv`: the 86 staff. **Fill the `email` column before importing.**

## Setup

1. **Supabase project.** Create a new project (free tier slots may be full on your existing account).
2. **SQL Editor:** run `schema.sql`.
3. **Fill emails** in `staff_import.csv` (one unique email per person; staff with no office email get a personal one).
   Table Editor → `staff` → Insert → Import data from CSV.
4. **Admins** (SQL Editor). Both people must also register on the voting page with these emails:
   `insert into public.admins (email, role) values ('your.office@email', 'owner');`
   `insert into public.admins (email, role) values ('second.admin@email', 'viewer');`
   Don't add the second admin to the Supabase project itself: the dashboard shows every table.
5. **Auth → Providers → Email:** keep "Confirm email" ON. This is the security. Without it, anyone can register as anyone.
6. **Auth → SMTP:** set up custom SMTP (Resend, Brevo, Zoho Mail, your mail server). Supabase's built-in sender is rate-limited and meant for testing only; 86 confirmation emails will not get through it.
7. **Auth → URL Configuration:** Site URL = your Netlify URL. Add `https://YOUR-SITE.netlify.app/**` to Redirect URLs.
8. Put your project URL and anon key in `config.js`.
9. Push to GitHub, then Netlify → Add new site → Import from GitHub. No build command; publish directory `.`.
10. Register on `/`, confirm your email, then use the **Admin** link at the bottom of the page. Test with 2–3 people, press **Reset all votes**, then flip **Voting open** on launch day.

## Rules enforced on the server (not just the page)
- Only email-confirmed accounts whose email matches a staff record can vote.
- One ballot per staff member (unique constraint).
- Exactly three votes, three different people, self at most once.
- Voting only while the admin toggle is on.
