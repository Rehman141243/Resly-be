# FitConnect Backend (Node + Express + TypeScript + Supabase)

Runtime dependencies: `express`, `@supabase/supabase-js`, `helmet`, `express-rate-limit`. Everything else is Node built-ins.

## Setup
1. Supabase -> SQL Editor -> run `supabase/schema.sql`.
2. `cp .env.example .env`, then fill in the Supabase URL + **service role** key.
3. Generate the three secrets (run 3 times):
   `node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"`
   -> `JWT_SECRET`, `PEPPER`, `ENCRYPTION_KEY`
4. `npm install && npm run dev`

In dev, reset codes are printed in the server console. In production set `RESEND_API_KEY` and `EMAIL_FROM`.
**Never change `PEPPER` / `ENCRYPTION_KEY` after users exist** (it invalidates sessions/codes and makes names undecryptable).

## API (all under `/api/auth`)
| Method | Path | Auth | Body |
|---|---|---|---|
| POST | /signup | - | name, email, password |
| POST | /login | - | email, password, remember? |
| POST | /refresh | - | refreshToken |
| POST | /logout | Bearer | - |
| POST | /logout-all | Bearer | - |
| POST | /forgot-password | - | email |
| POST | /reset-password | - | email, code, password |
| GET | /me | Bearer | - |
| POST | /change-password | Bearer | currentPassword, newPassword |
| GET | /sessions | Bearer | - |
| DELETE | /sessions/:id | Bearer | - |

Success (signup/login): `{ user: {id,name,email}, tokens: {accessToken, expiresIn, refreshToken, refreshExpiresAt} }`
Errors: `{ error: { code, message, fields? } }` where `fields` keys match your form inputs (name, email, password, code).
