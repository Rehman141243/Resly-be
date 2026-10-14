-- Run this in Supabase -> SQL Editor.

create table if not exists public.users (
  id               uuid primary key default gen_random_uuid(),
  email            text not null unique check (email = lower(email)),
  name_enc         text not null,               -- AES-256-GCM encrypted
  password_hash    text not null,               -- scrypt, never plaintext
  failed_attempts  int  not null default 0,
  locked_until     timestamptz,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now()
);

create table if not exists public.sessions (
  id                uuid primary key default gen_random_uuid(),
  user_id           uuid not null references public.users(id) on delete cascade,
  refresh_hash      text not null unique,       -- HMAC of the refresh token, never the token itself
  prev_refresh_hash text,                       -- for reuse (theft) detection
  rotated_at        timestamptz,
  user_agent        text,
  ip                text,
  created_at        timestamptz not null default now(),
  last_used_at      timestamptz not null default now(),
  expires_at        timestamptz not null,       -- absolute expiry
  revoked_at        timestamptz
);
create index if not exists sessions_user_idx on public.sessions(user_id);
create index if not exists sessions_prev_idx on public.sessions(prev_refresh_hash);

create table if not exists public.password_resets (
  id          uuid primary key default gen_random_uuid(),
  user_id     uuid not null references public.users(id) on delete cascade,
  code_hash   text not null,
  attempts    int  not null default 0,
  expires_at  timestamptz not null,
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);
create index if not exists resets_user_idx on public.password_resets(user_id);

-- Lock everything down. RLS on + no policies = the public anon/authenticated keys can read nothing.
-- Only the backend (service role key) can touch these tables.
alter table public.users           enable row level security;
alter table public.sessions        enable row level security;
alter table public.password_resets enable row level security;

revoke all on public.users, public.sessions, public.password_resets from anon, authenticated;
