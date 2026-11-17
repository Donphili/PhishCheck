-- PhishCheck team training. Run this once in the Supabase SQL Editor.
--
-- Privacy: there are no names, no email addresses and no IP addresses here.
-- A result is only a score, a language and the quiz topics that were missed.
-- Row Level Security is switched on and no public policies exist, so only the
-- server (using its secret key) can read or write these tables.

create table if not exists public.teams (
  id uuid primary key default gen_random_uuid(),
  join_code text not null unique,
  name text not null default '',
  manager_key_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.quiz_results (
  id bigint generated always as identity primary key,
  team_id uuid not null references public.teams (id) on delete cascade,
  score smallint not null check (score between 0 and 20),
  total smallint not null check (total between 1 and 20),
  language text not null check (language in ('en', 'ar')),
  missed text[] not null default '{}',
  created_at timestamptz not null default now(),
  check (score <= total)
);

create index if not exists quiz_results_team_created
  on public.quiz_results (team_id, created_at desc);

alter table public.teams enable row level security;
alter table public.quiz_results enable row level security;
