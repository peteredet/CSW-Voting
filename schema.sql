-- =====================================================================
-- CSW 2026 "Extra Mile" vote — Supabase schema
-- Run once in Supabase → SQL Editor. Then import staff_import.csv into
-- public.staff (Table Editor → staff → Insert → Import data from CSV).
--
-- Security model:
--   * A person can vote only when signed in with an email that
--     (a) they have CONFIRMED by clicking the link Supabase sends, and
--     (b) matches the email on file for exactly one row in public.staff.
--   * Tables have RLS on and NO public policies. Staff interact only
--     through the SECURITY DEFINER functions below.
--   * Two admin roles (public.admins.role):
--       owner  : results + who voted for whom + CSV export + reset
--       viewer : live results only (colleague votes per person). The
--                database itself refuses ballot data to this role.
-- =====================================================================

create extension if not exists citext;

-- ---------- Tables ----------------------------------------------------

create table if not exists public.staff (
  staff_id      text primary key,
  name          text not null unique,
  email         citext unique,
  company       text,
  business_unit text,
  department    text,
  designation   text,
  location      text
);

-- Blank emails from a CSV import become NULL (otherwise two blanks clash on UNIQUE).
create or replace function public._clean_staff_email()
returns trigger language plpgsql as $$
begin
  new.email := nullif(lower(trim(new.email::text)), '')::citext;
  new.staff_id := upper(trim(new.staff_id));
  new.name := trim(new.name);
  return new;
end;
$$;
drop trigger if exists clean_staff_email on public.staff;
create trigger clean_staff_email before insert or update on public.staff
  for each row execute function public._clean_staff_email();

create table if not exists public.settings (
  id          int primary key default 1 check (id = 1),
  voting_open boolean not null default false
);
insert into public.settings (id) values (1) on conflict do nothing;

create table if not exists public.admins (
  email citext primary key,
  role  text not null default 'viewer' check (role in ('owner', 'viewer'))
);
alter table public.admins add column if not exists role text not null default 'viewer';

create table if not exists public.ballots (
  id             bigint generated always as identity primary key,
  voter_staff_id text not null unique references public.staff(staff_id),  -- one ballot per person
  created_at     timestamptz not null default now()
);

create table if not exists public.votes (
  id               bigint generated always as identity primary key,
  ballot_id        bigint not null references public.ballots(id) on delete cascade,
  voter_staff_id   text not null references public.staff(staff_id),
  nominee_staff_id text not null references public.staff(staff_id),
  slot             smallint not null check (slot between 1 and 3),
  is_self          boolean not null,
  created_at       timestamptz not null default now(),
  unique (ballot_id, nominee_staff_id),   -- three different people
  unique (ballot_id, slot)
);

-- Content-free "a ballot arrived" signal so the results-only admin can get
-- realtime updates without being able to read the votes table.
create table if not exists public.vote_ticks (
  id         bigint generated always as identity primary key,
  created_at timestamptz not null default now()
);

alter table public.vote_ticks enable row level security;
alter table public.staff    enable row level security;
alter table public.settings enable row level security;
alter table public.admins   enable row level security;
alter table public.ballots  enable row level security;
alter table public.votes    enable row level security;

-- ---------- Helpers ---------------------------------------------------

-- The staff row belonging to the signed-in, email-confirmed user (or nothing).
create or replace function public._me()
returns public.staff
language sql stable security definer set search_path = public, auth
as $$
  select s.*
  from public.staff s
  join auth.users u on u.email::citext = s.email
  where u.id = auth.uid()
    and u.email_confirmed_at is not null
  limit 1;
$$;

create or replace function public.is_admin()
returns boolean
language sql stable security definer set search_path = public, auth
as $$
  select exists (
    select 1
    from public.admins a
    join auth.users u on u.email::citext = a.email
    where u.id = auth.uid()
      and u.email_confirmed_at is not null
  );
$$;

-- 'owner' | 'viewer' | null
create or replace function public.admin_role()
returns text
language sql stable security definer set search_path = public, auth
as $$
  select a.role
  from public.admins a
  join auth.users u on u.email::citext = a.email
  where u.id = auth.uid()
    and u.email_confirmed_at is not null
  limit 1;
$$;

create or replace function public.is_owner()
returns boolean
language sql stable security definer set search_path = public
as $$ select coalesce(public.admin_role() = 'owner', false); $$;

-- Read access (also what lets Realtime deliver changes to the admin page).
-- Ballot-level data: owner only. Content-free ticks and settings: any admin.
drop policy if exists admin_read_staff    on public.staff;
drop policy if exists admin_read_ballots  on public.ballots;
drop policy if exists admin_read_votes    on public.votes;
drop policy if exists admin_read_settings on public.settings;
drop policy if exists admin_read_ticks    on public.vote_ticks;
create policy admin_read_staff    on public.staff      for select to authenticated using (public.is_owner());
create policy admin_read_ballots  on public.ballots    for select to authenticated using (public.is_owner());
create policy admin_read_votes    on public.votes      for select to authenticated using (public.is_owner());
create policy admin_read_settings on public.settings   for select to authenticated using (public.is_admin());
create policy admin_read_ticks    on public.vote_ticks for select to authenticated using (public.is_admin());

-- ---------- Public functions (staff-facing) ----------------------------

-- Names for the scroll list. Never returns emails.
create or replace function public.get_staff_list()
returns table (staff_id text, name text)
language sql stable security definer set search_path = public
as $$
  select staff_id, name from public.staff order by name;
$$;

-- Called before sign-up so the page can give a clear message.
-- Returns: ok | no_email_on_file | email_mismatch | already_registered | unknown_staff
create or replace function public.registration_check(p_staff_id text, p_email text)
returns text
language plpgsql stable security definer set search_path = public, auth
as $$
declare s public.staff;
begin
  select * into s from public.staff where staff_id = p_staff_id;
  if not found then return 'unknown_staff'; end if;
  if s.email is null then return 'no_email_on_file'; end if;
  if s.email <> trim(p_email)::citext then return 'email_mismatch'; end if;
  if exists (select 1 from auth.users u where u.email::citext = s.email) then
    return 'already_registered';
  end if;
  return 'ok';
end;
$$;

-- What the signed-in person should see.
create or replace function public.my_status()
returns json
language plpgsql stable security definer set search_path = public
as $$
declare s public.staff;
begin
  s := public._me();
  if s.staff_id is null then
    return json_build_object('linked', false);
  end if;
  return json_build_object(
    'linked', true,
    'staff_id', s.staff_id,
    'name', s.name,
    'has_voted', exists (select 1 from public.ballots b where b.voter_staff_id = s.staff_id),
    'voting_open', (select voting_open from public.settings where id = 1)
  );
end;
$$;

-- Cast exactly three votes for three different people (self allowed once).
create or replace function public.cast_votes(p_nominees text[])
returns void
language plpgsql volatile security definer set search_path = public
as $$
declare
  s public.staff;
  b_id bigint;
  i int;
begin
  s := public._me();
  if s.staff_id is null then
    raise exception 'Sign in with your confirmed office email to vote.';
  end if;
  if not (select voting_open from public.settings where id = 1) then
    raise exception 'Voting is closed right now.';
  end if;
  if p_nominees is null or array_length(p_nominees, 1) <> 3 then
    raise exception 'Pick exactly three people.';
  end if;
  if (select count(distinct x) from unnest(p_nominees) x) <> 3 then
    raise exception 'Your three votes must go to three different people.';
  end if;
  if (select count(*) from public.staff where staff_id = any (p_nominees)) <> 3 then
    raise exception 'One of your picks is not on the staff list.';
  end if;

  begin
    insert into public.ballots (voter_staff_id) values (s.staff_id) returning id into b_id;
  exception when unique_violation then
    raise exception 'You have already voted. Each person votes once.';
  end;

  for i in 1..3 loop
    insert into public.votes (ballot_id, voter_staff_id, nominee_staff_id, slot, is_self)
    values (b_id, s.staff_id, p_nominees[i], i, p_nominees[i] = s.staff_id);
  end loop;
  insert into public.vote_ticks default values;
end;
$$;

-- ---------- Admin functions --------------------------------------------

create or replace function public.admin_set_voting(p_open boolean)
returns void
language plpgsql volatile security definer set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'Admins only.'; end if;
  update public.settings set voting_open = p_open where id = 1;
end;
$$;

create or replace function public.admin_overview()
returns json
language plpgsql stable security definer set search_path = public, auth
as $$
begin
  if not public.is_admin() then raise exception 'Admins only.'; end if;
  return json_build_object(
    'role',        public.admin_role(),
    'voting_open', (select voting_open from public.settings where id = 1),
    'staff_total', (select count(*) from public.staff),
    'with_email',  (select count(*) from public.staff where email is not null),
    'registered',  (select count(*) from public.staff s join auth.users u on u.email::citext = s.email
                     where u.email_confirmed_at is not null),
    'voted',       (select count(*) from public.ballots)
  );
end;
$$;

-- Results-only view for the viewer admin (and the owner): colleague votes per
-- person. Self-votes are left out on purpose: they would reveal individual ballots.
create or replace function public.admin_results()
returns table (staff_id text, name text, business_unit text, department text, colleague_votes bigint)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_admin() then raise exception 'Admins only.'; end if;
  return query
    select s.staff_id, s.name, s.business_unit, s.department,
           count(v.id) filter (where not v.is_self)
    from public.staff s
    left join public.votes v on v.nominee_staff_id = s.staff_id
    group by s.staff_id
    order by 5 desc, s.name;
end;
$$;

-- Owner: ranked by colleague votes, self-votes reported separately.
create or replace function public.admin_leaderboard()
returns table (staff_id text, name text, business_unit text, department text,
               colleague_votes bigint, self_votes bigint, total_votes bigint)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_owner() then raise exception 'Owner only.'; end if;
  return query
    select s.staff_id, s.name, s.business_unit, s.department,
           count(v.id) filter (where not v.is_self),
           count(v.id) filter (where v.is_self),
           count(v.id)
    from public.staff s
    left join public.votes v on v.nominee_staff_id = s.staff_id
    group by s.staff_id
    order by 5 desc, 7 desc, s.name;
end;
$$;

-- One row per vote, with both sides' attributes, for analysis/export.
create or replace function public.admin_vote_rows()
returns table (voted_at timestamptz, ballot_id bigint, slot smallint, is_self boolean,
               voter_id text, voter_name text, voter_business_unit text, voter_department text,
               voter_designation text, voter_location text,
               nominee_id text, nominee_name text, nominee_business_unit text, nominee_department text,
               nominee_designation text, nominee_location text)
language plpgsql stable security definer set search_path = public
as $$
begin
  if not public.is_owner() then raise exception 'Owner only.'; end if;
  return query
    select v.created_at, v.ballot_id, v.slot, v.is_self,
           a.staff_id, a.name, a.business_unit, a.department, a.designation, a.location,
           n.staff_id, n.name, n.business_unit, n.department, n.designation, n.location
    from public.votes v
    join public.staff a on a.staff_id = v.voter_staff_id
    join public.staff n on n.staff_id = v.nominee_staff_id
    order by v.created_at desc, v.ballot_id, v.slot;
end;
$$;

-- Testing only: wipes all ballots and votes.
create or replace function public.admin_reset_votes()
returns void
language plpgsql volatile security definer set search_path = public
as $$
begin
  if not public.is_owner() then raise exception 'Owner only.'; end if;
  delete from public.ballots where true;  -- cascades to votes
  delete from public.vote_ticks where true;
end;
$$;

-- ---------- Permissions -------------------------------------------------

revoke all on function public._me()                     from public, anon, authenticated;
revoke all on function public.get_staff_list()          from public;
revoke all on function public.registration_check(text, text) from public;
revoke all on function public.my_status()               from public;
revoke all on function public.cast_votes(text[])        from public;
revoke all on function public.admin_set_voting(boolean) from public;
revoke all on function public.admin_overview()          from public;
revoke all on function public.admin_leaderboard()       from public;
revoke all on function public.admin_results()           from public;
revoke all on function public.admin_role()              from public;
revoke all on function public.is_owner()                from public;
revoke all on function public.admin_vote_rows()         from public;
revoke all on function public.admin_reset_votes()       from public;

grant execute on function public.get_staff_list()              to anon, authenticated;
grant execute on function public.registration_check(text, text) to anon, authenticated;
grant execute on function public.is_admin()                    to authenticated;
grant execute on function public.my_status()                   to authenticated;
grant execute on function public.cast_votes(text[])            to authenticated;
grant execute on function public.admin_set_voting(boolean)     to authenticated;
grant execute on function public.admin_overview()              to authenticated;
grant execute on function public.admin_leaderboard()           to authenticated;
grant execute on function public.admin_results()               to authenticated;
grant execute on function public.admin_role()                  to authenticated;
grant execute on function public.is_owner()                    to authenticated;
grant execute on function public.admin_vote_rows()             to authenticated;
grant execute on function public.admin_reset_votes()           to authenticated;

-- ---------- Realtime (live leaderboard) ----------------------------------
do $$
begin
  begin alter publication supabase_realtime add table public.votes;    exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.ballots;  exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.settings; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.vote_ticks; exception when duplicate_object then null; end;
end $$;

-- ---------- Admins (edit the emails, then run) ---------------------------
-- insert into public.admins (email, role) values ('your.email@company.com', 'owner');
-- insert into public.admins (email, role) values ('second.admin@company.com', 'viewer');
