-- RPC Orders: общая статистика и отзывы.
-- Выполните этот файл один раз в Supabase: SQL Editor -> New query -> Run.

create extension if not exists pgcrypto;

create table if not exists public.site_stats (
  id smallint primary key default 1 check (id = 1),
  total_visitors bigint not null default 0,
  total_views bigint not null default 0,
  updated_at timestamptz not null default now()
);

insert into public.site_stats (id)
values (1)
on conflict (id) do nothing;

create table if not exists public.site_visitors (
  visitor_id text primary key,
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  visits bigint not null default 1
);

create index if not exists site_visitors_last_seen_idx
  on public.site_visitors (last_seen desc);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  name varchar(80) not null,
  project_type varchar(40) not null,
  rating smallint not null check (rating between 1 and 5),
  body varchar(1200) not null,
  approved boolean not null default false,
  created_at timestamptz not null default now()
);

create index if not exists reviews_approved_created_idx
  on public.reviews (approved, created_at desc);

create or replace function public.get_site_stats()
returns table (
  total_visitors bigint,
  total_views bigint,
  online_users bigint,
  approved_reviews bigint
)
language sql
security definer
set search_path = public
as $$
  select
    s.total_visitors,
    s.total_views,
    (select count(*)::bigint from public.site_visitors v where v.last_seen > now() - interval '2 minutes'),
    (select count(*)::bigint from public.reviews r where r.approved = true)
  from public.site_stats s
  where s.id = 1;
$$;

create or replace function public.register_site_visit(p_visitor_id text)
returns table (
  total_visitors bigint,
  total_views bigint,
  online_users bigint,
  approved_reviews bigint
)
language plpgsql
security definer
set search_path = public
as $$
declare
  inserted_rows integer := 0;
begin
  if p_visitor_id is null or length(trim(p_visitor_id)) < 10 then
    raise exception 'invalid visitor id';
  end if;

  insert into public.site_visitors (visitor_id)
  values (left(trim(p_visitor_id), 128))
  on conflict (visitor_id) do nothing;

  get diagnostics inserted_rows = row_count;

  if inserted_rows = 0 then
    update public.site_visitors
    set last_seen = now(), visits = visits + 1
    where visitor_id = left(trim(p_visitor_id), 128);
  end if;

  update public.site_stats
  set
    total_visitors = total_visitors + inserted_rows,
    total_views = total_views + 1,
    updated_at = now()
  where id = 1;

  return query select * from public.get_site_stats();
end;
$$;

create or replace function public.touch_site_visitor(p_visitor_id text)
returns table (
  total_visitors bigint,
  total_views bigint,
  online_users bigint,
  approved_reviews bigint
)
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.site_visitors
  set last_seen = now()
  where visitor_id = left(trim(p_visitor_id), 128);

  if not found then
    return query select * from public.register_site_visit(p_visitor_id);
    return;
  end if;

  return query select * from public.get_site_stats();
end;
$$;

alter table public.site_stats enable row level security;
alter table public.site_visitors enable row level security;
alter table public.reviews enable row level security;

revoke all on public.site_stats from anon, authenticated;
revoke all on public.site_visitors from anon, authenticated;
revoke all on public.reviews from anon, authenticated;

-- Сервер Render работает с секретным ключом Supabase.
grant select, insert, update, delete on public.site_stats to service_role;
grant select, insert, update, delete on public.site_visitors to service_role;
grant select, insert, update, delete on public.reviews to service_role;
grant execute on function public.get_site_stats() to service_role;
grant execute on function public.register_site_visit(text) to service_role;
grant execute on function public.touch_site_visitor(text) to service_role;
