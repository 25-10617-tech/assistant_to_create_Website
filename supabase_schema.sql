create table if not exists public.webcraft_projects (
  project_key text primary key,
  elements jsonb not null default '[]'::jsonb,
  id_counter integer not null default 1,
  updated_at timestamptz not null default now()
);

alter table public.webcraft_projects enable row level security;

drop policy if exists "Allow anon read webcraft projects" on public.webcraft_projects;
create policy "Allow anon read webcraft projects"
on public.webcraft_projects
for select
to anon
using (true);

drop policy if exists "Allow anon insert webcraft projects" on public.webcraft_projects;
create policy "Allow anon insert webcraft projects"
on public.webcraft_projects
for insert
to anon
with check (true);

drop policy if exists "Allow anon update webcraft projects" on public.webcraft_projects;
create policy "Allow anon update webcraft projects"
on public.webcraft_projects
for update
to anon
using (true)
with check (true);
