-- Вставь всё это в Supabase: SQL Editor → New query → Run (один раз).

create table users (
  id bigint generated always as identity primary key,
  uname text unique not null,
  username text not null,
  salt text not null,
  pw text not null,
  contact text default '',
  created bigint,
  role text default 'base',
  perms text default 'vg,mp'
);

create table sessions (
  token text primary key,
  user_id bigint not null,
  created bigint
);

create table tickets (
  id bigint generated always as identity primary key,
  user_id bigint not null,
  subject text,
  status text default 'open',
  created bigint,
  updated bigint
);

create table messages (
  id bigint generated always as identity primary key,
  ticket_id bigint not null,
  sender text,
  text text,
  created bigint,
  seen int default 0
);

create table tg_map (
  msg_id bigint primary key,
  kind text,
  ref bigint
);
