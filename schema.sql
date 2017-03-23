drop table if exists 'subscribers';
create table 'subscribers' (
  'id' integer primary key autoincrement,
  'number' text not null
);

drop table if exists 'banned';
create table 'banned' (
  'id' integer primary key autoincrement,
  'number' text not null
);

drop table if exists 'queue';
create table 'queue' (
  'id' integer primary key autoincrement,
  'src' text not null,
  'dst' text not null,
  'text' text not null,
  'delay' integer not null
);
