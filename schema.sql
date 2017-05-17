drop table if exists `instances`;
create table `instances` (
  `id` serial primary key,
  `instance` char(32) not null,
  `name` text not null,
  `community` text not null,
  `alias` char(32)
);

drop table if exists `subscribers`;
create table `subscribers` (
  `id` serial primary key,
  `instance` char(32) not null,
  `phone` char(32) not null
);

drop table if exists `investigators`;
create table `investigators` (
  `id` serial primary key,
  `instance` char(32) not null,
  `phone` char(32) not null,
  `name` text not null
);

drop table if exists `banned`;
create table `banned` (
  `id` serial primary key,
  `instance` char(32) not null,
  `phone` char(32) not null
);

drop table if exists `queue`;
create table `queue` (
  `id` serial primary key,
  `src` char(32) not null,
  `dst` char(32) not null,
  `text` text not null,
  `delay` integer not null
);
