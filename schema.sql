drop table if exists `beacons`;
create table `beacons` (
  `telno` varchar(16) primary key,
  `alias_for` varchar(16) null,
  `nickname` varchar(16) not null default 'beacon',
  `description` text null,

  /* a unique prefix name for the beacon, like an airport code */
  `locid` varchar(8) not null unique,

  /* a long string used to conceal the API route the provider hits for incoming SMS messages */
  `secret` char(64) not null,

  /* plivo credentials */
  `plivo_id` char(64) not null,
  `plivo_token` char(64) not null,

  /* autosend_delay:
   *   null -> don't autosend
   *   0    -> send without delay
   *   >0   -> sendable after this many seconds */
  `autosend_delay` int unsigned null,

  /* prune_delay:
   *   null -> keep all relayed or rejected messages until explicitly deleted
   *   0    -> delete messages when relayed or rejected
   *   >0   -> prune relayed or rejected messages after this many seconds */
  `prune_delay` int unsigned null,

  /* token_lifetime:
   *   0    -> tokens are never accepted
   *   >0   -> tokens are valid for this many seconds */
  `token_lifetime` int unsigned not null
);

drop table if exists `alerts`;
create table `alerts` (
  `id` serial primary key,
  `beacon` varchar(16) not null,

  /* the root user has telno=root */
  `telno` varchar(16) not null,

  `text` text not null,
  `reported` bigint unsigned not null,
  `relayed` bigint unsigned null,

  /* type:
   *   0  -> report_pending
   *   1  -> report_relayed
   *   2  -> report_rejected
   *   3  -> wallops_relayed
   *  >3  -> [reserved] */
  `alert_type` tinyint unsigned not null
);

drop table if exists `users`;
create table `users` (

  /* root is 1 */
  `id` serial primary key,

  `beacon` varchar(16) not null,
  `telno` varchar(16) not null,
  `nickname` varchar(16) null,

  /* user_type:
   * 0  -> not_subscribed
   * 1  -> subscribed
   * 2  -> admin
   * 3  -> banned_wasnt_subscribed
   * 4  -> banned_was_subscribed
   * >4 -> [reserved] */
  `user_type` tinyint unsigned not null,

  /* for an admin: how many reports has this admin rejected/relayed
   * for anyone else: how many of their reports have been rejected/relayed */
  `rejected` int not null default 0,
  `relayed` int not null default 0,

  /* password hash and salt */
  `phash` blob null,

  /* login token hash and salt */
  `thash` blob null,
  `token_expires` bigint unsigned null,

  `created` bigint unsigned not null
);
