create table govhub_applications (
   id int8 not null,
	application_id varchar(255) not null,
	deployed_uri varchar(255) not null,
	bg_color varchar(255),
	logo_color varchar(255),
	logo_name varchar(255),
	logo_type int4,
	logo_url varchar(255),
	name varchar(255) not null,
	primary key (id)
);

alter table govhub_applications 
   add constraint UK_c8mm83c640q0rl6mtbnfvrge9 unique (application_id);

