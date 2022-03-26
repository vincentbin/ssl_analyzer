create table certificate
(
    id                    int auto_increment
        primary key,
    issued_domain         varchar(256) not null,
    issued_to             varchar(256) null,
    issued_by             varchar(256) null,
    valid_from            varchar(256) null,
    valid_to              varchar(256) null,
    validity_days         int          null,
    certificate_sn        varchar(256) null,
    certificate_version   varchar(10)  null,
    certificate_algorithm varchar(256) null,
    expired               tinyint(1)   null,
    constraint certificate_k_2
        unique (issued_domain)
) default character set utf8 collate utf8_general_ci;

