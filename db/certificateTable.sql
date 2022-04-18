create table certificate
(
    id                    int auto_increment
        primary key,
    host                  varchar(256) not null,
    error_number          varchar(256) not null,
    certificate_version   varchar(10)  null,
    certificate_algorithm varchar(256) null,
    issuer_country        varchar(256) null,
    issued_organization   varchar(256) null,
    public_key_type       varchar(256) null,
    public_key_bits       varchar(256) null,
    expired               tinyint(1)   null
    valid_from            varchar(256) null,
    valid_to              varchar(256) null,
    validity_days         int          null,
    valid_days_left       varchar(256) null,
    ocsp_status           varchar(256) null,
) default character set utf8 collate utf8_general_ci;

