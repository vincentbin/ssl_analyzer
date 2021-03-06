create table certificate
(
    id                    int auto_increment
        primary key,
    host                  varchar(256) not null,
    open443               varchar(256) null,
    error                 varchar(256) null,
    ssl_error             varchar(256) null,
    certificate_version   varchar(10)  null,
    certificate_algorithm varchar(256) null,
    issuer_country        varchar(256) null,
    issued_organization   varchar(256) null,
    public_key_type       varchar(256) null,
    public_key_bits       varchar(256) null,
    expired               varchar(256) null,
    valid_from            varchar(256) null,
    valid_to              varchar(256) null,
    validity_days         varchar(256) null,
    valid_days_left       varchar(256) null,
    ocsp_status           varchar(256) null,
    ocsp_error            varchar(256) null,
    crl_status            varchar(256) null,
    crl_reason            varchar(256) null
) default character set utf8 collate utf8_general_ci;

