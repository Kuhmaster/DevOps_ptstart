CREATE USER kali WITH REPLICATION ENCRYPTED PASSWORD 'kali';
SELECT pg_create_physical_replication_slot('replication_slot');

CREATE DATABASE db_mail;
\c db_mail

CREATE TABLE IF NOT EXISTS email(
    id SERIAL PRIMARY KEY,
    mail VARCHAR (100) NOT NULL
);

CREATE TABLE IF NOT EXISTS phone(
    id SERIAL PRIMARY KEY,
    phone_number VARCHAR (100) NOT NULL
);
