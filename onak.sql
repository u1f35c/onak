DROP TABLE onak_keys;
DROP TABLE onak_uids;
DROP TABLE onak_sigs;

CREATE TABLE onak_keys (
	keyid	char(8) NOT NULL,
	keydata	oid NOT NULL
);

CREATE TABLE onak_uids (
	keyid	char(8) NOT NULL,
	uid	varchar(6000) NOT NULL
);

CREATE TABLE onak_sigs (
	signer	char(8) NOT NULL,
	signee	char(8) NOT NULL
);
