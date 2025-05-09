CREATE TABLE auth(
    username CHAR(64) UNIQUE NOT NULL,  -- hash sha256
    password CHAR(60) NOT NULL,         -- hash bcrypt
    email VARCHAR(50)
    PRIMARY KEY (username)
);

CREATE TABLE banned_ip(
    ip VARCHAR(16) UNIQUE NOT NULL,
    ban_date DATE,
    PRIMARY KEY (ip)
);

CREATE TABLE banned_accs(
    username CHAR(64) UNIQUE NOT NULL,
    ban_date DATE,
    PRIMARY KEY (username)
);