CREATE TABLE users (
  id INT AUTO_INCREMENT,
  email VARCHAR(255) NOT NULL UNIQUE,
  master_password VARCHAR(255) NOT NULL,
  password_salt VARCHAR(255),
  PRIMARY KEY (id)
);


CREATE TABLE passwords (
  id INT AUTO_INCREMENT,
  user_id INT NOT NULL,
  service VARCHAR(255) NOT NULL,
  encrypted_password VARBINARY(255) NOT NULL,
  encryption_password_salt VARBINARY(255),
  authentication_tag VARBINARY(16),
  nonce VARBINARY(16),
  PRIMARY KEY (id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);