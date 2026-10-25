#!/usr/bin/env bash
set -euo pipefail

# Run on the Linux server as the seeyourseo service user. It requests sudo
# authentication for MariaDB administration; the generated application
# password is written only to the private payments.env file.
DB_NAME="${PAYMENTS_DB_NAME:-seeyourseo_payments}"
DB_USER="${PAYMENTS_DB_USER:-seeyourseo_payments}"
ENV_DIR="${HOME}/.config/seeyourseo"
ENV_FILE="${PAYMENTS_ENV_FILE:-${ENV_DIR}/payments.env}"

if [[ ! "$DB_NAME" =~ ^[A-Za-z0-9_]+$ || ! "$DB_USER" =~ ^[A-Za-z0-9_]+$ ]]; then
  echo "Database and user names may contain only letters, numbers, and underscores." >&2
  exit 2
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "Run this script on the Linux SeeYourSEO server." >&2
  exit 2
fi
if ! command -v mariadb >/dev/null 2>&1; then
  echo "MariaDB client is not installed." >&2
  exit 2
fi

DB_PASSWORD="$(openssl rand -hex 32)"
umask 077
mkdir -p "$ENV_DIR"
TEMP_FILE="$(mktemp "${ENV_FILE}.XXXXXX")"
trap 'rm -f "$TEMP_FILE"; unset DB_PASSWORD' EXIT
if [[ -f "$ENV_FILE" ]]; then
  awk -F= '$1 != "PAYMENTS_DATABASE_URL" { print }' "$ENV_FILE" > "$TEMP_FILE"
fi
printf '\nPAYMENTS_DATABASE_URL=mysql://%s:%s@127.0.0.1:3306/%s\n' "$DB_USER" "$DB_PASSWORD" "$DB_NAME" >> "$TEMP_FILE"
chmod 600 "$TEMP_FILE"

sudo mariadb <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
ALTER USER '$DB_USER'@'127.0.0.1' IDENTIFIED BY '$DB_PASSWORD';
GRANT CREATE, ALTER, INDEX, SELECT, INSERT, UPDATE, DELETE ON \`$DB_NAME\`.* TO '$DB_USER'@'127.0.0.1';
SQL

mv -f "$TEMP_FILE" "$ENV_FILE"
chmod 600 "$ENV_FILE"
unset DB_PASSWORD
echo "Created isolated MariaDB database and restricted user. Connection details are saved in $ENV_FILE (mode 600)."
