#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL must be set}"
: "${S3_BACKUP_BUCKET:?S3_BACKUP_BUCKET must be set}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID must be set}"
: "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY must be set}"

backup_dir="$(mktemp -d)"
trap 'rm -rf "$backup_dir"' EXIT INT TERM
timestamp="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
backup_file="$backup_dir/failure-doctor-$timestamp.dump"

pg_dump --format=custom --no-owner --no-privileges --dbname="$DATABASE_URL" --file="$backup_file"
aws s3 cp "$backup_file" "s3://${S3_BACKUP_BUCKET%/}/postgres/failure-doctor-$timestamp.dump" --sse AES256 --only-show-errors
echo "Encrypted database backup uploaded: postgres/failure-doctor-$timestamp.dump"
