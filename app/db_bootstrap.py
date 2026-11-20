"""Create an unprivileged runtime role while preserving the existing owner role."""

import os

import psycopg
from psycopg import sql


def main() -> None:
    host = os.environ["DB_HOST"]
    port = int(os.getenv("DB_PORT", "5432"))
    database = os.getenv("DB_NAME", "osint")
    owner = os.getenv("ADMIN_DB_USER", "osint")
    owner_password = os.environ["ADMIN_DB_PASSWORD"]
    app_user = os.getenv("APP_DB_USER", "osint_app")
    app_password = os.environ["APP_DB_PASSWORD"]
    with psycopg.connect(host=host, port=port, dbname=database, user=owner, password=owner_password, autocommit=True) as connection:
        exists = connection.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (app_user,)).fetchone()
        if not exists:
            connection.execute(
                sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(app_user), sql.Literal(app_password))
            )
        else:
            connection.execute(
                sql.SQL("ALTER ROLE {} WITH LOGIN PASSWORD {}").format(sql.Identifier(app_user), sql.Literal(app_password))
            )
        connection.execute(sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(database), sql.Identifier(app_user)))
        connection.execute(sql.SQL("GRANT USAGE ON SCHEMA public TO {}").format(sql.Identifier(app_user)))
        connection.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {}").format(sql.Identifier(app_user)))
        connection.execute(sql.SQL("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {}").format(sql.Identifier(app_user)))
        connection.execute(sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {}").format(sql.Identifier(owner), sql.Identifier(app_user)))
        connection.execute(sql.SQL("ALTER DEFAULT PRIVILEGES FOR ROLE {} IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO {}").format(sql.Identifier(owner), sql.Identifier(app_user)))


if __name__ == "__main__":
    main()
