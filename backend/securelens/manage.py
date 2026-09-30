"""``securelens-manage`` — operator commands for a SecureLens server.

    securelens-manage migrate            apply database migrations
    securelens-manage current            show the database revision
    securelens-manage bootstrap          create the first owner account (interactive, or --password-stdin)
    securelens-manage check              report configuration problems before going live
"""

from __future__ import annotations

import argparse
import getpass
import sys


def _alembic_config():
    from alembic.config import Config

    config = Config()
    config.set_main_option("script_location", "securelens:migrations")
    return config


def cmd_migrate(_: argparse.Namespace) -> int:
    from alembic import command

    command.upgrade(_alembic_config(), "head")
    print("database is up to date")
    return 0


def cmd_current(_: argparse.Namespace) -> int:
    from alembic import command

    command.current(_alembic_config(), verbose=False)
    return 0


def cmd_bootstrap(args: argparse.Namespace) -> int:
    from securelens.core import audit
    from securelens.core.database import session_scope
    from securelens.core.errors import AppError
    from securelens.services import identity

    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = getpass.getpass("Password for the owner account: ")
        if getpass.getpass("Repeat the password: ") != password:
            print("passwords do not match", file=sys.stderr)
            return 2
    with session_scope() as db:
        if identity.users_exist(db):
            print("this instance already has accounts; sign in and invite people from Settings → Members",
                  file=sys.stderr)
            return 2
        try:
            user = identity.create_user(db, email=args.email, display_name=args.name, password=password)
        except AppError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return 2
        org = identity.create_organization(db, name=args.organization, owner=user)
        audit.record(db, "instance.bootstrap", organization_id=org.id, target_type="user", target_id=user.id,
                     actor_label=f"securelens-manage:{user.email}")
    print(f"created owner {args.email} in organization '{args.organization}'")
    return 0


def cmd_check(_: argparse.Namespace) -> int:
    from securelens.ai.providers import provider_status
    from securelens.core.config import get_settings
    from securelens.scanners.external import external_scanner_status

    settings = get_settings()
    problems: list[str] = []
    notes: list[str] = []
    if settings.uses_insecure_default_key:
        problems.append("SECURELENS_SECRET_KEY is the insecure development default")
    if not settings.cookie_secure:
        (problems if settings.environment == "production" else notes).append(
            "SECURELENS_COOKIE_SECURE is false (cookies are sent over plain HTTP)")
    if settings.is_sqlite:
        (problems if settings.environment == "production" else notes).append(
            "SQLite is configured; use PostgreSQL for multi-user deployments")
    try:
        settings.storage_dir.mkdir(parents=True, exist_ok=True)
        probe = settings.storage_dir / ".write-test"
        probe.write_text("ok")
        probe.unlink()
    except OSError as exc:
        problems.append(f"storage directory {settings.storage_dir} is not writable ({exc.__class__.__name__})")
    ai = provider_status()
    notes.append(f"AI provider: {ai['provider']} ({ai['detail']})")
    if not settings.osv_enabled and not settings.advisory_db_dir:
        notes.append("dependency vulnerability lookup is disabled; dependencies will be NOT VERIFIED")
    for tool in external_scanner_status(settings.external_scanners):
        state = "installed" if tool["installed"] else "not installed"
        notes.append(f"external scanner {tool['name']}: {state}{'' if tool['enabled'] else ' (disabled)'}")
    for note in notes:
        print(f"note:    {note}")
    for problem in problems:
        print(f"problem: {problem}")
    print("configuration OK" if not problems else f"{len(problems)} problem(s) found")
    return 1 if problems else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="securelens-manage", description="SecureLens server administration.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="apply database migrations")
    sub.add_parser("current", help="show the current database revision")
    p = sub.add_parser("bootstrap", help="create the first owner account")
    p.add_argument("--email", required=True)
    p.add_argument("--name", default="Owner")
    p.add_argument("--organization", required=True)
    p.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    sub.add_parser("check", help="check the configuration")
    args = parser.parse_args(argv)
    commands = {"migrate": cmd_migrate, "current": cmd_current, "bootstrap": cmd_bootstrap, "check": cmd_check}
    return commands[args.command](args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
