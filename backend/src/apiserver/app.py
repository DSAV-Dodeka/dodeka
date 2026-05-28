"""Application entry point: route table, server startup, and configuration."""

import logging
import logging.handlers
import threading
from pathlib import Path
from urllib.parse import urlparse

from freetser import (
    Request,
    Response,
    TcpServerConfig,
    setup_logging,
    start_server,
    start_storage_thread,
)
from freetser.server import StorageQueue

from apiserver.data import DB_TABLES
from apiserver.data.client import AuthClient
from apiserver.handlers.admin import (
    accept_registration_handler,
    add_user_permission,
    available_permissions_handler,
    complete_sync_handler,
    delete_registration_handler,
    delete_user_handler,
    import_sync_handler,
    link_bondsnummer_handler,
    list_registrations_handler,
    list_system_users_handler,
    list_users_handler,
    remove_user_permission,
    resend_registration_invite_handler,
    resolve_sync_match_handler,
    set_permissions_handler,
    sync_status_handler,
)
from apiserver.handlers.auth import (
    clear_session,
    get_registration_status_handler,
    get_session_token_handler,
    lookup_registration_handler,
    renew_signup_handler,
    request_registration,
    session_info,
    set_session,
)
from apiserver.handlers.acceptance import start_outbox_dispatcher
from apiserver.handlers.features.birthdays import birthdays_handler
from apiserver.handlers.features.private_kv import (
    admin_get_private_handler,
    admin_list_private_handler,
    admin_set_private_handler,
    get_private_handler,
)
from apiserver.private import create_private_handler, start_private_server
from apiserver.server import (
    InvalidHeaders,
    PermissionConfig,
    RouteData,
    RouteEntry,
    check_access,
    check_csrf,
    handle_options_request,
    parse_headers,
)
from apiserver.settings import Settings, SmtpConfig, load_settings_from_env, parse_args
from apiserver.tooling.command_handlers import bootstrap_admin_on_startup
from apiserver.tooling.codes import CodeWaiter

logger = logging.getLogger("apiserver.app")


def handler_with_client(
    auth_client: AuthClient,
    req: Request,
    store_queue: StorageQueue | None,
    frontend_origin: str,
    smtp_config: SmtpConfig | None = None,
    smtp_send: bool = False,
) -> Response:
    """Dispatch a request to its handler based on the route table."""
    if store_queue is None:
        logger.error("Storage not available")
        return Response.text("Storage not available", status_code=500)

    path = urlparse(req.path).path
    method = req.method

    headers = parse_headers(req.headers)
    if isinstance(headers, InvalidHeaders):
        return Response.text("Invalid headers", status_code=400)

    def h_request_registration():
        return request_registration(auth_client, req, store_queue)

    def h_set_sess():
        return set_session(
            auth_client,
            req,
            store_queue,
            smtp_config,
            smtp_send,
            frontend_origin,
        )

    def h_clear_sess():
        return clear_session(req)

    def h_sess_info():
        return session_info(auth_client, req, headers, store_queue)

    def h_add_perm():
        return add_user_permission(req, store_queue)

    def h_remove_perm():
        return remove_user_permission(req, store_queue)

    def h_list_registrations():
        return list_registrations_handler(store_queue)

    def h_accept_registration():
        return accept_registration_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_get_reg_status():
        return get_registration_status_handler(req, store_queue)

    def h_lookup_registration():
        return lookup_registration_handler(req, store_queue)

    def h_get_sess_token():
        return get_session_token_handler(headers)

    def h_renew_signup():
        return renew_signup_handler(auth_client, req, store_queue)

    def h_list_users():
        return list_users_handler(store_queue)

    def h_available_permissions():
        return available_permissions_handler()

    def h_set_permissions():
        return set_permissions_handler(req, store_queue)

    def h_import_sync():
        return import_sync_handler(req, store_queue)

    def h_sync_status():
        return sync_status_handler(store_queue)

    def h_resolve_sync_match():
        return resolve_sync_match_handler(req, store_queue)

    def h_complete_sync():
        return complete_sync_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_resend_registration_invite():
        return resend_registration_invite_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_delete_registration():
        return delete_registration_handler(req, store_queue)

    def h_delete_user():
        return delete_user_handler(req, store_queue)

    def h_link_bondsnummer():
        return link_bondsnummer_handler(req, store_queue)

    def h_list_system_users():
        return list_system_users_handler(store_queue)

    def h_birthdays():
        return birthdays_handler(store_queue)

    def h_get_private():
        return get_private_handler(req, headers, auth_client, store_queue)

    def h_admin_get_private():
        return admin_get_private_handler(req, store_queue)

    def h_admin_set_private():
        return admin_set_private_handler(req, store_queue)

    def h_admin_list_private():
        return admin_list_private_handler(store_queue)

    route_table = {
        # Auth
        "/auth/request_registration": {
            "POST": RouteEntry(h_request_registration, PermissionConfig.public())
        },
        "/auth/registration_status": {
            "POST": RouteEntry(h_get_reg_status, PermissionConfig.public())
        },
        "/auth/lookup_registration": {
            "POST": RouteEntry(h_lookup_registration, PermissionConfig.public())
        },
        "/auth/renew_signup": {
            "POST": RouteEntry(h_renew_signup, PermissionConfig.public())
        },
        # Admin - registrations
        "/admin/list_registrations/": {
            "GET": RouteEntry(h_list_registrations, PermissionConfig.require("admin"))
        },
        "/admin/accept_registration/": {
            "POST": RouteEntry(h_accept_registration, PermissionConfig.require("admin"))
        },
        "/admin/resend_registration_invite/": {
            "POST": RouteEntry(
                h_resend_registration_invite, PermissionConfig.require("admin")
            )
        },
        "/admin/delete_registration/": {
            "POST": RouteEntry(h_delete_registration, PermissionConfig.require("admin"))
        },
        "/admin/delete_user/": {
            "POST": RouteEntry(h_delete_user, PermissionConfig.require("admin"))
        },
        # Admin - permissions
        "/admin/add_permission/": {
            "POST": RouteEntry(h_add_perm, PermissionConfig.require("admin"))
        },
        "/admin/remove_permission/": {
            "POST": RouteEntry(h_remove_perm, PermissionConfig.require("admin"))
        },
        "/admin/list_users/": {
            "GET": RouteEntry(h_list_users, PermissionConfig.require("admin"))
        },
        "/admin/available_permissions/": {
            "GET": RouteEntry(
                h_available_permissions, PermissionConfig.require("admin")
            )
        },
        "/admin/set_permissions/": {
            "POST": RouteEntry(h_set_permissions, PermissionConfig.require("admin"))
        },
        # Admin - sync
        "/admin/import_sync/": {
            "POST": RouteEntry(h_import_sync, PermissionConfig.require("admin"))
        },
        "/admin/sync_status/": {
            "GET": RouteEntry(h_sync_status, PermissionConfig.require("admin"))
        },
        "/admin/resolve_sync_match/": {
            "POST": RouteEntry(h_resolve_sync_match, PermissionConfig.require("admin"))
        },
        "/admin/complete_sync/": {
            "POST": RouteEntry(h_complete_sync, PermissionConfig.require("admin"))
        },
        "/admin/link_bondsnummer/": {
            "POST": RouteEntry(h_link_bondsnummer, PermissionConfig.require("admin"))
        },
        "/admin/list_system_users/": {
            "GET": RouteEntry(h_list_system_users, PermissionConfig.require("admin"))
        },
        # Member routes
        "/members/birthdays/": {
            "GET": RouteEntry(h_birthdays, PermissionConfig.require("member"))
        },
        # Private key-value store
        "/members/private/": {
            "POST": RouteEntry(
                h_get_private,
                PermissionConfig.public(),
                requires_credentials=True,
            )
        },
        "/admin/private_kv/get/": {
            "POST": RouteEntry(h_admin_get_private, PermissionConfig.require("admin"))
        },
        "/admin/private_kv/set/": {
            "POST": RouteEntry(h_admin_set_private, PermissionConfig.require("admin"))
        },
        "/admin/private_kv/list/": {
            "GET": RouteEntry(h_admin_list_private, PermissionConfig.require("admin"))
        },
        "/auth/session_info/": {
            "GET": RouteEntry(
                h_sess_info, PermissionConfig.public(), requires_credentials=True
            )
        },
        # Cookie management
        "/cookies/session_token/": {
            "GET": RouteEntry(
                h_get_sess_token, PermissionConfig.public(), requires_credentials=True
            )
        },
        "/cookies/set_session/": {
            "POST": RouteEntry(
                h_set_sess, PermissionConfig.public(), requires_credentials=True
            )
        },
        "/cookies/clear_session/": {
            "POST": RouteEntry(
                h_clear_sess, PermissionConfig.public(), requires_credentials=True
            )
        },
    }

    def add_cors(response: Response, credentials: bool = False) -> Response:
        response.headers.append(
            (
                b"Access-Control-Allow-Origin",
                frontend_origin.encode("utf-8"),
            )
        )
        if credentials:
            response.headers.append((b"Access-Control-Allow-Credentials", b"true"))
        return response

    route = route_table.get(path)
    if route is None:
        logger.info(f"Route not found: {method} {path}")
        return add_cors(Response.text(f"Not Found: {method} {path}", status_code=404))

    if method == "OPTIONS":
        requested_method = headers.get("access-control-request-method")
    else:
        requested_method = method

    route_entry = None if requested_method is None else route.get(requested_method)
    if route_entry is None:
        logger.info(f"Method not supported: {method} {path}")
        return add_cors(Response.text(f"Not Found: {method} {path}", status_code=404))

    credentials = route_entry.needs_credentials()

    if method == "OPTIONS":
        return handle_options_request(route, route_entry, frontend_origin)

    csrf = check_csrf(method, headers, [frontend_origin])
    if csrf is not None:
        logger.warning(f"CSRF rejected: {method} {path} ({csrf.reason})")
        return add_cors(Response.text("Cross-origin request blocked", status_code=403))

    if error := check_access(
        RouteData(entry=route_entry, method=method, path=path),
        headers,
        auth_client,
        store_queue,
    ):
        return add_cors(error, credentials)

    response = route_entry.handler()
    return add_cors(response, credentials)


class PrefixFormatter(logging.Formatter):
    """Wraps an existing formatter, prepending a prefix to each line."""

    def __init__(self, prefix: str, base: logging.Formatter | None):
        super().__init__()
        self.prefix = prefix
        self.base = base

    def format(self, record: logging.LogRecord) -> str:
        msg = self.base.format(record) if self.base else super().format(record)
        return f"{self.prefix} {msg}"


def configure_logging(
    log_listener: logging.handlers.QueueListener,
    debug_logs: bool,
    log_prefix: str,
) -> None:
    log_level = logging.DEBUG if debug_logs else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for h in root_logger.handlers:
        h.setLevel(log_level)

    if log_prefix:
        for h in log_listener.handlers:
            h.setFormatter(PrefixFormatter(log_prefix, h.formatter))


def run_with_settings(
    settings: Settings,
    *,
    log_prefix: str = "",
    ready_event: threading.Event | None = None,
    log_file: Path | None = None,
):
    log_listener = setup_logging()
    if log_file is not None:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter("[%(threadName)s] %(message)s"))
        log_listener.handlers = (*log_listener.handlers, file_handler)
    log_listener.start()
    configure_logging(log_listener, settings.debug_logs, log_prefix)

    logger.info(
        f"Running with settings:"
        f"\n\t- frontend_origin={settings.frontend_origin}"
        f"\n\t- debug_logs={settings.debug_logs}"
        f"\n\t- port={settings.port}"
        f"\n\t- private_port={settings.private_port}"
    )

    auth_client = AuthClient(settings.auth_server_url)

    store_queue = start_storage_thread(
        db_file=str(settings.db_file),
        db_tables=DB_TABLES,
    )

    code_waiter = CodeWaiter(store_queue)

    private_handler = create_private_handler(
        store_queue,
        code_waiter,
        settings.frontend_origin,
        settings.smtp,
        settings.smtp_send,
        auth_client,
    )
    start_private_server(settings.private_port, private_handler, store_queue)

    def handler(req: Request, store_queue: StorageQueue | None) -> Response:
        return handler_with_client(
            auth_client,
            req,
            store_queue,
            settings.frontend_origin,
            settings.smtp,
            settings.smtp_send,
        )

    if ready_event is None:
        ready_event = threading.Event()

    threading.Thread(
        target=bootstrap_admin_on_startup,
        args=(ready_event, code_waiter, settings.auth_server_url, store_queue),
        daemon=True,
    ).start()

    start_outbox_dispatcher(
        store_queue,
        settings.frontend_origin,
        settings.smtp,
        settings.smtp_send,
        ready_event,
    )

    config = TcpServerConfig(port=settings.port)

    try:
        start_server(config, handler, store_queue=store_queue, ready_event=ready_event)
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        log_listener.stop()


def run():
    """Main entry point - parses args and runs with settings from env file."""
    args = parse_args()
    run_with_settings(load_settings_from_env(Path(args.env_file)))


def run_test():
    """Run only the Python backend with test environment settings."""
    run_with_settings(load_settings_from_env(Path("envs/test/.env")))


def run_demo():
    """Run with demo environment settings."""
    run_with_settings(load_settings_from_env(Path("envs/demo/.env")))


def run_production():
    """Run with production environment settings."""
    run_with_settings(load_settings_from_env(Path("envs/production/.env")))


if __name__ == "__main__":
    run()
