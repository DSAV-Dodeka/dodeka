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
    accept_new_sync_handler,
    accept_user_handler,
    add_user_permission,
    available_permissions_handler,
    import_sync_handler,
    list_newusers_handler,
    list_system_users_handler,
    list_users_handler,
    remove_departed_handler,
    remove_user_permission,
    set_permissions_handler,
    sync_status_handler,
    update_existing_handler,
)
from apiserver.handlers.auth import (
    clear_session,
    get_registration_status_handler,
    get_session_token_handler,
    lookup_registration_handler,
    renew_signup_handler,
    request_registration,
    resend_signup_email_handler,
    session_info,
    set_session,
)
from apiserver.handlers.features.birthdays import birthdays_handler
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
    """
    This function dispatches a request to a specific handler, based on the route. It
    also handles things like CORS (browsers are careful when making requests that are
    not the same 'origin', so different domain)
    """
    if store_queue is None:
        logger.error("Storage not available")
        return Response.text("Storage not available", status_code=500)

    # Strip query string for route lookup (handlers can access full path via req.path)
    path = urlparse(req.path).path
    method = req.method

    # Parse headers once for reuse in handlers
    headers = parse_headers(req.headers)
    if isinstance(headers, InvalidHeaders):
        return Response.text("Invalid headers", status_code=400)

    def h_request_registration():
        return request_registration(auth_client, req, store_queue)

    def h_set_sess():
        return set_session(
            auth_client,
            req,
            headers,
            store_queue,
            smtp_config,
            smtp_send,
            frontend_origin,
        )

    def h_clear_sess():
        return clear_session(req, headers)

    def h_sess_info():
        return session_info(auth_client, req, headers, store_queue)

    def h_add_perm():
        return add_user_permission(req, store_queue)

    def h_remove_perm():
        return remove_user_permission(req, store_queue)

    def h_list_newusers():
        return list_newusers_handler(store_queue)

    def h_accept_user():
        return accept_user_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_get_reg_status():
        return get_registration_status_handler(req, store_queue)

    def h_lookup_registration():
        return lookup_registration_handler(req, store_queue)

    def h_get_sess_token():
        return get_session_token_handler(headers)

    def h_resend_signup_email():
        return resend_signup_email_handler(auth_client, req, store_queue)

    def h_renew_signup():
        return renew_signup_handler(auth_client, req, store_queue)

    def h_list_users():
        return list_users_handler(store_queue)

    def h_available_permissions():
        return available_permissions_handler()

    def h_set_permissions():
        return set_permissions_handler(req, store_queue)

    # Sync route handlers
    def h_import_sync():
        return import_sync_handler(req, store_queue)

    def h_sync_status():
        return sync_status_handler(store_queue)

    def h_accept_new_sync():
        return accept_new_sync_handler(
            req, store_queue, frontend_origin, smtp_config, smtp_send
        )

    def h_remove_departed():
        return remove_departed_handler(req, store_queue)

    def h_update_existing():
        return update_existing_handler(req, store_queue)

    def h_list_system_users():
        return list_system_users_handler(store_queue)

    def h_birthdays():
        return birthdays_handler(store_queue)

    # This table maps each route to a specific handler (the RouteEntry)
    route_table = {
        # Dodeka-specific actions related to auth
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
        # We prefix the next with 'admin' to make it clear it's only accessible to
        # admins
        "/admin/accept_user/": {
            "POST": RouteEntry(h_accept_user, PermissionConfig.require("admin"))
        },
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
        "/admin/list_newusers/": {
            "GET": RouteEntry(h_list_newusers, PermissionConfig.require("admin"))
        },
        "/admin/resend_signup_email/": {
            "POST": RouteEntry(h_resend_signup_email, PermissionConfig.require("admin"))
        },
        # Sync operations
        "/admin/import_sync/": {
            "POST": RouteEntry(h_import_sync, PermissionConfig.require("admin"))
        },
        "/admin/sync_status/": {
            "GET": RouteEntry(h_sync_status, PermissionConfig.require("admin"))
        },
        "/admin/accept_new_sync/": {
            "POST": RouteEntry(h_accept_new_sync, PermissionConfig.require("admin"))
        },
        "/admin/remove_departed/": {
            "POST": RouteEntry(h_remove_departed, PermissionConfig.require("admin"))
        },
        "/admin/update_existing/": {
            "POST": RouteEntry(h_update_existing, PermissionConfig.require("admin"))
        },
        "/admin/list_system_users/": {
            "GET": RouteEntry(h_list_system_users, PermissionConfig.require("admin"))
        },
        # Member routes
        "/members/birthdays/": {
            "GET": RouteEntry(h_birthdays, PermissionConfig.require("member"))
        },
        "/auth/session_info/": {
            "GET": RouteEntry(
                h_sess_info, PermissionConfig.public(), requires_credentials=True
            )
        },
        # Since we have HttpOnly cookies, we need server functions to modify them
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
        """Add CORS headers to any response."""
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

    # In order to get a useful method when the method is OPTIONS is sent for many other
    # methods in a so-called pre-flight request during CORS), we get this special header
    if method == "OPTIONS":
        requested_method = headers.get("access-control-request-method")
    else:
        requested_method = method

    # We can now get a route_entry, or just set it to none and then return not found
    route_entry = None if requested_method is None else route.get(requested_method)
    if route_entry is None:
        logger.info(f"Method not supported: {method} {path}")
        return add_cors(Response.text(f"Not Found: {method} {path}", status_code=404))

    credentials = route_entry.needs_credentials()

    # Handle OPTIONS preflight for CORS (before auth - preflight has no cookies)
    if method == "OPTIONS":
        return handle_options_request(route, route_entry, frontend_origin)

    # CSRF protection (Filippo Valsorda's algorithm)
    csrf = check_csrf(method, headers, [frontend_origin])
    if csrf is not None:
        logger.warning(f"CSRF rejected: {method} {path} ({csrf.reason})")
        return add_cors(Response.text("Cross-origin request blocked", status_code=403))

    # Check access (permissions, etc.)
    if error := check_access(
        RouteData(entry=route_entry, method=method, path=path),
        headers,
        auth_client,
        store_queue,
    ):
        return add_cors(error, credentials)

    # It's only here the actual handler is called
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
    """Configure log level and optional prefix on the listener's handlers."""
    log_level = logging.DEBUG if debug_logs else logging.INFO
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    for h in root_logger.handlers:
        h.setLevel(log_level)

    # Set prefix on the QueueListener's console handler (not the QueueHandler).
    # Setting it on the QueueHandler would bake the prefix into the message
    # before the console handler adds [threadName], producing
    # "[Thread-1] [backend] msg" instead of the desired "[backend] [Thread-1] msg".
    if log_prefix:
        for h in log_listener.handlers:
            h.setFormatter(PrefixFormatter(log_prefix, h.formatter))


def run_with_settings(
    settings: Settings,
    *,
    log_prefix: str = "",
    ready_event: threading.Event | None = None,
):
    log_listener = setup_logging()
    log_listener.start()
    configure_logging(log_listener, settings.debug_logs, log_prefix)

    logger.info(
        f"Running with settings:\n\t- frontend_origin={settings.frontend_origin}"
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

    # Start private TCP server on 127.0.0.2 (Go and CLI connect to this)
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
