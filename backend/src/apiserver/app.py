from hfree import GetConn, Request, Response, ServerConfig, setup_logging, start_server


def handler(req: Request, get_conn: GetConn) -> Response:
    conn = get_conn()

    text = (
        f"Hello from dodeka!\n"
        f"Method: {req.method}\nPath: {req.path}\n"
        f"Body length: {len(req.body)} bytes\n"
    )

    return Response.text(text)


def run():
    listener = setup_logging()
    listener.start()

    config = ServerConfig(db_file="db.sqlite", db_tables=["USERS"])
    try:
        start_server(config, handler)
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        listener.stop()


if __name__ == "__main__":
    run()
