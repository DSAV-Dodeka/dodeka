# Socket Refactor Design

## Full Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                  Clients                                    │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
            ▼                       ▼                       ▼
   HTTP: Auth Actions        HTTP: Session/Cookies    HTTP: App Routes
   (signup, signin,          (set_session,            (admin/*, auth/*,
    verify, password)         clear_session,           registration)
            │                 session_info)                 │
            ▼                       │                       │
   ┌─────────────┐                  │                       │
   │ Go (tiauth) │                  │                       │
   └──────┬──────┘                  │                       │
          │                         │                       │
          │ Unix Socket             │                       │
          │ (user CRUD,             │                       │
          │  notifications)         │                       │
          │                         │                       │
          ▼                         ▼                       ▼
   ┌─────────────────────────────────────────────────────────────────────────┐
   │                           Python Backend                                 │
   │                                                                          │
   │   SQLite: users, newusers, registration_state, session_cache, metadata  │
   └─────────────────────────────────────────────────────────────────────────┘
```

**Client → Go**: Auth actions only (signup, signin, verify_email, set_password, etc.)
**Client → Python**: Everything else (sessions, cookies, admin operations, registration)
**Go → Python**: User CRUD (when auth actions need to store/retrieve users) + notifications

## Current State (What Changes)

```
Go ─── HTTP /private/invoke_user_action ───► Python   (becomes socket)
Go ─── Socket (Go listens) ────────────────► Python   (direction flips)
Python ─── HTTP to self ───────────────────► Python   (becomes direct DB calls)
```

Problems:
- Private route access key complexity
- Python calling its own HTTP routes for bootstrap
- Two communication channels between Go and Python

## Proposed Design

```
Go ─── Unix Socket (Python listens) ───► Python
       - User action requests (synchronous)
       - Token notifications (one-way)
```

Single bidirectional socket. Python is the server, Go is the client.

## Python Routes (unchanged, HTTP)

These routes are called directly by clients and stay as HTTP:

| Route | Purpose |
|-------|---------|
| `/cookies/set_session/` | Store session token in HttpOnly cookie |
| `/cookies/clear_session/` | Clear session cookie |
| `/cookies/session_token/` | Get session token from cookie |
| `/auth/session_info/` | Get current user info from session |
| `/auth/request_registration` | Start registration flow (creates newuser) |
| `/auth/registration_status` | Check registration status |
| `/admin/list_newusers/` | List pending registrations |
| `/admin/accept_user/` | Accept user and initiate Faroe signup |
| `/admin/add_permission/` | Add permission to user |
| `/admin/remove_permission/` | Remove permission from user |

## Protocol

Length-prefixed messages. Each message is:
```
[4 bytes: length (big-endian uint32)] [length bytes: JSON payload]
```

### Notifications (Go → Python, no response)

```json
{"type":"notification","action":"signup_verification","email":"user@example.com","code":"123456"}
```

Python stores these for the message reader (used in bootstrap/testing).

### User Action Requests (Go → Python, synchronous)

Request:
```json
{"action":"create_user","arguments":{"action_invocation_id":"xyz","email_address":"user@example.com",...}}
```

Response:
```json
{"ok":true,"action_invocation_id":"xyz","values":{"user":{"id":"1_user",...}}}
```

Go sends request, blocks until response arrives. No request IDs needed.

### Message Routing

Python reads length + payload:
- Has `"type":"notification"` → store in messages list, no response
- Otherwise → user action request, process and respond

## Go Changes

### Delete TokenBroadcaster

Replace with a simple client that connects to Python's socket.

### New SocketClient

```go
// socket_client.go

type SocketClient struct {
    socketPath string
    conn       net.Conn
    mu         sync.Mutex
}

func NewSocketClient(socketPath string) *SocketClient {
    return &SocketClient{socketPath: socketPath}
}

func (c *SocketClient) Connect() error {
    conn, err := net.Dial("unix", c.socketPath)
    if err != nil {
        return err
    }
    c.conn = conn
    return nil
}

func (c *SocketClient) writeMessage(data []byte) error {
    length := make([]byte, 4)
    binary.BigEndian.PutUint32(length, uint32(len(data)))
    if _, err := c.conn.Write(length); err != nil {
        return err
    }
    _, err := c.conn.Write(data)
    return err
}

func (c *SocketClient) readMessage() ([]byte, error) {
    length := make([]byte, 4)
    if _, err := io.ReadFull(c.conn, length); err != nil {
        return nil, err
    }
    size := binary.BigEndian.Uint32(length)
    data := make([]byte, size)
    if _, err := io.ReadFull(c.conn, data); err != nil {
        return nil, err
    }
    return data, nil
}

// SendNotification sends a one-way notification (no response expected)
func (c *SocketClient) SendNotification(msg map[string]string) error {
    c.mu.Lock()
    defer c.mu.Unlock()
    data, _ := json.Marshal(msg)
    return c.writeMessage(data)
}

// SendRequest sends a request and waits for response
func (c *SocketClient) SendRequest(body string) (string, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if err := c.writeMessage([]byte(body)); err != nil {
        return "", err
    }
    response, err := c.readMessage()
    if err != nil {
        return "", err
    }
    return string(response), nil
}

func (c *SocketClient) BroadcastSignupVerification(email, code string) {
    c.SendNotification(map[string]string{
        "type":   "notification",
        "action": "signup_verification",
        "email":  email,
        "code":   code,
    })
}
```

### Modify userActionInvocationClientStruct

```go
// user_endpoint.go

type userActionInvocationClientStruct struct {
    socketClient *SocketClient
}

func newUserActionInvocationClient(socketClient *SocketClient) *userActionInvocationClientStruct {
    return &userActionInvocationClientStruct{socketClient: socketClient}
}

func (c *userActionInvocationClientStruct) SendActionInvocationEndpointRequest(body string) (string, error) {
    return c.socketClient.SendRequest(body)
}
```

### Config Changes

```go
// config.go

// Replace:
//   TokenSocketPath string
//   UserActionInvocationURL string
//   PrivateRouteKeyFile string
// With:
SocketPath string  // e.g., "./auth/socket.sock"
```

Remove `FAROE_USER_ACTION_INVOCATION_URL`, `FAROE_PRIVATE_ROUTE_KEY_FILE`, `FAROE_TOKEN_SOCKET_PATH`.
Add `FAROE_SOCKET_PATH`.

## Python Changes

### SocketServer Class

```python
# apiserver/socket_server.py

class SocketServer:
    def __init__(
        self,
        socket_path: Path,
        store_queue: StorageQueue,
        messages: list[dict],
        condition: threading.Condition,
    ):
        self.socket_path = socket_path
        self.store_queue = store_queue
        self.messages = messages
        self.condition = condition
        self._socket: socket.socket | None = None

    def start(self) -> None:
        if self.socket_path.exists():
            self.socket_path.unlink()

        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(self.socket_path))
        self._socket.listen(1)

        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while True:
            conn, _ = self._socket.accept()
            threading.Thread(target=self._handle_connection, args=(conn,), daemon=True).start()

    def _recv_exact(self, conn: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data

    def _read_message(self, conn: socket.socket) -> bytes:
        length_bytes = self._recv_exact(conn, 4)
        length = int.from_bytes(length_bytes, "big")
        return self._recv_exact(conn, length)

    def _send_message(self, conn: socket.socket, data: bytes) -> None:
        conn.sendall(len(data).to_bytes(4, "big") + data)

    def _handle_connection(self, conn: socket.socket) -> None:
        try:
            while True:
                data = self._read_message(conn)
                msg = json.loads(data.decode("utf-8"))

                if msg.get("type") == "notification":
                    with self.condition:
                        self.messages.append(msg)
                        self.condition.notify_all()
                else:
                    response = self._execute_action(msg)
                    self._send_message(conn, json.dumps(response).encode("utf-8"))
        except ConnectionError:
            pass
        finally:
            conn.close()

    def _execute_action(self, request: dict) -> dict:
        def execute(store: Storage) -> str:
            server = SqliteSyncServer(store)
            result = handle_request_sync(request, server)
            return result.response_json

        response_json = self.store_queue.execute(execute)
        return json.loads(response_json)
```

### Remove from app.py

1. Delete private route handlers:
   - `/private/invoke_user_action`
   - `/private/clear_tables`
   - `/private/prepare_user`
   - `/private/add_admin_permission/`
   - `/private/delete_user/`

2. Delete access key infrastructure:
   - `private_route_access_key` generation
   - `private_route_access_file` setting
   - `x-private-route-access-key` header checking

3. Modify bootstrap to call DB functions directly (no HTTP self-calls)

### Settings Changes

```python
# settings.py

# Replace:
#   code_socket_path: Path
#   private_route_access_file: Path
# With:
socket_path: Path = Path("./auth/socket.sock")
```

### Startup Flow

Using freetser 0.2.0's `start_storage_thread` to get `store_queue` before starting HTTP server:

```python
from freetser import start_storage_thread, start_server, ServerConfig

def run_with_settings(settings: Settings):
    # Create shared state for messages
    messages: list[dict] = []
    condition = threading.Condition()
    message_reader = MessageReader(messages, condition)

    # Start storage thread first (freetser 0.2.0)
    store_queue = start_storage_thread(
        db_file=str(settings.db_file),
        db_tables=["users", "users_by_email", "newusers", "registration_state", "metadata", "session_cache"],
    )

    # Start socket server (now we have store_queue)
    socket_server = SocketServer(settings.socket_path, store_queue, messages, condition)
    socket_server.start()

    # Start HTTP server (pass existing store_queue)
    config = ServerConfig(port=settings.port)
    start_server(config, handler, store_queue=store_queue)
```

## Deployment

Single config value: socket path (e.g., `./auth/socket.sock`)

Works the same in dev, demo, and prod.

### Startup Order

1. Python: `start_storage_thread()` → `SocketServer.start()` → `start_server()`
2. Go: retry socket connection until Python is ready
3. Go connects, system is operational

## What Gets Removed

### Go
- `TokenBroadcaster` (entire file)
- HTTP client code in `user_endpoint.go`
- Private route key file reading
- `UserActionInvocationURL` config

### Python
- All `/private/*` routes
- `private_route_access_key` generation
- `private_route_access_file` setting
- `check_access` private key logic
- `AppClient` HTTP calls to self
- `start_socket_reader` (notifications now via SocketServer)

## Implementation Order

1. **Python**: Add `SocketServer`, keep HTTP routes working
2. **Go**: Add `SocketClient`, switch user actions to socket
3. **Test**: Verify user actions work over socket
4. **Go**: Switch notifications to socket, delete `TokenBroadcaster`
5. **Python**: Delete `start_socket_reader` (notifications now come through SocketServer)
6. **Python**: Remove HTTP private routes
7. **Python**: Simplify bootstrap (direct DB calls)
