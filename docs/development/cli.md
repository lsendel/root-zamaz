# Developer CLI

The `mvpctl` command-line tool allows developers to interact with the Zero Trust Auth API.

## Building

```bash
go build -o mvpctl ./cmd/cli
```

## Examples

```bash
# Login and get tokens
./mvpctl login -u admin -p password

# Register a new user
./mvpctl register -u alice -e alice@example.com -p secret

# Inspect the current user
./mvpctl whoami -t <access-token>
```

The API base URL can be changed with the `--api` flag.
