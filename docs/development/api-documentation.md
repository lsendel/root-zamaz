# Interactive API Documentation

This guide explains how to view and regenerate the interactive API documentation for the Zero Trust Authentication API.

## Viewing the Documentation

Run the server in development mode and open the Swagger UI in your browser:

```
make dev-up
# in another terminal
make dev-frontend
```

Once the services are running, navigate to:

```
http://localhost:8080/swagger/index.html
```

The Swagger UI provides an interactive interface to explore and test the API endpoints.

## Regenerating the Swagger Spec

API documentation is generated from source code comments using `swag`. To regenerate the OpenAPI specification:

```
make swag
```

This command runs `swag init` and updates the files in the `docs` package that are served by the Swagger UI.

