# SDK Generation

Client SDKs can be generated from the OpenAPI specification using the provided script.

```bash
./scripts/generate-sdks.sh
```

The script uses the `openapitools/openapi-generator-cli` Docker image to create Go, Python and JavaScript SDKs under the `sdk/` directory.
