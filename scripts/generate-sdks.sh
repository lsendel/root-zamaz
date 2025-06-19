#!/usr/bin/env bash
set -e

OPENAPI_FILE=${OPENAPI_FILE:-docs/swagger.yaml}
OUTPUT_DIR=${OUTPUT_DIR:-sdk}

LANGS=(go python javascript)

for lang in "${LANGS[@]}"; do
  echo "Generating $lang SDK..."
  docker run --rm -v "$(pwd):/local" openapitools/openapi-generator-cli generate \
    -i "/local/$OPENAPI_FILE" -g "$lang" -o "/local/$OUTPUT_DIR/$lang"
done

echo "SDKs generated in $OUTPUT_DIR/"
