package security

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRequestSigningAndValidation(t *testing.T) {
	signer := NewRequestSigner("test-key", []byte("secret"), []string{"Content-Type"})
	v := NewSignatureValidator(map[string][]byte{"test-key": []byte("secret")}, []string{"Content-Type"}, SignatureValidation{MaxClockSkew: 5 * time.Second})

	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("Content-Type", "application/json")

	err := signer.Sign(req)
	assert.NoError(t, err)

	err = v.Validate(req)
	assert.NoError(t, err)
}
