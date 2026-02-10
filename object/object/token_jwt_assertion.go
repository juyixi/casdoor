// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// ClientAssertionClaims represents the JWT claims for private_key_jwt client authentication (RFC 7523)
type ClientAssertionClaims struct {
	jwt.RegisteredClaims
}

const (
	ClientAssertionTypeJWT = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
)

// ValidateClientAssertion validates a JWT client assertion according to RFC 7523
// Returns the client_id if validation succeeds, error otherwise
func ValidateClientAssertion(clientAssertion string, clientAssertionType string, expectedAudience string) (string, error) {
	// Validate assertion type per RFC 7521 section 4.2
	if clientAssertionType != ClientAssertionTypeJWT {
		return "", fmt.Errorf("invalid client_assertion_type: expected %s, got %s", ClientAssertionTypeJWT, clientAssertionType)
	}

	// Parse the JWT without verification to extract the client_id (issuer)
	token, _, err := new(jwt.Parser).ParseUnverified(clientAssertion, &ClientAssertionClaims{})
	if err != nil {
		return "", fmt.Errorf("failed to parse client assertion: %w", err)
	}

	claims, ok := token.Claims.(*ClientAssertionClaims)
	if !ok {
		return "", fmt.Errorf("invalid client assertion claims")
	}

	// RFC 7523 Section 3: iss (issuer) and sub (subject) MUST be the client_id
	if claims.Issuer == "" {
		return "", fmt.Errorf("client assertion missing 'iss' claim")
	}
	if claims.Subject == "" {
		return "", fmt.Errorf("client assertion missing 'sub' claim")
	}
	if claims.Issuer != claims.Subject {
		return "", fmt.Errorf("client assertion 'iss' and 'sub' must be equal (both should be client_id)")
	}

	clientId := claims.Issuer

	// Get the application to retrieve its certificate for verification
	application, err := GetApplicationByClientId(clientId)
	if err != nil {
		return "", fmt.Errorf("failed to get application: %w", err)
	}
	if application == nil {
		return "", fmt.Errorf("application not found for client_id: %s", clientId)
	}

	// Get the certificate associated with this application
	cert, err := getCertByApplication(application)
	if err != nil {
		return "", fmt.Errorf("failed to get certificate: %w", err)
	}
	if cert == nil {
		return "", fmt.Errorf("no certificate configured for application: %s", application.Name)
	}

	// Parse and verify the JWT using the application's public certificate
	publicKey, err := parsePublicKeyFromCert(cert)
	if err != nil {
		return "", fmt.Errorf("failed to parse public key from certificate: %w", err)
	}

	// Parse and validate the token with the public key
	parsedToken, err := jwt.ParseWithClaims(clientAssertion, &ClientAssertionClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		switch token.Method.(type) {
		case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA, *jwt.SigningMethodRSAPSS, *jwt.SigningMethodEd25519:
			return publicKey, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		return "", fmt.Errorf("failed to verify client assertion signature: %w", err)
	}

	validatedClaims, ok := parsedToken.Claims.(*ClientAssertionClaims)
	if !ok || !parsedToken.Valid {
		return "", fmt.Errorf("invalid client assertion token")
	}

	// RFC 7523 Section 3: aud (audience) MUST be the token endpoint URL
	if len(validatedClaims.Audience) == 0 {
		return "", fmt.Errorf("client assertion missing 'aud' claim")
	}

	// Check if expected audience is in the audience list
	audienceValid := false
	for _, aud := range validatedClaims.Audience {
		if aud == expectedAudience {
			audienceValid = true
			break
		}
	}
	if !audienceValid {
		return "", fmt.Errorf("client assertion 'aud' claim does not match expected audience")
	}

	// RFC 7523 Section 3: exp (expiration) MUST be present and in the future
	if validatedClaims.ExpiresAt == nil {
		return "", fmt.Errorf("client assertion missing 'exp' claim")
	}
	if time.Now().After(validatedClaims.ExpiresAt.Time) {
		return "", fmt.Errorf("client assertion has expired")
	}

	// RFC 7523 Section 3: jti (JWT ID) SHOULD be present for replay protection
	// Note: Full replay protection requires storing used jti values in a cache/database
	// until the JWT expires. This implementation validates presence but doesn't track usage.
	// For production deployments, consider implementing jti tracking using Redis or similar.
	if validatedClaims.ID == "" {
		return "", fmt.Errorf("client assertion missing 'jti' claim (required for replay protection)")
	}

	return clientId, nil
}

// parsePublicKeyFromCert extracts the public key from a certificate
func parsePublicKeyFromCert(cert *Cert) (interface{}, error) {
	if cert.Certificate == "" {
		return nil, fmt.Errorf("certificate is empty")
	}

	// Try to parse as PEM-encoded certificate
	block, _ := pem.Decode([]byte(cert.Certificate))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	// Try to parse as X.509 certificate first
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		// Successfully parsed as certificate, return public key
		return x509Cert.PublicKey, nil
	}

	// If not a certificate, try to parse as public key directly
	switch block.Type {
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported certificate/key type: %s", block.Type)
	}
}
