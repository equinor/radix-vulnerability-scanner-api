package auth

import (
	"context"
	"log"

	"github.com/coreos/go-oidc/v3/oidc"
)

// AuthProvider interface
type AuthProvider interface {
	VerifyToken(ctx context.Context, token string) (IDToken, error)
}

// IDToken interface
type IDToken interface {
	GetClaims(out interface{}) error
}

type oidcProvider struct {
	verifier *oidc.IDTokenVerifier
}

// IDTokenStruct instance variables
type IDTokenStruct struct {
	token *oidc.IDToken
}

type Claims struct {
	Groups []string `json:"groups"`
	Email  string   `json:"email"`
}

// GetClaims returns claims for the token
func (it *IDTokenStruct) GetClaims(out interface{}) error {
	err := it.token.Claims(out)
	if err != nil {
		return err
	}

	return nil
}

// VerifyToken verifies the provided IDToken
func (p *oidcProvider) VerifyToken(ctx context.Context, token string) (IDToken, error) {
	idToken, err := p.verifier.Verify(ctx, token)

	if err != nil {
		return nil, err
	}

	return &IDTokenStruct{
		token: idToken,
	}, nil
}

// NewAuthProvider creates a new auth provider
func NewAuthProvider(ctx context.Context, issuer, audience string) AuthProvider {
	verifier := getTokenVerifier(ctx, issuer, audience)
	return &oidcProvider{
		verifier: verifier,
	}
}

func getTokenVerifier(ctx context.Context, issuer, audience string) *oidc.IDTokenVerifier {

	provider, err := oidc.NewProvider(ctx, issuer)

	if err != nil {
		log.Fatal(err)
	}

	oidcConfig := &oidc.Config{
		ClientID: audience,
	}

	return provider.Verifier(oidcConfig)
}
