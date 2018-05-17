package sign

import (
	"encoding/base64"
	"flag"
	"log"
	"os"
	"time"

	pb "github.com/dhtech/proto/auth"
	token "github.com/dhtech/authservice/sign/token"
)

var (
	tokenTtl        = flag.String("token_ttl", "20h", "Validity duration of signed cookies")
	tokenDomain     = flag.String("token_domain", "*.dreamhack.se", "Domain validity of signed cookies")
	tokenName       = flag.String("token_name", "dhtech-authservice", "Cookie name to store token")
	tokenGeneration = flag.Int("token_generation", 1, "Token generation for signed cookies (increase to invalidate all existing cookies)")
)

// Glue struct to fulfill the interface that Tink's Token library uses
type verifiedSession struct {
	u *pb.VerifiedUser
}

func (v *verifiedSession) User() string {
	return v.u.Username
}

func (v *verifiedSession) Domain() string {
	// TODO(bluecmd): If we need to we can change so that event/colo has different
	// domains to force login twice, but I don't see the need.
	return "dhtech"
}

func (v *verifiedSession) Groups() []string {
	return v.u.Group
}

func (s *signer) signBrowserCookie(r *pb.UserCredentialRequest, u *pb.VerifiedUser, res *pb.CredentialResponse) (string, error) {
	ttl, err := time.ParseDuration(*tokenTtl)
	if err != nil {
		log.Fatalf("unable to parse Token TTL")
	}

	cookie, err := s.t.Create(&verifiedSession{u})
	if err != nil {
		return "", err
	}

	// TTL is embedded in the cookie as well, so this is only a browser
	// recommendation to keep things tidy
	res.BrowserCookie.Expires = uint64(time.Now().Add(ttl).Unix())
	res.BrowserCookie.Name = *tokenName
	res.BrowserCookie.Domain = *tokenDomain
	res.BrowserCookie.Value = base64.URLEncoding.EncodeToString(cookie)

	return "browser cookie", nil
}

func (s *signer) initToken() {
	aesk, ok := os.LookupEnv("TOKEN_AES_KEY")
	if !ok {
		log.Fatalf("Missing mandatory environment variable TOKEN_AES_KEY")
	}
	eck, ok := os.LookupEnv("TOKEN_EC_KEY")
	if !ok {
		log.Fatalf("Missing mandatory environment variable TOKEN_EC_KEY")
	}

	aes, err := base64.StdEncoding.DecodeString(aesk)
	if err != nil {
		log.Fatalf("Unable to decode AES key: %s", err)
	}

	ec, err := base64.StdEncoding.DecodeString(eck)
	if err != nil {
		log.Fatalf("Unable to decode EC private key: %s", err)
	}

	ttl, err := time.ParseDuration(*tokenTtl)
	if err != nil {
		log.Fatalf("unable to parse Token TTL")
	}

	provider := token.NewSimpleProvider(*tokenGeneration, &token.RealTime)
	crypto := token.NewStdCrypto(aes)
	signer := token.NewEcdsaSigner(ec)
	s.t = token.NewMinter(ttl, crypto, signer, provider, &token.RealTime)
}
