package sign

import (
	"flag"
	"fmt"
	"log"
	"strings"

	pb "github.com/dhtech/proto/auth"
	vault "github.com/hashicorp/vault/api"
)

var (
	vaultSshMount = flag.String("vault_ssh_mount", "ssh", "Mount point for the SSH signer in Vault")
	vaultTtl      = flag.String("vault_ttl", "20h", "Validity duration of signed artificats from Vault")
)

type Auditor interface {
	Log(string)
}

type signer struct {
	a Auditor
	v *vault.Client
}

func (s *signer) Sign(r *pb.UserCredentialRequest, u *pb.VerifiedUser) (*pb.CredentialResponse, error) {
	res := &pb.CredentialResponse{}
	
	artifacts := make([]string, 0)
	if r.SshCertificateRequest != nil {
		kd := map[string]interface{}{
			"public_key": r.SshCertificateRequest.PublicKey,
			"valid_principals": u.Username,
			"ttl": *vaultTtl,
		}
		sk, err := s.v.SSHWithMountPoint(*vaultSshMount).SignKey("user", kd)
		if err != nil {
			log.Printf("failed to sign SSH key: %v", err)
			return nil, fmt.Errorf("failed to sign SSH key")
		}
		res.SshCertificate = &pb.SshCertificate{
			Certificate: sk.Data["signed_key"].(string),
		}
		artifacts = append(artifacts, "SSH certificate")
	}

	s.a.Log(fmt.Sprintf("signed %s for %s", strings.Join(artifacts, ", "), u.Username))
	return res, nil
}

func New(a Auditor) *signer {
	v, err := vault.NewClient(nil)
	if err != nil {
		log.Fatalf("could not create Vault client: %v", err)
	}
	s := &signer{
		a: a,
		v: v,
	}
	return s
}
