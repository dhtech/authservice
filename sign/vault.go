package sign

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	pb "github.com/dhtech/proto/auth"
	vault "github.com/hashicorp/vault/api"
)

var (
	vaultSshMount = flag.String("vault_ssh_mount", "ssh", "Mount point for the SSH signer in Vault")
	vaultTtl      = flag.String("vault_ttl", "20h", "Validity duration of signed artificats from Vault")
	vaultRenew    = flag.String("vault_renew", "24h", "How often to renew the token")
	vaultGroupMap = flag.String("vault_group_map", "{}", "JSON group map from LDAP group DN to policy")
)

type Auditor interface {
	Log(string)
}

type signer struct {
	a Auditor
	v *vault.Client
	gmap map[string]string
}

func (s *signer) renewer() {
	d, err := time.ParseDuration(*vaultRenew)
	if err != nil {
		log.Fatalf("unable to parse Vault renew interval")
	}
	log.Printf("Bumping Vault token TTL")
	_, err = s.v.Auth().Token().RenewSelf(int(d.Seconds() * 5))
	if err != nil {
		log.Printf("WARNING: unable to renew Vault token: %v", err)
	}

	renewTicker := time.NewTicker(d)

	for {
		select {
		case <-renewTicker.C:
			log.Printf("Renewing Vault token")
			_, err := s.v.Auth().Token().RenewSelf(int(d.Seconds() * 5))
			if err != nil {
				log.Printf("WARNING: unable to renew Vault token: %v", err)
			}
		}
	}
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

	if r.VaultTokenRequest != nil {
		policies := make([]string, 0)
		for _, group := range u.Group {
			p, ok := s.gmap[group]
			if !ok {
				continue
			}
			policies = append(policies, p)
		}
		log.Printf("Creating Vault token for %s with policies %v", u.Username, policies)

		tcr := &vault.TokenCreateRequest{
			Metadata: map[string]string{"username": u.Username},
			TTL: *vaultTtl,
			Policies: policies,
		}
		sk, err := s.v.Auth().Token().CreateWithRole(tcr, "user")
		if err != nil {
			log.Printf("failed to create Vault token: %v", err)
			return nil, fmt.Errorf("failed to create Vault token")
		}
		res.VaultToken = &pb.VaultToken{
			Token: sk.Auth.ClientToken,
		}
		artifacts = append(artifacts, "Vault token")
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
	s.gmap = make(map[string]string)
	var j interface{}
	err = json.Unmarshal([]byte(*vaultGroupMap), &j)
	if err != nil {
		log.Fatalf("could not parse Vault group map: %v", err)
	}
	for k, v := range j.(map[string]interface{}) {
		s.gmap[k] = v.(string)
	}
	go s.renewer()
	return s
}
