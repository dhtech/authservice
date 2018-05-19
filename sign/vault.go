package sign

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"time"

	pb "github.com/dhtech/proto/auth"
	vault "github.com/hashicorp/vault/api"
)

var (
	vaultSshMount     = flag.String("vault_ssh_mount", "ssh", "Mount point for the SSH signer in Vault")
	vaultTtl          = flag.String("vault_ttl", "20h", "Validity duration of short signed artifacts from Vault")
	vaultLongTtl      = flag.String("vault_long_ttl", "2160h", "Validity duration of long signed artifacts from Vault")
	vaultRenew        = flag.String("vault_renew", "24h", "How often to renew the token")
	vaultGroupMap     = flag.String("vault_group_map", "{}", "JSON group map from LDAP group DN to policy")
	vaultVmwareDomain = flag.String("vault_vmware_domain", "tech.dreamhack.se", "VMware uses AD UPNs in the format of ${user}@{$domain}, this is the domain part")
)

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

func (s *signer) signSsh(r *pb.UserCredentialRequest, u *pb.VerifiedUser, res *pb.CredentialResponse) (string, error) {
	kd := map[string]interface{}{
		"public_key": r.SshCertificateRequest.PublicKey,
		"valid_principals": u.Username,
		"ttl": *vaultTtl,
	}
	sk, err := s.v.SSHWithMountPoint(*vaultSshMount).SignKey("user", kd)
	if err != nil {
		log.Printf("failed to sign SSH key: %v", err)
		return "", fmt.Errorf("failed to sign SSH key")
	}
	res.SshCertificate = &pb.SshCertificate{
		Certificate: sk.Data["signed_key"].(string),
	}
	return "SSH certificate", nil
}

func (s *signer) signVault(r *pb.UserCredentialRequest, u *pb.VerifiedUser, res *pb.CredentialResponse) (string, error) {
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
		return "", fmt.Errorf("failed to create Vault token")
	}
	res.VaultToken = &pb.VaultToken{
		Token: sk.Auth.ClientToken,
	}
	return "Vault token", nil
}

func (s *signer) signBrowser(r *pb.UserCredentialRequest, u *pb.VerifiedUser, res *pb.CredentialResponse) (string, error) {
	data := map[string]interface{}{
		"csr": string(r.BrowserCertificateRequest.Csr),
		"ttl": *vaultLongTtl,
		"common_name": u.Username,
	}
	sk, err := s.v.Logical().Write("browser-pki/sign/user", data)
	if err != nil {
		log.Printf("failed to sign browser certificate: %v", err)
		return "", fmt.Errorf("failed to sign browser certificate")
	}
	res.BrowserCertificate.Certificate = sk.Data["certificate"].(string)
	return "Browser certificate", nil
}

func (s *signer) signVmware(r *pb.UserCredentialRequest, u *pb.VerifiedUser, res *pb.CredentialResponse) (string, error) {
	data := map[string]interface{}{
		"csr": string(r.VmwareCertificateRequest.Csr),
		"ttl": *vaultTtl,
		"common_name": u.Username,
		"other_sans": fmt.Sprintf("1.3.6.1.4.1.1;UTF8:%s@%s", u.Username, *vaultVmwareDomain),
	}
	sk, err := s.v.Logical().Write("vmware-pki/sign/user", data)
	if err != nil {
		log.Printf("failed to sign VMware certificate: %v", err)
		return "", fmt.Errorf("failed to sign VMware certificate")
	}
	res.VmwareCertificate.Certificate = sk.Data["certificate"].(string)
	return "VMware certificate", nil
}

func (s *signer) signKubernetes(r *pb.UserCredentialRequest, u *pb.VerifiedUser, res *pb.CredentialResponse) (string, error) {
	// TODO(bluecmd): Due to https://github.com/hashicorp/vault/issues/4562 we
	// are forced to create our own CSR here and give the key back to the user.
	keyb, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		return "", err
	}
	asnKey, err := x509.MarshalECPrivateKey(keyb)
	if err != nil {
		return "", err
	}
	keyPemBlob := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: asnKey})
	res.KubernetesCertificate = &pb.KubernetesCertificate{}
	res.KubernetesCertificate.PrivateKey = string(keyPemBlob)

	subj := pkix.Name{
		CommonName: u.Username,
		Organization: u.Group,
		OrganizationalUnit: []string{"Kubernetes"},
	}
	tmpl := x509.CertificateRequest{
		Subject: subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrb, _ := x509.CreateCertificateRequest(rand.Reader, &tmpl, keyb)
	pemBlob := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrb})
	data := map[string]interface{}{
		"csr": string(pemBlob),
		"ttl": *vaultTtl,
	}
	sk, err := s.v.Logical().Write("k8s-pki/sign-verbatim/user", data)
	if err != nil {
		log.Printf("failed to sign Kubernetes certificate: %v", err)
		return "", fmt.Errorf("failed to sign Kubernetes certificate")
	}
	res.KubernetesCertificate.Certificate = sk.Data["certificate"].(string)
	return "Kubernetes certificate", nil
}

func (s *signer)initVault() {
	v, err := vault.NewClient(nil)
	if err != nil {
		log.Fatalf("could not create Vault client: %v", err)
	}

	s.v = v

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
}
