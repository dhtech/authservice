package auth

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	
	ldap "gopkg.in/ldap.v2"
)

var (
	ldapServer     = flag.String("ldap_server", "ldap.change.the.flag:0", "What LDAP server and port to use")
	ldapTls        = flag.Bool("ldap_tls", true, "Whether or not to use TLS to connect to LDAP")
	ldapBind       = flag.String("ldap_bind", "uid=%s,dc=dummy", "DN format to use when binding with a login attempt")
	ldapServerName = flag.String("ldap_server_name", "", "Override LDAP server name used for TLS verification")
	ldapBase       = flag.String("ldap_base", "dc=dummy", "What LDAP base to use for the group search")
)

type ldapAuth struct {
}

func (l *ldapAuth) Verify(a Attempt) ([]string, error) {
	c := newLdapConnection()
	if c == nil {
		return []string{}, fmt.Errorf("LDAP unavailable")
	}

	dn := fmt.Sprintf(*ldapBind, a.Username())
	err := c.Bind(dn, a.Credential())
	if err != nil {
		log.Printf("failed to bind: %v", err)
		return []string{}, err
	}

	return l.resolve(dn, c)
}

func (l *ldapAuth) resolve(dn string, c *ldap.Conn) ([]string, error) {

	// Login succeeded, get groups.
	// We're using RFC2307bis, so doing a search for our DN should be easy enough.
	sreq := ldap.NewSearchRequest(
		*ldapBase, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(member=%s)", dn), []string{"dn"}, nil)

	sr, err := c.Search(sreq)
	if err != nil {
		log.Printf("failed to execute group search: %v", err)
		return []string{}, err
	}

	groups := make([]string, 0)
	for _, entry := range sr.Entries {
		recurse, err := l.resolve(entry.DN, c)
		if err != nil {
			return nil, err
		}
		groups = append(groups, entry.DN)
		groups = append(groups, recurse...)
	}
	return groups, nil
}

func newLdapConnection() *ldap.Conn {
	var conn *ldap.Conn
	var err error

	if *ldapTls {
		tc := &tls.Config{}
		if *ldapServerName != "" {
			tc.ServerName = *ldapServerName
		}
		conn, err = ldap.DialTLS("tcp", *ldapServer, tc)
	} else {
		conn, err = ldap.Dial("tcp", *ldapServer)
	}
	if err != nil {
		log.Printf("failed to connect to LDAP: %v", err)
		return nil
	}
	return conn
}

func NewLdap() *ldapAuth {
	l := &ldapAuth{}
	return l
}
