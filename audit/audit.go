package audit

import (
	"flag"
	"fmt"
	"log"
	"net"
)

var (
	auditProtocol = flag.String("audit_protocol", "udp", "Protocol to send audit event over")
	auditHost     = flag.String("audit_host", "", "Host:port to send the audit logs to")
)

type auditor struct {

}

func (a *auditor) Log(msg string) {
	log.Printf("Audit: %s", msg)
	if (*auditHost != "") {
		c, err := net.Dial(*auditProtocol, *auditHost)
		if err != nil {
			log.Printf("failed to dial audit receiver: %v", err)
			return
		}
		defer c.Close()
		c.Write([]byte(fmt.Sprintf("authserver: %s", msg)))
	}
}

func New() *auditor {
	a := &auditor{}
	return a
}
