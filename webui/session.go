package webui

import (
	"fmt"
	"log"

	"github.com/dhtech/authservice/verify"
	pb "github.com/dhtech/proto/auth"
	"github.com/google/uuid"
)

type loginSession struct {
	p *webuiServer
	atq chan verify.Attempt
	eq chan error
	id string
	Ident string
}

type attempt struct {
	username string
	credential string
}

func (a *attempt) Username() string {
	return a.username
}

func (a *attempt) Credential() string {
	return a.credential
}

func (s *webuiServer) NewSession(r *pb.UserCredentialRequest, atq chan verify.Attempt, eq chan error) verify.Session {
	id := uuid.New().String()
	sess := &loginSession{
		Ident: r.ClientValidation.Ident,
		id: id,
		eq: eq,
		atq: atq,
		p: s,
	}
	s.sessionLock.Lock()
	s.sessions[id] = sess
	s.sessionLock.Unlock()
	return sess
}

func (s *loginSession) ChallengeLogin() *pb.UserAction {
	return &pb.UserAction{Url: fmt.Sprintf("/login?session=%s", s.id)}
}

func (s *loginSession) ChallengeReview() *pb.UserAction {
	return &pb.UserAction{Url: fmt.Sprintf("/details?session=%s", s.id)}
}

func (s *loginSession) ProcessLogin(username string, password string) error {
	select {
	case s.atq <- &attempt{username, password}:
		return <-s.eq
	default:
		return fmt.Errorf("Session is gone")
	}
}

func (s *loginSession) Destroy() {
	s.p.sessionLock.Lock()
	delete(s.p.sessions, s.id)
	s.p.sessionLock.Unlock()
	// Flush all error readers if there are any
	for {
		select {
		case s.eq <- fmt.Errorf("internal error: session destroyed"):
			continue
		default:
			break
		}
	}
	log.Printf("Cleaned up session %s", s.id)
}


