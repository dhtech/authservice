package webui

import (
	"fmt"
	"log"

	"github.com/dhtech/authservice/auth"
	"github.com/dhtech/authservice/verify"
	pb "github.com/dhtech/proto/auth"
	"github.com/google/uuid"
)

type loginSession struct {
	p *webuiServer
	// Structured attempt queue
	atq chan auth.Attempt
	// Redirect queue
	rq chan string
	// Attempt error queue
	eq chan error

	// On the first request this cookie is set to pin the session to a single
	// browser. Attempting to set this twice will fail.
	cookie string

	id string
	Request *pb.UserCredentialRequest
	NextUrl string
	Page string
	VerifiedUser *pb.VerifiedUser
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

func (s *webuiServer) NewSession(r *pb.UserCredentialRequest, atq chan auth.Attempt, eq chan error) verify.Session {
	id := uuid.New().String()
	rq := make(chan string, 0)
	sess := &loginSession{
		Request: r,
		NextUrl: fmt.Sprintf("/next?session=%s", id),
		id: id,
		eq: eq,
		atq: atq,
		rq: rq,
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

func (s *loginSession) ChallengeReview(u *pb.VerifiedUser) *pb.UserAction {
	s.VerifiedUser = u
	s.rq <- fmt.Sprintf("/review?session=%s", s.id)
	return nil
}

func (s *loginSession) ChallengeComplete(c *pb.BrowserCookie) *pb.UserAction {
	s.rq <- "/complete"
	return nil
}

func (s *loginSession) sendAttempt(a *attempt) error {
	select {
	case s.atq <- a:
		return <-s.eq
	default:
		return fmt.Errorf("Session is gone")
	}

}

func (s *loginSession) ProcessLogin(username string, password string) error {
	return s.sendAttempt(&attempt{username, password})
}

func (s *loginSession) ProcessReview() error {
	return s.sendAttempt(&attempt{})
}

func (s *loginSession) NextStep() string {
	return <-s.rq
}

func (s *loginSession) Cookie() (string, error) {
	if (s.cookie != "") {
		return "", fmt.Errorf("cookie already set")
	}
	s.cookie = uuid.New().String()
	return s.cookie, nil
}

func (s *loginSession) VerifyCookie(c string) bool {
	return s.cookie == c && s.cookie != ""
}

func (s *loginSession) Destroy() {
	s.p.sessionLock.Lock()
	delete(s.p.sessions, s.id)
	s.p.sessionLock.Unlock()
	close(s.rq)
	log.Printf("Cleaned up session %s", s.id)
}
