package verify

import (
	"flag"
	"fmt"
	"log"
	"time"

	pb "github.com/dhtech/proto/auth"
)

var (
	verifyTimeout = flag.Int("verify_timeout", 600, "Seconds before a verify attempt times out.")
)

type Attempt interface {
	// Only used for username/password auth
	Username() string
	// Used for password/OTP/U2F
	Credential() string
}

type Session interface {
	// A request for username/password
	ChallengeLogin() *pb.UserAction

	// A request for the user to acknowledge the credentials being minted
	ChallengeReview(*pb.VerifiedUser) *pb.UserAction

	// The final screen showing something nice to the user prompting to close
	// the window.
	ChallengeComplete() *pb.UserAction

	Destroy()
}

type SessionServer interface {
	NewSession(*pb.UserCredentialRequest, chan Attempt, chan error) Session
}

type verifier struct {
	sessionServer SessionServer
}

func waitForAttempt(atq chan Attempt) (Attempt, error) {
	select {
	case a := <-atq:
		log.Printf("Got attempt: %v", a)
		return a, nil
	case <-time.After(time.Duration(*verifyTimeout) * time.Second):
		return nil, fmt.Errorf("Session timed out")
	}
}

func (v *verifier) Verify(r *pb.UserCredentialRequest, aq chan *pb.UserAction, user *pb.VerifiedUser) error {
	// Challenge the user to visit our login web page where we will talk to the
	// local prodaccess running on the user's computer to try to verify that
	// the user has not been tricked to follow some other person's link.
	// After that, we will challenge the user to login as usual using LDAP
	// and U2F/OTP (TODO(bluecmd)).

	// Used to read the attempts gathered from the UI.
	atq := make(chan Attempt, 1)
	// Queue used to push back errors during login. Success is nil.
	eq := make(chan error, 1)
	defer close(atq)
	defer close(eq)
	s := v.sessionServer.NewSession(r, atq, eq)
	defer s.Destroy()

	// Start the username/password challenge to figure out who the user is.
	c := s.ChallengeLogin()
	if c != nil {
		aq <- c
	}
	a, err := waitForAttempt(atq)
	if err != nil {
		return err
	}
	// TODO(bluecmd): Verify attempt
	eq <- nil

	// Now we know the username, use it to look up what groups and what
	// other challenge methods we should use (TODO).
	user.Username = a.Username()

	// TODO(bluecmd): real groups
	user.Group = append(user.Group, "test", "test2-long-group-name")

	// Present the user with all the details about what we're about to generate
	// and let them review the data.
	c = s.ChallengeReview(user)
	if c != nil {
		aq <- c
	}
	_, err = waitForAttempt(atq)
	if err != nil {
		return err
	}
	// The review always succeeded if it didn't time out
	eq <- nil

	// Tell the user we're finished with the challenges
	c = s.ChallengeComplete()
	if c != nil {
		aq <- c
	}
	return fmt.Errorf("not implemented")
}

func New(sessionServer SessionServer) *verifier {
	v := verifier{
		sessionServer: sessionServer,
	}
	return &v
}
