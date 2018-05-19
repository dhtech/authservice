package verify

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/dhtech/authservice/auth"
	pb "github.com/dhtech/proto/auth"
)

var (
	verifyTimeout = flag.String("verify_timeout", "10m", "Seconds before a verify attempt times out.")
)

type Session interface {
	// A request for username/password
	ChallengeLogin() *pb.UserAction

	// A request for the user to acknowledge the credentials being minted
	ChallengeReview(*pb.VerifiedUser) *pb.UserAction

	// The final screen showing something nice to the user prompting to close
	// the window. Sets the attached cookie if set.
	ChallengeComplete(*pb.BrowserCookie) *pb.UserAction

	Destroy()
}

type SessionServer interface {
	NewSession(*pb.UserCredentialRequest, chan auth.Attempt, chan error) Session
}

type AuthBackend interface {
	Verify(auth.Attempt) ([]string, error)
}

type Signer interface {
	Sign(*pb.UserCredentialRequest, *pb.VerifiedUser) (*pb.CredentialResponse, error)
}

type verifier struct {
	sessionServer SessionServer
	ldap AuthBackend
	signer Signer
}

func waitForAttempt(atq chan auth.Attempt) (auth.Attempt, error) {
	tmout, err := time.ParseDuration(*verifyTimeout)
	if err != nil {
		log.Fatalf("failed to parse verification timeout: %v", err)
	}
	select {
	case a := <-atq:
		return a, nil
	case <-time.After(tmout):
		return nil, fmt.Errorf("Session timed out")
	}
}

func (v *verifier) VerifyAndSign(r *pb.UserCredentialRequest, aq chan *pb.UserAction, user *pb.VerifiedUser) (*pb.CredentialResponse, error) {
	// Challenge the user to visit our login web page where we will talk to the
	// local prodaccess running on the user's computer to try to verify that
	// the user has not been tricked to follow some other person's link.
	// After that, we will challenge the user to login as usual using LDAP
	// and U2F/OTP (TODO(bluecmd)).

	// Used to read the attempts gathered from the UI.
	atq := make(chan auth.Attempt, 1)
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

	var a auth.Attempt
	var groups []string
	for {
		var err error
		a, err = waitForAttempt(atq)
		if err != nil {
			return nil, err
		}
		groups, err = v.ldap.Verify(a)
		if err == nil {
			eq <- nil
			break
		}
		eq <- fmt.Errorf("LDAP authentication failed")
	}

	// Now we know the username, use it to look up what groups and what
	// other challenge methods we should use (TODO).
	user.Username = a.Username()
	user.Group = append(user.Group, groups...)

	// Present the user with all the details about what we're about to generate
	// and let them review the data.
	c = s.ChallengeReview(user)
	if c != nil {
		aq <- c
	}
	_, err := waitForAttempt(atq)
	if err != nil {
		return nil, err
	}
	// The review always succeeded if it didn't time out
	eq <- nil

	log.Printf("Done verifying %v, proceeding to signing", user.Username)
	res, err := v.signer.Sign(r, user)
	if err != nil {
		return nil, err
	}

	// Tell the user we're finished with the challenges and set the browser
	// cookie if it was requested and granted.
	log.Printf("Artifacts signed for %v, moving user to success", user.Username)
	c = s.ChallengeComplete(res.BrowserCookie)
	if c != nil {
		aq <- c
	}

	// TODO(bluecmd): Nginx seems to have some timing issue so let's wait
	// before replying to the user.
	// What seems to happen is that when the GRPC channel is closed, the next
	// HTTP request will simply fail.
	time.Sleep(3 * time.Second)

	log.Printf("Response flow done for %v", user.Username)
	return res, nil
}

func New(sessionServer SessionServer, signer Signer) *verifier {
	v := verifier{
		sessionServer: sessionServer,
		signer: signer,
		ldap: auth.NewLdap(),
	}
	return &v
}
