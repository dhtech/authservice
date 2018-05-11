package rpc

import (
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
	pb "github.com/dhtech/proto/auth"
)

type Verifier interface {
	Verify(*pb.UserCredentialRequest, chan *pb.UserAction) (*pb.VerifiedUser, error)
}

type Signer interface {
	Sign(*pb.UserCredentialRequest, *pb.VerifiedUser) (*pb.CredentialResponse, error)
}

type authServer struct {
	signer Signer
	verifier Verifier
}

func (s *authServer) RequestUserCredential(r *pb.UserCredentialRequest, stream pb.AuthenticationService_RequestUserCredentialServer) error {
	log.Printf("Handling request %v", *r)
	aq := make(chan *pb.UserAction, 1)
	go func() {
		// As long as the validator sends user actions, pass them along.
		for action := range aq {
			stream.Send(&pb.CredentialResponse{
				RequiredAction: action,
			})
		}
	}()
	v, err := s.verifier.Verify(r, aq)
	if err != nil {
		log.Printf("User failed validation: %v", err)
		return err
	}
	log.Printf("Done verifying %v, proceeding to signing", *r)
	s.signer.Sign(r, v)
	return nil
}

func (s *authServer) Serve(l net.Listener) {
	g := grpc.NewServer()
	pb.RegisterAuthenticationServiceServer(g, s)
	reflection.Register(g)
	g.Serve(l)
}

func New(signer Signer, verifier Verifier) *authServer {
	s := new(authServer)
	s.signer = signer
	s.verifier = verifier
	return s
}
