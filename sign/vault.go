package sign

import (
	pb "github.com/dhtech/proto/auth"
)

type signer struct {

}

func (s *signer) Sign(r *pb.UserCredentialRequest, u *pb.VerifiedUser) (*pb.CredentialResponse, error) {
	res := &pb.CredentialResponse{}
	return res, nil
}

func New() *signer {
	s := &signer{}
	return s
}
