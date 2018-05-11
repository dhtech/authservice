package webui

import (
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"

	pb "github.com/dhtech/proto/auth"
	"github.com/google/uuid"
)

type webuiServer struct {
	loginTmpl *template.Template
	sessionLock *sync.Mutex
	sessions map[string]*loginSession
}

type loginSession struct {
	Ident string
}

func (s *webuiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderLogin(w, r)
	}
	if r.Method == "POST" {
		s.processLogin(w, r)
	}
}

func (s *webuiServer) processLogin(w http.ResponseWriter, r *http.Request) {
	log.Printf("Processing login, TODO")
}

func (s *webuiServer) renderLogin(w http.ResponseWriter, r *http.Request) {
  w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.loginTmpl.Execute(w, s.sessions[r.URL.Query()["session"][0]])
	if err != nil {
		log.Printf("error when rendering login template: %v", err)
	}
}

func (s *webuiServer) Verify(r *pb.UserCredentialRequest, aq chan *pb.UserAction) (*pb.VerifiedUser, error) {
	// Challenge the user to visit our login web page where we will talk to the
	// local prodaccess running on the user's computer to try to verify that
	// the user has not been tricked to follow some other person's link.
	// After that, we will challenge the user to login as usual using LDAP
	// and U2F/OTP (TODO(bluecmd)).
	sid := uuid.New().String()
	s.sessions[sid] = &loginSession{
		Ident: r.ClientValidation.Ident,
	}
	aq <- &pb.UserAction{Url: fmt.Sprintf("/login?session=%s", sid)}
	
	c := make(chan int, 1)
	// TODO(bluecmd): block foever for now
	<-c
	return &pb.VerifiedUser{}, fmt.Errorf("not implemented")
}

func (s *webuiServer) Serve(l net.Listener) {
	http.HandleFunc("/login", s.handleLogin)
	http.Serve(l, nil)
}

func New() *webuiServer {
	s := new(webuiServer)
	s.loginTmpl = template.Must(template.ParseFiles("login.tmpl"))
	s.sessions = make(map[string]*loginSession)
	s.sessionLock = &sync.Mutex{}
	return s
}
