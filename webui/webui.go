package webui

import (
	"flag"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	pb "github.com/dhtech/proto/auth"
	"github.com/google/uuid"
)

var (
	sessionTimeout = flag.Int("session_timeout", 600, "Seconds before a login session times out.")
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
	sids, ok := r.URL.Query()["session"]
	if !ok {
		http.Error(w, "No session ID provided", http.StatusBadRequest)
		return
	}
	sid := sids[0]
	session, ok := s.sessions[sid]
	if !ok {
		http.Error(w, "Invalid session ID provided", http.StatusBadRequest)
		return
	}
  w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.loginTmpl.Execute(w, session)
	if err != nil {
		log.Printf("error when rendering login template: %v", err)
	}
}

func (s *webuiServer) cleanupSession(sid string) {
	s.sessionLock.Lock()
	delete(s.sessions, sid)
	s.sessionLock.Unlock()
	log.Printf("Cleaned up session %s", sid)
}

func (s *webuiServer) Verify(r *pb.UserCredentialRequest, aq chan *pb.UserAction) (*pb.VerifiedUser, error) {
	// Challenge the user to visit our login web page where we will talk to the
	// local prodaccess running on the user's computer to try to verify that
	// the user has not been tricked to follow some other person's link.
	// After that, we will challenge the user to login as usual using LDAP
	// and U2F/OTP (TODO(bluecmd)).
	sid := uuid.New().String()
	s.sessionLock.Lock()
	s.sessions[sid] = &loginSession{
		Ident: r.ClientValidation.Ident,
	}
	s.sessionLock.Unlock()
	defer s.cleanupSession(sid)

	aq <- &pb.UserAction{Url: fmt.Sprintf("/login?session=%s", sid)}
	
	c := make(chan int, 1)
	// TODO(bluecmd): block forever for now
	select {
	case <-c:
	case <-time.After(time.Duration(*sessionTimeout) * time.Second):
		return &pb.VerifiedUser{}, fmt.Errorf("Session timed out")
	}
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
