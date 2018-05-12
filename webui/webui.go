package webui

import (
	"html/template"
	"log"
	"net"
	"net/http"
	"sync"
)

type webuiServer struct {
	loginTmpl *template.Template
	sessionLock *sync.Mutex
	sessions map[string]*loginSession
}

func (s *webuiServer) handleLogin(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderLogin(sess, w, r)
	}
	if r.Method == "POST" {
		s.processLogin(sess, w, r)
	}
}

func (s *webuiServer) processLogin(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username, ok := r.PostForm["username"]
	if !ok {
		http.Error(w, "No username provided", http.StatusBadRequest)
		return
	}
	password, ok := r.PostForm["password"]
	if !ok {
		http.Error(w, "No password provided", http.StatusBadRequest)
		return
	}

	err := sess.ProcessLogin(username[0], password[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Printf("User %v login challenge successful", username[0])
}

func (s *webuiServer) renderLogin(sess *loginSession, w http.ResponseWriter, r *http.Request) {
  w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.loginTmpl.Execute(w, sess)
	if err != nil {
		log.Printf("error when rendering login template: %v", err)
	}
}

func (s *webuiServer) handleNext(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")
	w.Write([]byte(sess.NextStep()))
}

func (s *webuiServer) handleReview(sess *loginSession, w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")
	// TODO(bluecmd)
	w.Write([]byte("TODO"))
}

func (s *webuiServer) handleComplete(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/plain")
	// TODO(bluecmd): Make this screen nicer
	w.Write([]byte("You're done, you can close this window"))
}

func (s *webuiServer) withSession(rh func(*loginSession, http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		sid, ok := r.URL.Query()["session"]
		if !ok {
			http.Error(w, "No session ID provided", http.StatusBadRequest)
			return
		}
		session, ok := s.sessions[sid[0]]
		if !ok {
			http.Error(w, "Invalid session ID provided", http.StatusBadRequest)
			return
		}
		rh(session, w, r)
	}
}

func (s *webuiServer) Serve(l net.Listener) {
	http.HandleFunc("/login", s.withSession(s.handleLogin))
	http.HandleFunc("/next", s.withSession(s.handleNext))
	http.HandleFunc("/review", s.withSession(s.handleReview))
	http.HandleFunc("/complete", s.handleComplete)
	http.Serve(l, nil)
}

func New() *webuiServer {
	s := new(webuiServer)
	s.loginTmpl = template.Must(template.ParseFiles("login.tmpl"))
	s.sessions = make(map[string]*loginSession)
	s.sessionLock = &sync.Mutex{}
	return s
}
