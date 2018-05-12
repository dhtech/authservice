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

func (s *webuiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		s.renderLogin(w, r)
	}
	if r.Method == "POST" {
		s.processLogin(w, r)
	}
}

func (s *webuiServer) processLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
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

	err := session.ProcessLogin(username[0], password[0])
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	log.Printf("User %v login challenge successful", username[0])
}

func (s *webuiServer) renderLogin(w http.ResponseWriter, r *http.Request) {
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
  w.Header().Add("content-type", "text/html;charset=utf-8")
	err := s.loginTmpl.Execute(w, session)
	if err != nil {
		log.Printf("error when rendering login template: %v", err)
	}
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
