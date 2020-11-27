package server

import (
	"db"
)

type Server struct {
	db db.MyDB
}

func (s *Server) AddUserAge(key string) (*db.User, error) {
	user, _ := s.db.Retrieve(key)
	user.Age++
	return user, nil
}
