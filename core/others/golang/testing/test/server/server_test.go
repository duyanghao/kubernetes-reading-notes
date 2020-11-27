package server

import (
	"db"
	"github.com/golang/mock/gomock"
	"testing"
)

func TestAddUserAge(t *testing.T) {
	ctl := gomock.NewController(t)
	defer ctl.Finish()

	mockMyDB := db.NewMockMyDB(ctl)

	mockMyDB.EXPECT().Retrieve("1").Return(&db.User{
		ID:   "1",
		Name: "duyanghao",
		Age:  27,
	}, nil)

	server := &Server{
		db: mockMyDB,
	}

	user, _ := server.AddUserAge("1")

	if user.Age != 27 {
		t.Fatal("expected age 28, but got", user.Age)
	}
}
