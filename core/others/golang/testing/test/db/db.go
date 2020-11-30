package db

type User struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Age int `json:age`
}

type MyDB interface {
	Retrieve(key string) (*User, error)
	// TODO
}
