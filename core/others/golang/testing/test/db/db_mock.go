// Code generated by MockGen. DO NOT EDIT.
// Source: db/db.go

// Package db is a generated GoMock package.
package db

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockMyDB is a mock of MyDB interface
type MockMyDB struct {
	ctrl     *gomock.Controller
	recorder *MockMyDBMockRecorder
}

// MockMyDBMockRecorder is the mock recorder for MockMyDB
type MockMyDBMockRecorder struct {
	mock *MockMyDB
}

// NewMockMyDB creates a new mock instance
func NewMockMyDB(ctrl *gomock.Controller) *MockMyDB {
	mock := &MockMyDB{ctrl: ctrl}
	mock.recorder = &MockMyDBMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockMyDB) EXPECT() *MockMyDBMockRecorder {
	return m.recorder
}

// Retrieve mocks base method
func (m *MockMyDB) Retrieve(key string) (*User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Retrieve", key)
	ret0, _ := ret[0].(*User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Retrieve indicates an expected call of Retrieve
func (mr *MockMyDBMockRecorder) Retrieve(key interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Retrieve", reflect.TypeOf((*MockMyDB)(nil).Retrieve), key)
}
