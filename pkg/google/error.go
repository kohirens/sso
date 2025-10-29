package google

import "fmt"

type ErrDeviceNotFound struct {
	DeviceID string
}

func (e *ErrDeviceNotFound) Error() string {
	return fmt.Sprintf(stderr.DeviceNotFound, e.DeviceID)
}

type ErrInvalidState struct {
	msg      string
	Location string
	Code     int
}

func (e *ErrInvalidState) Error() string {
	return e.msg
}

type ErrNoLoginInfo struct {
	DeviceID string
}

func (e *ErrNoLoginInfo) Error() string {
	return fmt.Sprintf(stderr.NoLoginInfo, e.DeviceID)
}

type ErrNoSessionData struct {
	data string
}

func (e *ErrNoSessionData) Error() string {
	return fmt.Sprintf("no session data for %v", e.data)
}

type ErrNoSession struct{}

func (e *ErrNoSession) Error() string {
	return "session manager is nil"
}

type ErrExpireToken struct{}

func (e *ErrExpireToken) Error() string {
	return "token has expired"
}
