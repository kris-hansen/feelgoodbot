//go:build !darwin

package console

import "fmt"

type Console struct{}
type Alert struct{}
type Change struct{}

func New() *Console {
	return &Console{}
}

func (c *Console) Start() error {
	fmt.Println("Console is only supported on macOS")
	return nil
}

func (c *Console) Stop() {}
