package smb_test

import (
	"fmt"
	"io"
	"net"

	"github.com/5amu/smb"
)

func Example() {
	conn, err := net.Dial("tcp", "localhost:445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb.Dialer{
		Initiator: &smb.NTLMInitiator{
			User:     "Guest",
			Password: "",
			Domain:   "MicrosoftAccount",
		},
	}

	c, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = c.Logoff()
	}()

	fs, err := c.Mount(`\\localhost\share`)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = fs.Umount()
	}()

	f, err := fs.Create("hello.txt")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = fs.Remove("hello.txt")
		_ = f.Close()
	}()

	_, err = f.Write([]byte("Hello world!"))
	if err != nil {
		panic(err)
	}

	_, err = f.Seek(0, io.SeekStart)
	if err != nil {
		panic(err)
	}

	bs, err := io.ReadAll(f)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(bs))

	// Hello world!
}
