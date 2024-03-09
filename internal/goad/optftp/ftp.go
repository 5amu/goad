package optftp

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"sync"

	"github.com/5amu/goad/internal/printer"
	"github.com/5amu/goad/internal/utils"
	"github.com/jlaffaye/ftp"
)

type Options struct {
	Targets struct {
		TARGETS []string `description:"Provide target IP/FQDN/FILE"`
	} `positional-args:"yes"`

	Connection struct {
		Username string `short:"u" description:"Provide username (or FILE)"`
		Password string `short:"p" description:"Provide password (or FILE)"`
		Port     int    `long:"port" default:"21" description:"Port to contact"`
	} `group:"Connection Options" description:"Connection Options"`

	Mode struct {
		GetFile       string `long:"get" description:"Get specified file"`
		PutFile       string `long:"put" description:"Put specified file"`
		DstFile       string `long:"dst" description:"Destination file (get/put)"`
		ReadFile      string `long:"read" description:"Read a file stored in the server"`
		List          bool   `long:"list" description:"List files in / directory"`
		RecursiveList bool   `long:"recursive-list" description:"List all files in FTP server (might take long)"`
	} `group:"Possible Operations"`

	targets       []string
	target2Banner map[string]string
	printMutex    sync.Mutex
	credentials   []utils.Credential

	srcFile string
	dstFile string
}

func (o *Options) authenticate(host string, stopAtFirstMatch bool) (*ftp.ServerConn, utils.Credential, error) {
	prt := printer.NewPrinter("FTP", host, o.target2Banner[host], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	srv, err := connect(host, o.Connection.Port)
	if err != nil {
		return nil, utils.Credential{}, err
	}

	var found bool
	for _, creds := range o.credentials {
		err := srv.Login(creds.Username, creds.Password)
		if err != nil {
			prt.StoreFailure(creds.String())
			continue
		}
		found = true
		prt.StoreSuccess(creds.String())
		if stopAtFirstMatch {
			return srv, creds, nil
		}
	}

	if !found {
		return nil, utils.Credential{}, fmt.Errorf("no valid authentication")
	}
	return nil, utils.Credential{}, nil
}

func (o *Options) Run() {
	o.targets = utils.ExtractTargets(o.Targets.TARGETS)
	o.credentials = utils.NewCredentialsClusterBomb(
		utils.ExtractLinesFromFileOrString(o.Connection.Username),
		utils.ExtractLinesFromFileOrString(o.Connection.Password),
	)
	o.target2Banner = gatherFTPBanner2Map(&o.printMutex, o.targets, o.Connection.Port)

	if !slices.Contains(os.Args, "-u") {
		return
	}

	var f func(string)
	if o.Mode.List {
		f = o.listRoot
	} else if o.Mode.RecursiveList {
		f = o.recursiveList
	} else if o.Mode.PutFile != "" {
		o.srcFile = o.Mode.PutFile
		o.dstFile = o.Mode.DstFile
		f = o.putFile
	} else if o.Mode.ReadFile != "" {
		o.srcFile = o.Mode.ReadFile
		f = o.readFile
	} else if o.Mode.GetFile != "" {
		o.srcFile = o.Mode.GetFile
		o.dstFile = o.Mode.DstFile
		f = o.getFile
	} else {
		return
	}

	var wg sync.WaitGroup
	for target := range o.target2Banner {
		wg.Add(1)
		go func(t string) {
			f(t)
			wg.Done()
		}(target)
	}
	wg.Wait()
}

func (o *Options) listRoot(target string) {
	prt := printer.NewPrinter("FTP", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	srv, _, err := o.authenticate(target, true)
	if err != nil {
		return
	}
	defer func() {
		_ = srv.Quit()
	}()

	e, err := srv.List("/")
	if err != nil {
		fmt.Println(err)
		return
	}

	for _, entry := range e {
		prt.Store(entry.Name)
	}
}

func (o *Options) recursiveList(target string) {
	prt := printer.NewPrinter("FTP", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	srv, _, err := o.authenticate(target, true)
	if err != nil {
		return
	}
	defer func() {
		_ = srv.Quit()
	}()

	for fs := srv.Walk("/"); fs.Next(); {
		prt.Store(fs.Path())
	}
}

func (o *Options) readFile(target string) {
	prt := printer.NewPrinter("FTP", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	srv, _, err := o.authenticate(target, true)
	if err != nil {
		return
	}
	defer func() {
		_ = srv.Quit()
	}()

	r, err := srv.Retr(o.srcFile)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer func() {
		_ = r.Close()
	}()

	buf, err := io.ReadAll(r)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	prt.StoreInfo(fmt.Sprintf("Content of %s\n", o.srcFile))
	prt.StoreWithoutStripping(string(buf))
}

func (o *Options) getFile(target string) {
	prt := printer.NewPrinter("FTP", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	var outfile *os.File
	if o.dstFile == "" {
		basePath := path.Base(o.srcFile)

		dst, err := os.Create(basePath)
		if err != nil {
			prt.StoreFailure(err.Error())
			return
		}
		outfile = dst
		o.dstFile = dst.Name()
	} else {
		dst, err := os.Open(o.dstFile)
		if err != nil {
			prt.StoreFailure(err.Error())
			return
		}
		outfile = dst
	}
	defer func() {
		_ = outfile.Close()
	}()

	srv, _, err := o.authenticate(target, true)
	if err != nil {
		return
	}
	defer func() {
		_ = srv.Quit()
	}()

	r, err := srv.Retr(o.srcFile)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	defer func() {
		_ = r.Close()
	}()

	buf, err := io.ReadAll(r)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	_, err = outfile.Write(buf)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}
	msg := fmt.Sprintf("Output of file %s written to %s", o.srcFile, o.dstFile)
	prt.Store(msg)
}

func (o *Options) putFile(target string) {
	prt := printer.NewPrinter("FTP", target, o.target2Banner[target], o.Connection.Port)
	defer prt.PrintStored(&o.printMutex)

	if o.dstFile == "" {
		o.dstFile = o.srcFile
	}

	srv, _, err := o.authenticate(target, true)
	if err != nil {
		return
	}
	defer func() {
		_ = srv.Quit()
	}()

	data, err := os.ReadFile(o.srcFile)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	reader := bytes.NewBuffer(data)

	err = srv.Stor(o.dstFile, reader)
	if err != nil {
		prt.StoreFailure(err.Error())
		return
	}

	msg := fmt.Sprintf("Successfully uploaded %s to %s", o.srcFile, o.dstFile)
	prt.Store(msg)
}
