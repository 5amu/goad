package bloodhound

import (
	"archive/zip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/5amu/goad/ldap"
)

type Collection int

var (
	Default     Collection = 1
	All         Collection = 2
	Group       Collection = 3
	LocalAdmin  Collection = 4
	Session     Collection = 5
	Trusts      Collection = 6
	DCOnly      Collection = 7
	DCOM        Collection = 8
	RDP         Collection = 9
	PSRemote    Collection = 10
	LoggedOn    Collection = 11
	Container   Collection = 12
	ObjectProps Collection = 13
	ACL         Collection = 14
)

type Collector interface {
	Collect(*ldap.LdapClient) error
	Export(string) error
}

func uniq(s []Collection) (list []Collection) {
	allKeys := make(map[Collection]bool)
	for _, item := range s {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func generateQueue(collection ...Collection) []Collector {
	var selected []Collection
	for _, method := range collection {
		switch method {
		case All:
			return []Collector{&GroupCollector{}}
		}
	}

	selected = uniq(selected)
	var ret []Collector
	for _, s := range selected {
		switch s {
		}
	}
	return ret
}

func compress(dir string, outfile string) error {
	if strings.HasPrefix(outfile, "/") {
		return fmt.Errorf("output file starts with /")
	}

	file, err := os.Create(outfile)
	if err != nil {
		return err
	}
	w := zip.NewWriter(file)
	defer func() {
		file.Close()
		w.Close()
	}()

	walker := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()

		f, err := w.Create(path)
		if err != nil {
			return err
		}

		_, err = io.Copy(f, file)
		return err
	}

	return filepath.WalkDir(dir, walker)
}

func BloodhoundCollector(ldapClient *ldap.LdapClient, outfile string, collection ...Collection) error {
	queue := generateQueue(collection...)

	tmpDir, err := os.MkdirTemp(os.TempDir(), "bh")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	var wg sync.WaitGroup
	for _, q := range queue {
		wg.Add(1)
		go func(coll Collector) {
			if err := coll.Collect(ldapClient); err != nil {
				fmt.Println(err)
			}
			if err := coll.Export(tmpDir); err != nil {
				fmt.Println(err)
			}
			wg.Done()
		}(q)
	}
	wg.Wait()
	return compress(tmpDir, outfile)
}
