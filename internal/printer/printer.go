package printer

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/fatih/color"
)

type Formatter func(string, ...interface{}) string

type Printer struct {
	module  string
	target  string
	netbios string
	port    int
	config  *PrinterConfig
	storage []string
}

type PrinterConfig struct {
	Writer               io.Writer
	ColumnWidth          int
	FirstColumnFormatter Formatter
	OutputFormatter      Formatter
	SuccessFormatter     Formatter
	SuccessSymbol        string
	FailureFormatter     Formatter
	FailureSymbol        string
}

func DefaultPrinterConfig() *PrinterConfig {
	return &PrinterConfig{
		Writer:               os.Stdout,
		FirstColumnFormatter: color.New(color.FgBlue, color.Bold).SprintfFunc(),
		OutputFormatter:      color.New(color.FgHiYellow).SprintfFunc(),
		SuccessFormatter:     color.New(color.FgGreen, color.Bold).SprintfFunc(),
		FailureFormatter:     color.New(color.FgRed, color.Bold).SprintfFunc(),
		SuccessSymbol:        "[*]",
		FailureSymbol:        "[-]",
	}
}

func NewPrinter(module, target, netbios string, port int) *Printer {
	if netbios == "" {
		netbios = "?????"
	}

	return &Printer{
		module:  module,
		target:  target,
		netbios: netbios,
		port:    port,
		config:  DefaultPrinterConfig(),
	}
}

func (p *Printer) SetConfigs(cfg *PrinterConfig) *Printer {
	p.config = cfg
	return p
}

func (p *Printer) print(symbol string, msg ...string) {
	var row strings.Builder
	row.WriteString(p.config.FirstColumnFormatter("%-8s", p.module))
	row.WriteString(fmt.Sprintf("%-16s", p.target))
	row.WriteString(fmt.Sprintf("%-5d", p.port))
	row.WriteString(fmt.Sprintf("%-20s", p.netbios))

	var message strings.Builder
	for _, part := range msg {
		message.WriteString(fmt.Sprintf("%-40s", part))
		if len(part) > 37 {
			message.WriteString(fmt.Sprintf("%-3s", ""))
		}
	}

	var txt string
	if symbol != "" {
		txt = message.String()
	} else {
		txt = p.config.OutputFormatter(message.String())
	}
	fmt.Fprintf(p.config.Writer, "%s%s%s\n", row.String(), symbol, strings.ReplaceAll(strings.ReplaceAll(txt, "\n", ""), "\r", ""))
}

func (p *Printer) Print(msg ...string) {
	p.print("", msg...)
}

func (p *Printer) PrintSuccess(msg ...string) {
	p.print(
		p.config.SuccessFormatter("%s ", p.config.SuccessSymbol),
		msg...,
	)
}

func (p *Printer) PrintFailure(msg ...string) {
	p.print(
		p.config.FailureFormatter("%s ", p.config.FailureSymbol),
		msg...,
	)
}

func (p *Printer) PrintInfo(msg ...string) {
	p.print(
		color.BlueString("%s ", p.config.SuccessSymbol),
		msg...,
	)
}

func (p *Printer) store(symbol string, strip bool, msg ...string) {
	var row strings.Builder
	row.WriteString(p.config.FirstColumnFormatter("%-8s", p.module))
	row.WriteString(fmt.Sprintf("%-16s", p.target))
	row.WriteString(fmt.Sprintf("%-5d", p.port))
	row.WriteString(fmt.Sprintf("%-20s", p.netbios))

	var message strings.Builder
	for _, part := range msg {
		message.WriteString(fmt.Sprintf("%-40s", part))
		if len(part) > 37 {
			message.WriteString(fmt.Sprintf("%-3s", ""))
		}
	}

	var txt string
	if symbol != "" {
		txt = message.String()
	} else {
		txt = p.config.OutputFormatter(message.String())
	}

	var toAppend []string
	if strip {
		tmp := strings.ReplaceAll(strings.ReplaceAll(fmt.Sprintf("%s%s%s", row.String(), symbol, txt), "\n", ""), "\r", "") + "\n"
		toAppend = append(toAppend, tmp)
	} else {
		tmpS := strings.Split(strings.ReplaceAll(txt, "\r", ""), "\n")
		for _, l := range tmpS {
			toAppend = append(toAppend, fmt.Sprintf("%s%s%s\n", row.String(), symbol, p.config.OutputFormatter(l)))
		}
	}

	p.storage = append(p.storage, toAppend...)
}

func (p *Printer) Store(msg ...string) {
	p.store("", true, msg...)
}

func (p *Printer) StoreFailure(msg ...string) {
	p.store(
		p.config.FailureFormatter("%s ", p.config.FailureSymbol),
		true,
		msg...,
	)
}

func (p *Printer) StoreInfo(msg ...string) {
	p.store(
		color.BlueString("%s ", p.config.SuccessSymbol),
		true,
		msg...,
	)
}

func (p *Printer) StoreSuccess(msg ...string) {
	p.store(
		p.config.SuccessFormatter("%s ", p.config.SuccessSymbol),
		true,
		msg...,
	)
}

func (p *Printer) PrintStored(mutex *sync.Mutex) {
	mutex.Lock()
	for _, s := range p.storage {
		fmt.Fprintf(p.config.Writer, "%s", s)
	}
	mutex.Unlock()
}

func (p *Printer) StoreWithoutStripping(msg ...string) {
	p.store("", false, msg...)
}

func (p *Printer) SetModule(s string) *Printer {
	p.module = s
	return p
}

func (p *Printer) SetTarget(s string) *Printer {
	p.target = s
	return p
}

func (p *Printer) SetNebios(s string) *Printer {
	p.netbios = s
	return p
}

func (p *Printer) SetPort(port int) *Printer {
	p.port = port
	return p
}
