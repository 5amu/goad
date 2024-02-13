package printer

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatih/color"
)

type Formatter func(string, ...interface{}) string

type Printer struct {
	module  string
	target  string
	netbios string
	port    int
	config  *PrinterConfig
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
	row.WriteString(fmt.Sprintf("%-15s", p.target))
	row.WriteString(fmt.Sprintf("%-5d", p.port))
	row.WriteString(fmt.Sprintf("%-20s", p.netbios))

	var message strings.Builder
	for _, part := range msg {
		message.WriteString(fmt.Sprintf("%-30s", part))
		if len(part) > 30 {
			message.WriteString(fmt.Sprintf("%-3s", ""))
		}
	}

	var txt string
	if symbol != "" {
		txt = message.String()
	} else {
		txt = p.config.OutputFormatter(message.String())
	}
	fmt.Fprintf(p.config.Writer, "%s%s%s\n", row.String(), symbol, txt)
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
