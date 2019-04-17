package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/davecgh/go-spew/spew"

	"github.com/yuin/gopher-lua/ast"

	"github.com/yuin/gopher-lua/parse"
)

var prefix = "sudo nmap -v4 -Pn -n --version-light "
var scriptsGlob = "/usr/share/nmap/scripts/*.nse"

var usageRe = regexp.MustCompile(`^--*\s*@usage\s*((|sudo|nmap).*)`) // group 1
var nmapRe = regexp.MustCompile(`^--*\s*(.*nmap.*--script.*)\s*$`)   // group 1

// TODO:
// need command line flags for:
// 1: only listing all scripts by name
// 2: given a script name and prefix, output a command
// 3: produce the script-help output. Only requires parsing a few global strings
// 4: make sure that all scripts are output, even if they don't have ports.

// REMOVE THE nmap command from the front of the parsed usage. it gets duplicated.
// - there are some ./nmap
// - there are some @usage still, not sure why it isn't removed.
// there are sudo nmap
// 0- there are some sudo ./nmap
// i'm really not sure why @usage items are still showing up.
// PROBLEM IS, we match a "-- @usage" line, assuming the following lines will only be comment lines, but some of the subsequent lines start with "-- @usage nmap..."
//

// NOTE: wherever this ends up, I don't want to lose the ability to easiliy add in more commands. Maybe i should make this generic for use with all pentest commands. So we should merge whatever auto stuff this produces with another config file
// It would be nice to be able to add key words to lines somehow. perhaps just with comments at the end that get stripped before the command is added to the terminal..

// portrule = shortport.port_or_service({80,443}, "http", "tcp")

// FindIdentExpr returns the AssignStmt where the Lhs value matches val.
// Generally a []ast.Stmt will be provided as root, but it could be any
// func findAllAssignStmt(root interface{}, val string) *ast.AssignStmt {

// }

// func parsePortrule(rhs []ast.Expr) ([]string, error) {
// rhs.Last
// shortport.port_or_service

// function calls:
// shortport.port_or_service
//
// handle only the first argument, since those are the ports
//
// not having shortport is fine for things that aren't common to a port, and those are things we don't need port numbers for anyway. http-screenshot is one example where we wouldn't want ports. or banner, etc.
// need to get the third param if exists for tcp/udp
// we may also want to parse the services... since some may only specify those. need to see if this is the case, since i'm assuming most use both
// these are the shortports being used with their frequency:
// http: 100
// LIKELY_HTTP_PORTS: 8 (passed as port argument)
// LIKELY_HTTP_SERVICES: 8 (passed as svc argument)
// port_is_excluded: 6 (not needed since only eval at runtime)
// port_or_service: 236
// portnumber: 46
// service: 11
// ssl: 28 (wrapper for list of likely ports and svc that use ssl)
// version_port_or_service: 35 (true if port or svc is included in the list of service probes to use. more likely to be true with thorough service disco)
//
// we don't want to specify ports if there are likely to be a ton of them. For a service that uses "http" for example, we don't want to use ports for ports that would match the http rule. we only want to specify the common ones. So it for LIKELY_HTTP blah, we want to use populate 80,443.

// conclusion, honestly, we probably won't be doing anything with turning services into ports. it may actually be easier to just us regex on the files since we'll need to do that anyway if we want to parse the comments. But if we stick to parsing "portnumber", and "port_or_service". Then detecting use of "ssl", and "http", then we are pretty much there.. Parsing will be helpful for the protocol and ports accuracy.

//
// I want to look for use of shortport anywhere in the file...
// What are the concrete types we're dealing with:
// ast.Stmt:
// *ast.LocalAssignStmt
//

// }

// Need function to find use of a function call
// abandon this for now. 380/473 uses of shortport occure
// during the portrule top-level statement. We can just parse those
// isntead of handling all netsted function calls.
// func getCalledFn(i interface{}) interface{} {
// 	switch v := i.(type) {
// 	case *ast.AssignStmt:
// 		v.Lhs // []Expr
// 		v.Rhs // []Expr

// 	case *ast.AttrGetExpr:
// 		v.Object // Expr
// 		v.Key // Expr

// 	case *ast.FalseExpr:
// 		// none, ConstExprBase

// 	case *ast.Field:
// 		v.Key // Expr
// 		v.Value // Expr

// 	case *ast.FuncCallExpr:
// 		v.

// 	case *ast.FuncCallStmt:

// 	case *ast.FunctionExpr:

// 	case *ast.GenericForStmt:

// 	case *ast.IdentExpr:

// 	case *ast.IfStmt:

// 	case *ast.LocalAssignStmt:

// 	case *ast.LogicalOpExpr:

// 	case *ast.NilExpr:

// 	case *ast.NumberExpr:

// 	case *ast.ParList:

// 	case *ast.RelationalOpExpr:

// 	case *ast.ReturnStmt:

// 	case *ast.StringConcatOpExpr:

// 	case *ast.StringExpr:

// 	case *ast.TableExpr:

// 	case *ast.TrueExpr:

// 	}
// }

// getShortport reutrns the *ast.FuncCallExpr which is the
// Rhs of the portrule *ast.AssignStmt.
func getShortport(chunk []ast.Stmt) *ast.FuncCallExpr {
	for _, stmt := range chunk {
		st, ok := stmt.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for _, expr := range st.Lhs {
			identExpr, ok := expr.(*ast.IdentExpr)
			if !ok {
				continue
			}
			if identExpr.Value == "portrule" {
				for _, expr2 := range st.Rhs {
					fcallExpr, ok := expr2.(*ast.FuncCallExpr)
					if !ok {
						continue
					}
					attrGetExpr, ok := fcallExpr.Func.(*ast.AttrGetExpr)
					if !ok {
						continue
					}
					identExpr2, ok := attrGetExpr.Object.(*ast.IdentExpr)
					if !ok {
						continue
					}
					if identExpr2.Value == "shortport" {
						return fcallExpr
					}
					// check args on returned value
				}
			}
		}
	}
	return nil
}

func getFnKeyValue(expr *ast.FuncCallExpr) string {
	if expr == nil {
		return ""
	}
	attr, ok := expr.Func.(*ast.AttrGetExpr)
	if !ok {
		return ""
	}
	key, ok := attr.Key.(*ast.StringExpr)
	if !ok {
		return ""
	}
	return key.Value
}

type Source string

var (
	Usage     Source = "@usage"    // parsed from @usage comment section
	Shortport Source = "shortport" // portrule = shortport
	Prefix    Source = "prefix"    // filename prefix
)

type Script struct {
	Filepath string
	Command  string // Full command usage example
	Ports    Ports
	Source   Source
}

func (s *Script) Filename() string {
	return filepath.Base(s.Filepath)
}

func (s *Script) Name() string {
	return strings.TrimSuffix(s.Filename(), ".nse")
}

type Ports struct {
	Numbers   []int
	Protocols []string // tcp, udp
}

func (p *Ports) String() string {
	tcp := false
	udp := false
	for _, proto := range p.Protocols {
		if proto == "tcp" {
			tcp = true
		}
		if proto == "udp" {
			udp = true
		}
	}
	proto := ""
	if tcp && udp {
		proto = "-sSU"
	} else if udp {
		proto = "-sU"
	}
	var nums []string
	for _, n := range p.Numbers {
		nums = append(nums, strconv.Itoa(n))
	}
	portNos := strings.Join(nums, ",")
	return fmt.Sprintf("%s -p %s", proto, portNos)
}

// getPorts
// func getPorts(port arg, proto arg)
// ports may be a table of ports

// portOrService
func portOrService(args []ast.Expr) (Ports, error) {
	var ports Ports
	if len(args) < 1 {
		return ports, nil
	}
	// get port numbers
	switch v := args[0].(type) {
	case *ast.NumberExpr:
		num, err := strconv.Atoi(v.Value)
		if err != nil {
			return ports, err
		}
		ports.Numbers = append(ports.Numbers, num)
	case *ast.TableExpr:
		for _, field := range v.Fields {
			numExpr, ok := field.Value.(*ast.NumberExpr)
			if !ok {
				// this can be reached if fn is called with a table, like port_or_service{3310, "clam"}.
				// just skip
				continue
				// spew.Dump(numExpr)
				// return ports, fmt.Errorf("expected number, got: %q", numExpr)
			}
			num, err := strconv.Atoi(numExpr.Value)
			if err != nil {
				return ports, err
			}
			ports.Numbers = append(ports.Numbers, num)
		}
	}

	if len(args) < 3 {
		return ports, nil
	}
	switch v := args[2].(type) {
	case *ast.StringExpr:
		ports.Protocols = append(ports.Protocols, v.Value)
	case *ast.TableExpr:
		for _, field := range v.Fields {
			strExpr, ok := field.Value.(*ast.StringExpr)
			if !ok {
				return ports, fmt.Errorf("expected string, got: %q", strExpr)
			}
			ports.Protocols = append(ports.Protocols, strExpr.Value)
		}
	}

	return ports, nil

}

// need to combine these functions
func portNumber(args []ast.Expr) (Ports, error) {
	var ports Ports
	if len(args) < 1 {
		return ports, nil
	}
	// get port numbers
	switch v := args[0].(type) {
	case *ast.NumberExpr:
		num, err := strconv.Atoi(v.Value)
		if err != nil {
			return ports, err
		}
		ports.Numbers = append(ports.Numbers, num)
	case *ast.TableExpr:
		for _, field := range v.Fields {
			numExpr, ok := field.Value.(*ast.NumberExpr)
			if !ok {
				// this can be reached if fn is called with a table, like port_or_service{3310, "clam"}.
				// just skip
				continue
				// spew.Dump(numExpr)
				// return ports, fmt.Errorf("expected number, got: %q", numExpr)
			}
			num, err := strconv.Atoi(numExpr.Value)
			if err != nil {
				return ports, err
			}
			ports.Numbers = append(ports.Numbers, num)
		}
	}

	if len(args) < 2 {
		return ports, nil
	}
	switch v := args[1].(type) {
	case *ast.StringExpr:
		ports.Protocols = append(ports.Protocols, v.Value)
	case *ast.TableExpr:
		for _, field := range v.Fields {
			strExpr, ok := field.Value.(*ast.StringExpr)
			if !ok {
				return ports, fmt.Errorf("expected string, got: %q", strExpr)
			}
			ports.Protocols = append(ports.Protocols, strExpr.Value)
		}
	}

	return ports, nil

}

// func parseUsage()

func usageScripts(lines int) []*Script {
	var scripts []*Script
	scriptPaths, err := filepath.Glob(scriptsGlob)
	if err != nil {
		fmt.Println("error listing files: %v", err)
		os.Exit(1)
	}

	for _, scriptPath := range scriptPaths {
		// fmt.Printf("scanning: %s:\n\n\n\n", scriptPath)
		// fmt.Printf("scanning: %s:\n", scriptPath)
		// script := Script{Filepath: scriptPath}
		file, err := os.Open(scriptPath)
		if err != nil {
			fmt.Println("error opening script:", err)
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		currentLine := 0
		usageLine := -1
		for scanner.Scan() {
			currentLine += 1
			line := scanner.Text()
			if usageLine == -1 {
				matches := usageRe.FindAllStringSubmatch(line, 1)
				// fmt.Printf("line: %q\n", line)
				// fmt.Printf("matches: %q\n", matches)
				if len(matches) > 0 {
					// fmt.Printf("%v: %+v\n", currentLine, matches)
					usageLine = currentLine
					// fmt.Println("usage line:", usageLine)
					if matches[0][1] != "" {
						line = fmt.Sprintf("-- %s", matches[0][1])
						// fmt.Println(line)
					}
				} else {
					continue
				}
			}
			// fmt.Printf("current: %v, usage: %v, diff: %v, ok: %v\n", currentLine, usageLine, currentLine-usageLine, currentLine-usageLine > lines)
			if currentLine-usageLine > lines {
				// fmt.Println("bailing")
				break
			}
			// fmt.Println(line)
			matches := nmapRe.FindAllStringSubmatch(line, 1)
			if len(matches) > 0 {
				// fmt.Println("found match", matches)
				script := Script{
					Filepath: scriptPath,
					Command:  matches[0][1],
					Source:   Usage,
				}
				scripts = append(scripts, &script)
				// don't break, allow adding of multiples. we'll quality score them later
			}
			// (<host/ip>|<host/s>|<host>|<hosts/networks>|<ip>|<ips>|<target>|<targets>)
			// <port>|<ports>
		}
	}
	return scripts

}

func parsedScripts() []*Script {
	var scripts []*Script
	scriptPaths, err := filepath.Glob(scriptsGlob)
	if err != nil {
		fmt.Println("error listing files: %v", err)
		os.Exit(1)
	}
	for _, scriptPath := range scriptPaths {

		script := Script{Filepath: scriptPath}

		file, err := os.Open(scriptPath)
		if err != nil {
			fmt.Println("error opening script:", err)
			os.Exit(1)
		}
		chunk, err := parse.Parse(file, script.Name())
		file.Close()
		if err != nil {
			// fmt.Println("error parsing script:", err)
			// os.Exit(1)
			continue
		}

		fcallExpr := getShortport(chunk)
		// add this functionality to the a more generic getShortport

		var ports *Ports

		if fcallExpr == nil && strings.HasPrefix(script.Name(), "http") {
			// this is just a slightly different version of a rull shortrule function call where you just pass the fucntion directly: portrule = shortport.http. It isn't a fn call so it doesn't hav ethe same ast.
			// fmt.Println("failed getting short port:", script)
			// if script == "/usr/share/nmap/scripts/http-sec-headers.nse" {
			// 	spew.Dump(chunk)
			// }

			// os.Exit(1)
			// continue
			ports = &Ports{
				Numbers:   []int{80, 443},
				Protocols: []string{"tcp"},
			}
			script.Source = Prefix
		}
		if fcallExpr == nil && strings.HasPrefix(script.Name(), "ssl") {
			// this is just a slightly different version of a rull shortrule function call where you just pass the fucntion directly: portrule = shortport.http. It isn't a fn call so it doesn't hav ethe same ast.
			// fmt.Println("failed getting short port:", script)
			// if script == "/usr/share/nmap/scripts/http-sec-headers.nse" {
			// 	spew.Dump(chunk)
			// }

			// os.Exit(1)
			// continue
			ports = &Ports{
				Numbers:   []int{443},
				Protocols: []string{"tcp"},
			}
			script.Source = Prefix
		}

		if fcallExpr == nil && ports == nil {
			continue
		}

		// fmt.Println(fcallExpr)
		fnName := getFnKeyValue(fcallExpr)
		// fmt.Println(fnName, script)
		// continue

		if fnName == "port_or_service" || fnName == "version_port_or_service" {
			p, err := portOrService(fcallExpr.Args)
			if err != nil {
				fmt.Printf("error parsing port_or_service for %v: %v", script, err)
				spew.Dump(fcallExpr)
				os.Exit(1)
			}
			ports = &p
			script.Source = Shortport
		}
		if fnName == "portnumber" {
			p, err := portNumber(fcallExpr.Args)
			if err != nil {
				fmt.Printf("error parsing portnumber for %v: %v", script, err)
				spew.Dump(fcallExpr)
				os.Exit(1)
			}
			ports = &p
			script.Source = Shortport
		}

		// there is only one: :portrule = shortport.ssl, but still support it
		// for http and ssl it may actually be better to just rely on the script name.

		if ports == nil {
			continue
		}
		scripts = append(scripts, &script)
		script.Ports = *ports

		fmt.Printf("%s %s %s \n", prefix, script.Name(), script.Ports.String())
	}
	return scripts
}

func main() {
	scripts := usageScripts(5)
	for _, s := range parsedScripts() {
		// check for dupes?? rank??
		scripts = append(scripts, s)
	}
	for _, script := range scripts {
		switch script.Source {
		case Usage:
			// cleanup <host> stuff
			fmt.Println(script.Command)
		case Prefix, Shortport:
			fmt.Printf("%s %s %s \n", prefix, script.Name(), script.Ports.String())
		}
		// not sure what is going on with prefix
	}

}
