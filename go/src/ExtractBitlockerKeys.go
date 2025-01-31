package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/xuri/excelize/v2"
)

func banner() {
	fmt.Printf("ExtractBitlockerKeys v%s - by Remi GASCOU (Podalirius)\n", "1.3")
	fmt.Println("")
}

func ldap_init_connection(host string, port int, username string, domain string, password string) (*ldap.Conn, error) {
	// Check if TCP port is valid
	if port < 1 || port > 65535 {
		fmt.Println("[!] Invalid port number. Port must be in the range 1-65535.")
		return nil, errors.New("invalid port number")
	}

	// Set up LDAP connection
	ldapSession, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		fmt.Println("[!] Error connecting to LDAP server:", err)
		return nil, nil
	}

	// Bind with credentials if provided
	bindDN := ""
	if username != "" {
		bindDN = fmt.Sprintf("%s@%s", username, domain)
	}
	if bindDN != "" && password != "" {
		err = ldapSession.Bind(bindDN, password)
		if err != nil {
			fmt.Println("[!] Error binding:", err)
			return nil, nil
		}
	}

	return ldapSession, nil
}

func ldap_get_rootdse(ldapSession *ldap.Conn) *ldap.Entry {
	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN blank
		"",
		// Scope Base
		ldap.ScopeBaseObject,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		1,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		"(objectClass=*)",
		// Attributes to retrieve
		[]string{"*"},
		// Controls
		nil,
	)

	// Perform LDAP search
	searchResult, err := ldapSession.Search(searchRequest)
	if err != nil {
		fmt.Println("[!] Error searching LDAP:", err)
		return nil
	}

	return searchResult.Entries[0]
}

func getDomainFromDistinguishedName(distinguishedName string) string {
	domain := ""
	if strings.Contains(strings.ToLower(distinguishedName), "dc=") {
		dnParts := strings.Split(strings.ToLower(distinguishedName), ",")
		for _, part := range dnParts {
			if strings.HasPrefix(part, "dc=") {
				dcValue := strings.SplitN(part, "=", 2)[1]
				if domain == "" {
					domain = dcValue
				} else {
					domain = domain + "." + dcValue
				}
			}
		}
	}
	return domain
}

func getOUPathFromDistinguishedName(distinguishedName string) string {
	ouPath := ""
	if strings.Contains(strings.ToLower(distinguishedName), "ou=") {
		dnParts := strings.Split(strings.ToLower(distinguishedName), ",")
		// Reverse dnParts slice
		for i, j := 0, len(dnParts)-1; i < j; i, j = i+1, j-1 {
			dnParts[i], dnParts[j] = dnParts[j], dnParts[i]
		}

		// Skip domain
		for len(dnParts) > 0 && strings.HasPrefix(dnParts[0], "dc=") {
			dnParts = dnParts[1:]
		}

		for len(dnParts) > 0 && strings.HasPrefix(dnParts[0], "ou=") {
			ouValue := strings.SplitN(dnParts[0], "=", 2)[1]
			if ouPath == "" {
				ouPath = ouValue
			} else {
				ouPath = ouPath + " --> " + ouValue
			}
			dnParts = dnParts[1:]
		}
	}
	return ouPath
}

func parseFVE(distinguishedName string, ldapEntry *ldap.Entry) map[string]string {
	entry := make(map[string]string)
	entry["distinguishedName"] = distinguishedName
	entry["domain"] = getDomainFromDistinguishedName(distinguishedName)
	entry["organizationalUnits"] = getOUPathFromDistinguishedName(distinguishedName)
	entry["createdAt"] = ""
	entry["volumeGuid"] = ""

	// Parse CN of key
	re := regexp.MustCompile(`^(CN=)([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}-[0-9]{2}:[0-9]{2})({[0-9A-F\-]+}),`)
	matched := re.FindStringSubmatch(distinguishedName)
	if matched != nil {
		createdAt, guid := matched[2], matched[3]
		entry["createdAt"] = createdAt
		entry["volumeGuid"] = strings.Trim(guid, "{}")
	}

	// Parse computer name
	entry["computerName"] = ""
	if strings.Contains(distinguishedName, ",") {
		splitDN := strings.Split(distinguishedName, ",")
		if strings.ToUpper(splitDN[1][:3]) == "CN=" {
			entry["computerName"] = strings.SplitN(splitDN[1], "=", 2)[1]
		}
	}

	// Add recovery key
	entry["recoveryKey"] = ldapEntry.GetAttributeValue("msFVE-RecoveryPassword")

	return entry
}


var (
	useLdaps     bool
	quiet        bool
	debug        bool
	ldapHost     string
	ldapPort     int
	authDomain   string
	authUsername string
	// noPass         bool
	authPassword string
	authHashes   string
	// authKey        string
	// useKerberos    bool
	xlsx         string
)

func parseArgs() {
	flag.BoolVar(&useLdaps, "use-ldaps", false, "Use LDAPS instead of LDAP.")
	flag.BoolVar(&quiet, "quiet", false, "Show no information at all.")
	flag.BoolVar(&debug, "debug", false, "Debug mode")

	flag.StringVar(&ldapHost, "host", "", "IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter.")
	flag.IntVar(&ldapPort, "port", 0, "Port number to connect to LDAP server.")

	flag.StringVar(&authDomain, "domain", "", "(FQDN) domain to authenticate to.")
	flag.StringVar(&authUsername, "username", "", "User to authenticate as.")
	//flag.BoolVar(&noPass, "no-pass", false, "don't ask for password (useful for -k)")
	flag.StringVar(&authPassword, "password", "", "password to authenticate with.")
	flag.StringVar(&authHashes, "hashes", "", "NT/LM hashes, format is LMhash:NThash.")
	//flag.StringVar(&authKey, "aes-key", "", "AES key to use for Kerberos Authentication (128 or 256 bits)")
	//flag.BoolVar(&useKerberos, "k", false, "Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line")

	flag.StringVar(&xlsx, "xlsx", "", "Output results in a XLSX Excel file.")

	flag.Parse()

	if ldapHost == "" {
		fmt.Println("[!] Option -host <host> is required.")
		flag.Usage()
		os.Exit(1)
	}

	if ldapPort == 0 {
		if useLdaps {
			ldapPort = 636
		} else {
			ldapPort = 389
		}
	}
}

func main() {
	banner()
	parseArgs()

	if debug {
		if !useLdaps {
			fmt.Printf("[debug] Connecting to remote ldap://%s:%d ...\n", ldapHost, ldapPort)
		} else {
			fmt.Printf("[debug] Connecting to remote ldaps://%s:%d ...\n", ldapHost, ldapPort)
		}
	}

	// Init the LDAP connection
	ldapSession, err := ldap_init_connection(ldapHost, ldapPort, authUsername, authDomain, authPassword)
	if err != nil {
		fmt.Println("[!] Error searching LDAP:", err)
		return
	}

	rootDSE := ldap_get_rootdse(ldapSession)
	if debug {
		fmt.Printf("[debug] Using defaultNamingContext %s ...\n", rootDSE.GetAttributeValue("defaultNamingContext"))
	}

	// Specify LDAP search parameters
	// https://pkg.go.dev/gopkg.in/ldap.v3#NewSearchRequest
	searchRequest := ldap.NewSearchRequest(
		// Base DN
		rootDSE.GetAttributeValue("defaultNamingContext"),
		// Scope
		ldap.ScopeWholeSubtree,
		// DerefAliases
		ldap.NeverDerefAliases,
		// SizeLimit
		0,
		// TimeLimit
		0,
		// TypesOnly
		false,
		// Search filter
		"(objectClass=msFVE-RecoveryInformation)",
		// Attributes to retrieve
		[]string{
			"msFVE-KeyPackage",        // https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-keypackage
			"msFVE-RecoveryGuid",      // https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoveryguid
			"msFVE-RecoveryPassword",  // https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoverypassword
			"msFVE-VolumeGuid",        // https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-volumeguid
			"distinguishedName",
		},
		// Controls
		nil,
	)

	// Perform LDAP search
	fmt.Println("[+] Extracting LAPS passwords of all computers ... ")
	searchResult, err := ldapSession.Search(searchRequest)
	if err != nil {
		fmt.Println("[!] Error searching LDAP:", err)
		return
	}
	
	// Print search results
	var resultsList []map[string]string
	for _, entry := range searchResult.Entries {
		result := parseFVE(entry.GetAttributeValue("distinguishedName"), entry)
		resultsList = append(resultsList, result)
	}
	fmt.Printf("[+] Total BitLocker recovery keys found: %d\n", len(resultsList))
	
	// Export BitLocker Recovery Keys to an Excel
	if xlsx != "" {
		f := excelize.NewFile()
		// Create a new sheet.
		index, err := f.NewSheet("Sheet1")
		// Set value of a cell.
		f.SetCellValue("Sheet1", "A1", "Domain")
		f.SetCellValue("Sheet1", "B1", "Computer Name")
		f.SetCellValue("Sheet1", "C1", "BitLocker Recovery Key")
		for i, result := range resultsList {
			f.SetCellValue("Sheet1", fmt.Sprintf("A%d", i+2), result["domain"])
			f.SetCellValue("Sheet1", fmt.Sprintf("B%d", i+2), result["computerName"])
			f.SetCellValue("Sheet1", fmt.Sprintf("C%d", i+2), result["recoveryKey"])
		}
		// Set active sheet of the workbook.
		f.SetActiveSheet(index)
		// Save xlsx file by the given path.
		if err := f.SaveAs(xlsx); err != nil {
			fmt.Println(err)
		}
		fmt.Printf("[+] Exported BitLocker recovery keys to: %s\n", xlsx)
	} else {
		// Print the keys in the console
		for _, result := range resultsList {
			fmt.Printf("| %-20s | %-20s | %s |\n", result["domain"], result["computerName"], result["recoveryKey"])
		}
	}

	fmt.Println("[+] All done!")
}
