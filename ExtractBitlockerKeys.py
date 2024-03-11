#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : ExtractBitlockerKeys.py
# Author             : Podalirius (@podalirius_)
# Date created       : 19 Sep 2023


import argparse
from sectools.windows.ldap import raw_ldap_query, init_ldap_session
from sectools.windows.crypto import nt_hash, parse_lm_nt_hashes
import os
import sys
import sqlite3
import json
import xlsxwriter
import re


VERSION = "1.1"


def export_json(options, results):
    print("[>] Exporting results to %s ... " % options.export_json, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(options.export_json)
    filename = os.path.basename(options.export_json)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    f = open(path_to_file, "w")
    f.write(json.dumps(results, indent=4) + "\n")
    f.close()
    print("done.")


def export_xlsx(options, results):
    print("[>] Exporting results to %s ... " % options.export_xlsx, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(options.export_xlsx)
    filename = os.path.basename(options.export_xlsx)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename
    workbook = xlsxwriter.Workbook(path_to_file)
    worksheet = workbook.add_worksheet()

    header_format = workbook.add_format({'bold': 1})
    header_fields = ["Computer FQDN", "Domain", "Recovery Key", "Volume GUID", "Created At", "Organizational Units"]
    for k in range(len(header_fields)):
        worksheet.set_column(k, k + 1, len(header_fields[k]) + 3)
    worksheet.set_row(0, 20, header_format)
    worksheet.write_row(0, 0, header_fields)

    row_id = 1
    for computerfqdn in results.keys():
        data = [
            computerfqdn,
            results[computerfqdn]["domain"],
            results[computerfqdn]["recoveryKey"],
            results[computerfqdn]["volumeGuid"],
            results[computerfqdn]["createdAt"],
            results[computerfqdn]["organizationalUnits"],
        ]
        worksheet.write_row(row_id, 0, data)
        row_id += 1
    worksheet.autofilter(0, 0, row_id, len(header_fields) - 1)
    workbook.close()
    print("done.")


def export_sqlite(options, results):
    print("[>] Exporting results to %s ... " % options.export_sqlite, end="")
    sys.stdout.flush()
    basepath = os.path.dirname(options.export_sqlite)
    filename = os.path.basename(options.export_sqlite)
    if basepath not in [".", ""]:
        if not os.path.exists(basepath):
            os.makedirs(basepath)
        path_to_file = basepath + os.path.sep + filename
    else:
        path_to_file = filename

    conn = sqlite3.connect(path_to_file)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS bitlocker_keys(fqdn VARCHAR(255), domain VARCHAR(255), recoveryKey VARCHAR(255), volumeGuid VARCHAR(255), createdAt VARCHAR(255), organizationalUnits VARCHAR(1024));")
    for computerfqdn in results.keys():
        cursor.execute("INSERT INTO shares VALUES (?, ?, ?, ?, ?, ?)", (
                computerfqdn,
                results[computerfqdn][0]["domain"],
                results[computerfqdn][0]["recoveryKey"],
                results[computerfqdn][0]["volumeGuid"],
                results[computerfqdn][0]["createdAt"],
                results[computerfqdn][0]["organizationalUnits"],
            )
        )
    conn.commit()
    conn.close()
    print("done.")


def get_domain_from_distinguished_name(distinguishedName):
    domain = None
    if "dc=" in distinguishedName.lower():
        distinguishedName = distinguishedName.lower().split(',')[::-1]

        while distinguishedName[0].startswith("dc="):
            if domain is None:
                domain = distinguishedName[0].split('=',1)[1]
            else:
                domain = distinguishedName[0].split('=', 1)[1] + "." + domain
            distinguishedName = distinguishedName[1:]

    return domain


def get_ou_path_from_distinguished_name(distinguishedName):
    ou_path = None
    if "ou=" in distinguishedName.lower():
        distinguishedName = distinguishedName.lower().split(',')[::-1]

        # Skip domain
        while distinguishedName[0].startswith("dc="):
            distinguishedName = distinguishedName[1:]

        while distinguishedName[0].startswith("ou="):
            if ou_path is None:
                ou_path = distinguishedName[0].split('=',1)[1]
            else:
                ou_path = ou_path + " --> " + distinguishedName[0].split('=',1)[1]
            distinguishedName = distinguishedName[1:]

        return ou_path
    else:
        return ou_path


def parse_fve(distinguishedName, bitlocker_keys):
    entry = {
        "distinguishedName": distinguishedName,
        "domain": get_domain_from_distinguished_name(distinguishedName),
        "organizationalUnits": get_ou_path_from_distinguished_name(distinguishedName),
        "createdAt": None,
        "volumeGuid": None
    }
    # Parse CN of key
    matched = re.match(r"^(CN=)([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9]-[0-9][0-9]:[0-9][0-9])({[0-9A-F\-]+}),", distinguishedName, re.IGNORECASE)
    if matched is not None:
        _, created_at, guid = matched.groups()
        entry["createdAt"] = created_at
        entry["volumeGuid"] = guid.strip('{}').lower()
    # Parse computer name
    entry["computerName"] = None
    if ',' in distinguishedName:
        if distinguishedName.split(',')[1].upper().startswith("CN="):
            entry["computerName"] = distinguishedName.split(',')[1].split('=',1)[1]
    # Add recovery key
    entry["recoveryKey"] = bitlocker_keys["msFVE-RecoveryPassword"]

    return entry


def parseArgs():
    print("ExtractBitlockerKeys.py v%s - by @podalirius_\n" % VERSION)

    parser = argparse.ArgumentParser(description="")

    parser.add_argument("-v", "--verbose", default=False, action="store_true", help='Verbose mode. (default: False)')
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true", default=False, help="Show no information at all.")
    parser.add_argument("-t", "--threads", dest="threads", action="store", type=int, default=4, required=False, help="Number of threads (default: 4).")

    output = parser.add_argument_group('Output files')
    output.add_argument("--export-xlsx", dest="export_xlsx", type=str, default=None, required=False, help="Output XLSX file to store the results in.")
    output.add_argument("--export-json", dest="export_json", type=str, default=None, required=False, help="Output JSON file to store the results in.")
    output.add_argument("--export-sqlite", dest="export_sqlite", type=str, default=None, required=False, help="Output SQLITE3 file to store the results in.")

    authconn = parser.add_argument_group('Authentication & connection')
    authconn.add_argument('--dc-ip', required=True, action='store', metavar="ip address", help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')
    authconn.add_argument('--kdcHost', dest="kdcHost", action='store', metavar="FQDN KDC", help='FQDN of KDC for Kerberos.')
    authconn.add_argument("-d", "--domain", dest="auth_domain", metavar="DOMAIN", action="store", default="", help="(FQDN) domain to authenticate to")
    authconn.add_argument("-u", "--user", dest="auth_username", metavar="USER", action="store", default="", help="user to authenticate with")

    secret = parser.add_argument_group("Credentials")
    cred = secret.add_mutually_exclusive_group()
    cred.add_argument("--no-pass", default=False, action="store_true", help="Don't ask for password (useful for -k)")
    cred.add_argument("-p", "--password", dest="auth_password", metavar="PASSWORD", action="store", default=None, help="Password to authenticate with")
    cred.add_argument("-H", "--hashes", dest="auth_hashes", action="store", metavar="[LMHASH:]NTHASH", help='NT/LM hashes, format is LMhash:NThash')
    cred.add_argument("--aes-key", dest="auth_key", action="store", metavar="hex key", help='AES key to use for Kerberos Authentication (128 or 256 bits)')
    secret.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')

    return parser.parse_args()


if __name__ == '__main__':
    options = parseArgs()
    if options.auth_hashes is not None:
        if ":" not in options.auth_hashes:
            options.auth_hashes = ":" + options.auth_hashes
    auth_lm_hash, auth_nt_hash = parse_lm_nt_hashes(options.auth_hashes)

    if options.auth_key is not None:
        options.use_kerberos = True
    
    if options.use_kerberos is True and options.kdcHost is None:
        print("[!] Specify KDC's Hostname of FQDN using the argument --kdcHost")
        exit()
    
    if not options.quiet:
        print("[>] Extracting BitLocker recovery keys of all computers ...")

    computer_keys = raw_ldap_query(
        auth_domain=options.auth_domain,
        auth_dc_ip=options.dc_ip,
        auth_username=options.auth_username,
        auth_password=options.auth_password,
        auth_hashes=options.auth_hashes,
        auth_key=options.auth_key,
        query="(objectClass=msFVE-RecoveryInformation)",
        attributes=[
            "msFVE-KeyPackage",  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-keypackage
            "msFVE-RecoveryGuid",  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoveryguid
            "msFVE-RecoveryPassword",  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-recoverypassword
            "msFVE-VolumeGuid"  # https://learn.microsoft.com/en-us/windows/win32/adschema/a-msfve-volumeguid
        ],
        use_kerberos=options.use_kerberos,
        kdcHost=options.kdcHost
    )

    if not options.quiet:
        print("[>] Found %d BitLocker recovery keys!" % len(computer_keys.keys()))

    results = {}

    if len(computer_keys.keys()) != 0:
        for dn, fve_entry in computer_keys.items():
            if len(fve_entry.keys()) != 0:
                if dn not in results.keys():
                    results[dn] = []
                result = parse_fve(dn, fve_entry)
                print("| %-20s | %-20s | %s |" % (result["domain"], result["computerName"], result["recoveryKey"]))
                results[dn].append(result)

        print("[>] Extracted %d BitLocker recovery keys!" % len(computer_keys.keys()))

        # Export results
        if options.export_json is not None:
            export_json(options, results)

        if options.export_xlsx is not None:
            export_xlsx(options, results)

        if options.export_sqlite is not None:
            export_sqlite(options, results)
    else:
        print("[!] No computers in the domain found matching filter (objectClass=msFVE-RecoveryInformation)")


    print("[+] Bye Bye!")
