#!/bin/python

import socket
import ssl
from datetime import datetime
from colorama import Fore, Style, init
import time
import sys

init(autoreset=True)

def get_ssl_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
    except socket.gaierror:
        return {"domain": hostname, "error": "Could not resolve hostname"}
    except ConnectionRefusedError:
        return {"domain": hostname, "error": "Connection refused (no HTTPS)"}
    except ssl.SSLError as e:
        return {"domain": hostname, "error": f"SSL Error: {e}"}
    except Exception as e:
        return {"domain": hostname, "error": f"Unexpected error: {e}"}

    subject = dict(x[0] for x in cert['subject'])
    issued_to = subject.get('commonName', 'N/A')
    issuer = dict(x[0] for x in cert['issuer'])
    issued_by = issuer.get('commonName', 'N/A')

    valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
    valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    days_left = (valid_to - datetime.utcnow()).days

    if days_left <= 0:
        status, color = "❌ EXPIRED", Fore.RED
    elif days_left <= 30:
        status, color = f"⚠️  Expires soon ({days_left} days left)", Fore.YELLOW
    elif days_left <= 90:
        status, color = f"🟠 Valid but under 3 months ({days_left} days left)", Fore.MAGENTA
    else:
        status, color = f"✅ VALID ({days_left} days left)", Fore.GREEN

    return {
        "domain": hostname,
        "issued_to": issued_to,
        "issued_by": issued_by,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "days_left": days_left,
        "status": status,
        "color": color
    }


def check_domains(domains):
    results = []
    for domain in domains:
        domain = domain.strip()
        if not domain:
            continue
        print(Fore.CYAN + f"\n🔎 Checking {domain} ...")
        result = get_ssl_info(domain)
        results.append(result)
        time.sleep(0.3)  # slight delay for readability
    return results


def display_results(results):
    print("\n" + "=" * 70)
    print(Fore.BLUE + "SSL CHECK REPORT".center(70))
    print("=" * 70)

    report_lines = []
    for r in results:
        if "error" in r:
            print(Fore.RED + f"{r['domain']}: {r['error']}")
            report_lines.append(f"{r['domain']}: {r['error']}")
        else:
            color = r["color"]
            print(color + f"\n🔐 {r['domain']}")
            print(color + f"Issued To: {r['issued_to']}")
            print(color + f"Issued By: {r['issued_by']}")
            print(color + f"Valid From: {r['valid_from']}")
            print(color + f"Valid Until: {r['valid_to']}")
            print(color + f"Status: {r['status']}")
            report_lines.append(
                f"{r['domain']} | {r['status']} | Expires: {r['valid_to'].strftime('%Y-%m-%d')}"
            )

    print(Style.RESET_ALL + "\n" + "=" * 70)
    save_report(report_lines)


def save_report(lines):
    with open("ssl_report.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(Fore.CYAN + "\n📁 Results saved to ssl_report.txt\n")


if __name__ == "__main__":
    print(Fore.MAGENTA + "🌐 Advanced SSL Certificate Checker")
    print("Enter domains separated by commas (e.g. google.com, github.com)\n")

    user_input = input("Domains: ").strip()
    if not user_input:
        print(Fore.RED + "Please enter at least one domain.")
        sys.exit()

    domain_list = [d.strip() for d in user_input.split(",")]
    results = check_domains(domain_list)
    display_results(results)

