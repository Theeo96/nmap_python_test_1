import nmap
import requests
import json
from markdown2 import markdown
from datetime import datetime

# 1. Nmap 스캔 수행
def perform_nmap_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments="-sV")
    # print(f"Scan info: {scanner.scaninfo()}")
    print(f"All hosts: {scanner.all_hosts()}")
    return scanner


# 2. 취약점 데이터베이스(CVE API) 검색
def search_cve(service, version):
    cve_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}+{version}"
    response = requests.get(cve_url)
    if response.status_code == 200:
        print(f"Searching CVE ...")
        data = response.json()
        return data.get("result", {}).get("CVE_Items", [])
    else:
        print(f"Failed to fetch CVE data for {service} {version}")
        return []


# 3. 결과 요약
def summarize_results(scanner):
    results = []
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            for port in scanner[host][protocol]:
                service = scanner[host][protocol][port]["name"]
                version = scanner[host][protocol][port].get("version", "unknown")
                print(f"Discovered: {service} {version} on port {port}")
                results.append({
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version
                })
    return results

# 4. 리포트 생성
def generate_report(scan_results, cve_results):
    print(f"Generate Report ...")
    report = f"# Penetration Test Report\n\n"
    report += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
    report += f"## Scan Results\n"
    for result in scan_results:
        report += f"- **Host**: {result['host']}\n"
        report += f"  - Port: {result['port']} ({result['protocol']})\n"
        report += f"  - Service: {result['service']} {result['version']}\n\n"
    report += f"## CVE Results\n"
    for cve in cve_results:
        report += f"- **CVE**: {cve['cve']['CVE_data_meta']['ID']}\n"
        report += f"  - Description: {cve['cve']['description']['description_data'][0]['value']}\n\n"
    return report

# 5. 메인 함수
if __name__ == "__main__":
    target_ip = "127.0.0.1"  # 타겟 IP 설정
    scan_data = perform_nmap_scan(target_ip)
    scan_results = summarize_results(scan_data)

    # 취약점 검색 수행
    all_cves = []
    for result in scan_results:
        cves = search_cve(result["service"], result["version"])
        all_cves.extend(cves)

    # 리포트 생성
    report_content = generate_report(scan_results, all_cves)
    with open("penetration_test_report.md", "w") as report_file:
        report_file.write(report_content)
    print("Report generated: penetration_test_report.md")
