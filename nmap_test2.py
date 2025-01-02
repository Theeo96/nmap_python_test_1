import nmap
import requests
from datetime import datetime

# NVD API URL
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 1. nmap 스캔
def perform_nmap_scan(target):
    scanner = nmap.PortScanner()
    print(f"Scanning target: {target}...")
    scanner.scan(target, arguments="-sV")
    return scanner

# 2. 결과 요약 + 데이터 담기
def summarize_results(scanner):
    results = []
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            for port in scanner[host][protocol]:
                service = scanner[host][protocol][port]["name"]
                version = scanner[host][protocol][port].get("version", "unknown")
                results.append({
                    "host": host,
                    "port": port,
                    "protocol": protocol,
                    "service": service,
                    "version": version
                })
    return results

# 3. CVE 검색
def search_cve(keyword, severity="HIGH"):
    # API 호출
    params = {"keywordSearch": keyword, "cvssV3Severity": severity}
    response = requests.get(BASE_URL, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error: Unable to fetch CVE data (Status code: {response.status_code})")
        return None

# 4. CVE 결과 JSON으로 파싱
def parse_cve_results(cve_data, max_results=5):
    vulnerabilities = cve_data.get("vulnerabilities", [])
    parsed_results = []

    for vuln in vulnerabilities[:max_results]:  # 최대 결과 제한
        cve_info = vuln.get("cve", {})
        cve_id = cve_info.get("id", "Unknown CVE ID")
        
        # Description (EN)
        descriptions = cve_info.get("descriptions", [])
        description = next(
            (desc["value"] for desc in descriptions if desc["lang"] == "en"),
            "No description available"
        )

        # CVSS Score
        metrics = cve_info.get("metrics", {})
        cvss_data = metrics.get("cvssMetricV2", [{}])[0].get("cvssData", {})
        severity = metrics.get("cvssMetricV2", [{}])[0].get("baseSeverity", "Unknown")
        base_score = cvss_data.get("baseScore", "N/A")

        # CVE 검색결과 다 출력
        """
        parsed_results.append({
            "cve_id": cve_id,
            "description": description,
            "severity": severity,
            "base_score": base_score
        })
        """

        # CVE 검색결과 7점 이상만 보기
        if base_score != "N/A" and float(base_score) >= 7.0:
            parsed_results.append({
                "cve_id": cve_id,
                    "description": description,
                    "severity": severity,
                    "base_score": base_score
            })


    return parsed_results

# 5. 리포트 생성
def generate_report(scan_results, cve_results):
    # 리포트 헤더
    report = f"# Penetration Test Report\n\n"
    report += f"**Date**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

    # nmap 스캔 결과
    report += "## Scan Results\n"
    for result in scan_results:
        report += f"- **Host**: {result['host']}\n"
        report += f"  - Port: {result['port']} ({result['protocol']})\n"
        report += f"  - Service: {result['service']} {result['version']}\n\n"

    # CVE 검색 결과
    report += "## CVE Results\n"
    for cve in cve_results:
        report += f"- **CVE ID**: {cve['cve_id']}\n"
        report += f"  - Description: {cve['description']}\n"
        report += f"  - Severity: {cve['severity']}\n"
        report += f"  - CVSS Base Score: {cve['base_score']}\n\n"

    return report

# 6. 메인
if __name__ == "__main__":
    target_ip = "127.0.0.1"  #일단 host ip로

    # nmap 스캔 수행
    scanner = perform_nmap_scan(target_ip)
    scan_results = summarize_results(scanner)

    # CVE 결과 수집
    cve_results = []
    for result in scan_results:
        service_name = result["service"]
        version = result["version"] if result["version"] != "unknown" else ""
        keyword = f"{service_name} {version}".strip()  # 서비스 이름 + 버전
        print(f"Searching CVEs for: {keyword}")
        cve_data = search_cve(keyword, severity="HIGH")  # HIGH 심각도 필터
        if cve_data:
            parsed_cves = parse_cve_results(cve_data, max_results=50)  # 최대 몇개인지 여기서 설정정
            cve_results.extend(parsed_cves)

    # 리포트 만들고 저장
    report = generate_report(scan_results, cve_results)
    with open("penetration_test_report.md", "w", encoding="utf-8") as f:
        f.write(report)
    print("Report generated: penetration_test_report.md")
