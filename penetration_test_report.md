# Penetration Test Report

**Date**: 2025-01-02 17:24:17

## Scan Results
- **Host**: 127.0.0.1
  - Port: 135 (tcp)
  - Service: msrpc 

- **Host**: 127.0.0.1
  - Port: 445 (tcp)
  - Service: microsoft-ds 

- **Host**: 127.0.0.1
  - Port: 1033 (tcp)
  - Service: msrpc 

- **Host**: 127.0.0.1
  - Port: 3306 (tcp)
  - Service: mysql 8.0.40

- **Host**: 127.0.0.1
  - Port: 5357 (tcp)
  - Service: http 2.0

- **Host**: 127.0.0.1
  - Port: 7000 (tcp)
  - Service: afs3-fileserver 

## CVE Results
- **CVE ID**: CVE-2016-0150
  - Description: HTTP.sys in Microsoft Windows 10 Gold and 1511 allows remote attackers to cause a denial of service (system hang) via crafted HTTP 2.0 requests, aka "HTTP.sys Denial of Service Vulnerability."
  - Severity: HIGH
  - CVSS Base Score: 7.8

- **CVE ID**: CVE-2017-3472
  - Description: Vulnerability in the Oracle FLEXCUBE Private Banking component of Oracle Financial Services Applications (subcomponent: Portfolio Management). Supported versions that are affected are 2.0.0, 2.0.1, 2.2.0.1 and 12.0.1. Easily "exploitable" vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle FLEXCUBE Private Banking. Successful attacks of this vulnerability can result in unauthorized creation, deletion or modification access to critical data or all Oracle FLEXCUBE Private Banking accessible data as well as unauthorized access to critical data or complete access to all Oracle FLEXCUBE Private Banking accessible data. CVSS 3.0 Base Score 8.1 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N).
  - Severity: HIGH
  - CVSS Base Score: 8.5

- **CVE ID**: CVE-2017-3476
  - Description: Vulnerability in the Oracle FLEXCUBE Private Banking component of Oracle Financial Services Applications (subcomponent: Miscellaneous). Supported versions that are affected are 2.0.0, 2.0.1, 2.2.0.1 and 12.0.1. Easily "exploitable" vulnerability allows low privileged attacker with network access via HTTP to compromise Oracle FLEXCUBE Private Banking. Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access to all Oracle FLEXCUBE Private Banking accessible data as well as unauthorized update, insert or delete access to some of Oracle FLEXCUBE Private Banking accessible data. CVSS 3.0 Base Score 7.1 (Confidentiality and Integrity impacts). CVSS Vector: (CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N).
  - Severity: HIGH
  - CVSS Base Score: 7.5

- **CVE ID**: CVE-2017-2890
  - Description: An exploitable vulnerability exists in the /api/CONFIG/restore functionality of Circle with Disney running firmware 2.0.1. Specially crafted network packets can cause an OS command injection. An attacker can send an HTTP request trigger this vulnerability.
  - Severity: HIGH
  - CVSS Base Score: 9.0

- **CVE ID**: CVE-2017-2915
  - Description: An exploitable vulnerability exists in the WiFi configuration functionality of Circle with Disney running firmware 2.0.1. A specially crafted SSID can cause the device to execute arbitrary shell commands. An attacker needs to send a couple of HTTP requests and setup an access point reachable by the device to trigger this vulnerability.
  - Severity: HIGH
  - CVSS Base Score: 7.7

- **CVE ID**: CVE-2017-2916
  - Description: An exploitable vulnerability exists in the /api/CONFIG/restore functionality of Circle with Disney running firmware 2.0.1. Specially crafted network packets can cause an arbitrary file to be overwritten. An attacker can send an HTTP request to trigger this vulnerability.
  - Severity: HIGH
  - CVSS Base Score: 9.0

- **CVE ID**: CVE-2017-2917
  - Description: An exploitable vulnerability exists in the notifications functionality of Circle with Disney running firmware 2.0.1. Specially crafted network packets can cause an OS command injection. An attacker can send an HTTP request to trigger this vulnerability.
  - Severity: HIGH
  - CVSS Base Score: 9.0

- **CVE ID**: CVE-2018-0956
  - Description: A denial of service vulnerability exists in the HTTP 2.0 protocol stack (HTTP.sys) when HTTP.sys improperly parses specially crafted HTTP 2.0 requests, aka "HTTP.sys Denial of Service Vulnerability." This affects Windows Server 2016, Windows 10, Windows 10 Servers.
  - Severity: HIGH
  - CVSS Base Score: 7.8

- **CVE ID**: CVE-2016-10559
  - Description: selenium-download downloads the latest versions of the selenium standalone server and the chromedriver. selenium-download before 2.0.7 downloads binary resources over HTTP, which leaves it vulnerable to MITM attacks. It may be possible to cause remote code execution (RCE) by swapping out the requested binary with an attacker controlled binary if the attacker is on the network or positioned in between the user and the remote server.
  - Severity: HIGH
  - CVSS Base Score: 9.3

- **CVE ID**: CVE-2018-8226
  - Description: A denial of service vulnerability exists in the HTTP 2.0 protocol stack (HTTP.sys) when HTTP.sys improperly parses specially crafted HTTP 2.0 requests, aka "HTTP.sys Denial of Service Vulnerability." This affects Windows Server 2016, Windows 10, Windows 10 Servers.
  - Severity: HIGH
  - CVSS Base Score: 7.8

- **CVE ID**: CVE-2018-3955
  - Description: An exploitable operating system command injection exists in the Linksys ESeries line of routers (Linksys E1200 Firmware Version 2.0.09 and Linksys E2500 Firmware Version 3.0.04). Specially crafted entries to network configuration information can cause execution of arbitrary system commands, resulting in full control of the device. An attacker can send an authenticated HTTP request to trigger this vulnerability. Data entered into the 'Domain Name' input field through the web portal is submitted to apply.cgi as the value to the 'wan_domain' POST parameter. The wan_domain data goes through the nvram_set process described above. When the 'preinit' binary receives the SIGHUP signal it enters a code path that calls a function named 'set_host_domain_name' from its libshared.so shared object.
  - Severity: HIGH
  - CVSS Base Score: 9.0

- **CVE ID**: CVE-2019-11063
  - Description: A broken access control vulnerability in SmartHome app (Android versions up to 3.0.42_190515, ios versions up to 2.0.22) allows an attacker in the same local area network to list user accounts and control IoT devices that connect with its gateway (HG100) via http://[target]/smarthome/devicecontrol without any authentication. CVSS 3.0 base score 10 (Confidentiality, Integrity and Availability impacts). CVSS vector: (CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).
  - Severity: HIGH
  - CVSS Base Score: 8.3

- **CVE ID**: CVE-2019-19642
  - Description: On SuperMicro X8STi-F motherboards with IPMI firmware 2.06 and BIOS 02.68, the Virtual Media feature allows OS Command Injection by authenticated attackers who can send HTTP requests to the IPMI IP address. This requires a POST to /rpc/setvmdrive.asp with shell metacharacters in ShareHost or ShareName. The attacker can achieve a persistent backdoor.
  - Severity: HIGH
  - CVSS Base Score: 9.0

- **CVE ID**: CVE-2017-18641
  - Description: In LXC 2.0, many template scripts download code over cleartext HTTP, and omit a digital-signature check, before running it to bootstrap containers.
  - Severity: HIGH
  - CVSS Base Score: 9.3

- **CVE ID**: CVE-2020-5911
  - Description: In versions 3.0.0-3.5.0, 2.0.0-2.9.0, and 1.0.1, the NGINX Controller installer starts the download of Kubernetes packages from an HTTP URL On Debian/Ubuntu system.
  - Severity: HIGH
  - CVSS Base Score: 7.5

- **CVE ID**: CVE-2020-4620
  - Description: IBM Data Risk Manager (iDNA) 2.0.6 could allow a remote authenticated attacker to upload arbitrary files, caused by the improper validation of file extensions. By sending a specially-crafted HTTP request, a remote attacker could exploit this vulnerability to upload a malicious file, which could allow the attacker to execute arbitrary code on the vulnerable system. IBM X-Force ID: 184979.
  - Severity: HIGH
  - CVSS Base Score: 9.0

