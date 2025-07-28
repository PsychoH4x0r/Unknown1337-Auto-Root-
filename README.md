Unknown1337 Auto Root v2.1

Unknown1337 Auto Root v2.1 is an advanced Linux kernel exploitation framework designed for security researchers and penetration testers. It automates privilege escalation by leveraging a comprehensive database of over 50 CVEs, targeting Linux kernels from version 2.x to 6.x. This tool is intended for ethical hacking and security research within controlled environments, such as CTF competitions or authorized penetration testing engagements.

⚠️ Disclaimer: This tool is for educational and research purposes only. Unauthorized use on systems you do not own or have explicit permission to test is illegal and unethical. The author is not responsible for misuse or any resulting damages.

Features

Extensive CVE Database: Includes over 50 CVEs (2008–2024), covering exploits like Dirty COW, PwnKit, and Dirty Pipe.
Broad Kernel Support: Compatible with Linux kernels 2.x to 6.x, including tailored exploits for specific kernel versions.
Non-Compilation Exploits: Supports exploits that do not require a compiler, such as CVE-2009-1185 (udev), /etc/passwd modification, and sudo misconfigurations.
Environment Detection: Automatically identifies cPanel, CloudLinux, and containerized environments for targeted exploitation.
Robust Logging: Detailed, color-coded logging with timestamps, saved to /tmp/.unknown1337_<SESSION_ID>/compile_error.log for debugging.
Anti-Copy Protection: Uses a unique session ID and temporary file to prevent unauthorized script copying.
Network-Based Exploits: Scans for vulnerable services like SSH (CVE-2016-0777) and web servers (PHP-based exploits).
Automatic Cleanup: Removes temporary files from /tmp post-execution to maintain a clean environment.
cPanel/Jailkit Compatibility: Specialized exploits for restricted hosting environments, including php.ini modifications and cron job manipulation.
Multi-Compiler Support: Attempts compilation with gcc, cc, and clang to maximize compatibility.

Supported CVEs
The tool includes exploits for the following CVEs, organized by year:
2024

CVE-2024-1086: Netfilter nf_tables Use-After-Free
CVE-2024-0582: io_uring Privilege Escalation

2023

CVE-2023-32629: Local Privilege Escalation via Netfilter
CVE-2023-0386: OverlayFS Privilege Escalation

2022

CVE-2022-0847: Dirty Pipe (Multiple Variants)
CVE-2022-32250: Netfilter Use-After-Free
CVE-2022-2588: cls_route Use-After-Free

2021

CVE-2021-4034: PwnKit (Multiple Variants)
CVE-2021-3156: Baron Samedit (Multiple Variants)
CVE-2021-22555: Netfilter Heap Out-of-Bounds
CVE-2021-3490: eBPF ALU32 Bounds Tracking

2020

CVE-2020-14386: AF_PACKET Memory Corruption
CVE-2020-8835: eBPF Verifier Integer Truncation

2016 and Earlier

CVE-2016-5195: Dirty COW (Multiple Variants)
CVE-2015-1328: OverlayFS (Multiple Variants)
CVE-2013-2094: perf_events
CVE-2014-3153: futex
CVE-2017-16995: eBPF Verifier
CVE-2017-1000112: UDP Fragmentation Offload
CVE-2018-18955: subpage_mkwrite
CVE-2019-13272: ptrace
CVE-2019-12749: dbus-daemon-launch-helper
CVE-2008-0600: vmsplice
CVE-2009-1185: udev Privilege Escalation
CVE-2009-2692: sock_sendpage
CVE-2010-3904: RDS Socket

Installation

Clone the repository:
git clone https://github.com/<your-username>/unknown1337-auto-root.git
cd unknown1337-auto-root


Set execute permissions:
chmod +x unknown1337_v2.1.sh


Ensure dependencies are installed (optional, for compilation-based exploits):
sudo apt-get install gcc g++ wget curl



Usage
Run the script to initiate automated privilege escalation:
./unknown1337_v2.1.sh

For debugging, use the --debug flag to enable verbose output:
./unknown1337_v2.1.sh --debug

Output

Logs are saved in /tmp/.unknown1337_<SESSION_ID>/compile_error.log.
The script provides real-time feedback with color-coded messages (INFO, SUCCESS, WARNING, ERROR, EXPLOIT, ROOT).
If root access is achieved, a shell is spawned. Otherwise, a failure report is generated with debugging recommendations.

Example
$ ./unknown1337_v2.1.sh
[20:32:50][INFO] Gathering comprehensive system intelligence...
[20:32:51][INFO] Phase 0: Non-compilation-based exploits
[20:32:52][EXPLOIT] Found dbus helper - CVE-2019-12749
...
[20:32:56][WARNING] All exploitation attempts completed

Debugging Tips
If the script fails to achieve root access:

Check the log file: cat /tmp/.unknown1337_<SESSION_ID>/compile_error.log.
Verify dependencies: which gcc cc clang wget curl timeout.
Run in debug mode: ./unknown1337_v2.1.sh --debug.
Manually test non-compilation exploits:cd /tmp/.unknown1337_<SESSION_ID>
./udev_2009_1185.sh


Check system details: sudo -l, cat /proc/version, ls -l /tmp/.unknown1337_<SESSION_ID>.

cPanel/Jailkit Environments
The script is optimized for restricted environments like cPanel/CloudLinux:

Attempts to escape jailkit via writable php.ini, cron jobs, or misconfigured jailkit settings.
Creates malicious PHP files (/tmp/exploit.php) for web-based exploitation.
Tests for writable /etc/passwd and sudo misconfigurations.

Ethical Usage
This tool is designed for:

Security researchers analyzing Linux kernel vulnerabilities.
Penetration testers with explicit permission to test systems.
CTF participants solving privilege escalation challenges.

Do not use this tool on systems without authorization. Misuse may result in legal consequences.
Contributing
Contributions are welcome! Please:

Fork the repository.
Create a feature branch (git checkout -b feature/new-exploit).
Commit your changes (git commit -m "Add new CVE exploit").
Push to the branch (git push origin feature/new-exploit).
Open a pull request.

License
This project is licensed under the MIT License.
Acknowledgments

Inspired by public exploit databases like Exploit-DB and GitHub repositories.
Built for educational purposes to advance Linux security research.
