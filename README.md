# 🔍 Phân tích và So sánh hai mẫu StealC V2 bằng Phương pháp Kết hợp (Hybrid Malware Analysis)

![Platform](https://img.shields.io/badge/Platform-Windows%20x64-blue)
![Analysis](https://img.shields.io/badge/Analysis-Static%20%26%20Dynamic-red)
![Malware Family](https://img.shields.io/badge/Malware-StealC%20V2-orange)
![Course](https://img.shields.io/badge/PTIT-INT14164-green)

> ⚠️ **CẢNH BÁO AN TOÀN (DISCLAIMER):** Tài liệu và các chỉ dấu kỹ thuật trong repository này chỉ phục vụ mục đích nghiên cứu học thuật, đào tạo An toàn thông tin và phòng thủ hệ thống (Blue Team / Threat Hunting). Tuyệt đối không thực thi các tệp mẫu trên máy thật hoặc hệ thống sản xuất.

---

## 📌 Tổng quan dự án

Dự án thuộc học phần **Phân tích mã độc (INT14164)** – Khoa An toàn thông tin, Học viện Công nghệ Bưu chính Viễn thông (PTIT). Báo cáo thực hiện phân tích chuyên sâu và đối chiếu hai biến thể liên quan đến họ mã độc đánh cắp thông tin (**Information Stealer**) **StealC V2** trên hệ điều hành Windows[cite: 6, 11].

Bằng cách kết hợp **Phân tích tĩnh (Static Analysis)** và **Phân tích động (Dynamic Analysis)** trong môi trường máy ảo cô lập, nghiên cứu làm rõ cấu trúc PE, kỹ thuật che giấu/đóng gói, luồng thực thi, hành vi hệ thống và trích xuất bộ quy tắc phát hiện (IOC, YARA, Sigma, Sysmon, SPL/KQL)[cite: 11, 12, 13, 48, 50].

---

## 🎯 Mục tiêu chính

1. **Định danh & Giải mã cấu trúc:** Xác định kiến trúc tệp PE, trình biên dịch, thành phần nhúng và cơ chế giải mã/giải nén payload[cite: 12].
2. **Kiểm chứng hành vi thực tế:** Đối chiếu các giả thuyết tĩnh với log hệ thống (tiến trình, tệp, Registry, lưu lượng mạng) trong môi trường sandbox cô lập[cite: 12].
3. **So sánh đối chiếu:** Phân tích sự khác biệt giữa biến thể sử dụng Go Loader và biến thể C++ nhúng PE trực tiếp[cite: 12, 41].
4. **Detection Engineering:** Xây dựng bộ IOC, ánh xạ kỹ thuật theo khung **MITRE ATT&CK**, viết luật **YARA**, **Sigma**, cấu hình **Sysmon** và truy vấn săn tìm trên **Splunk / Microsoft Defender XDR**[cite: 12, 45, 48, 50].

---

## 🧪 Thông tin hai mẫu phân tích

| Thuộc tính | Mẫu 1 (`OurNew.exe` - Go Loader) | Mẫu 2 (`Mau2.bin` - StealC V2) |
| :--- | :--- | :--- |
| **SHA-256** | `655d159778124a3e86adaa7fb139de2c107b9936f2d719b54756de98b8135deb`[cite: 14] | `ef767d259cbb694fb895ba874810f37d4bcc5fdf375ae7e70dc72bff4ccecba4`[cite: 14] |
| **Kích thước** | `2,570,240 bytes` (~2.45 MiB)[cite: 14, 17] | `784,384 bytes` (~766 KiB)[cite: 14, 24] |
| **Định dạng / Kiến trúc** | PE64 (AMD64), Windows GUI[cite: 14, 17] | PE32+ (AMD64), Windows GUI[cite: 14, 25] |
| **Ngôn ngữ / Compiler** | Golang (1.18.x - 1.24.0)[cite: 14, 17] | C/C++ (Microsoft Visual Studio 2026)[cite: 24] |
| **Kỹ thuật che giấu** | Giả mạo metadata `DISM.EXE`, Timestomp, mã hóa chuỗi XOR, payload nén `zlib` + mã hóa `RC4` trong `.data`[cite: 23, 31, 41] | Nhúng trực tiếp một tệp PE64 (`163,840 bytes`, SHA-256: `083c9888...221aa7`) tại offset `0x8F120` trong section `.data`[cite: 26, 40] |
| **Hành vi nổi bật** | Giải mã và thả payload vào `%TEMP%\<16_hex>.exe`, chạy tiến trình con, gửi HTTP POST JSON tới C2 `193.111.117.22:80`[cite: 29, 30, 32] | Truy vấn cấu hình Internet Settings, tra cứu các thư mục `INetCache`, `INetCookies`, `History.IE5`[cite: 34, 35, 37] |

---

## 🛠️ Công cụ & Môi trường thực nghiệm

* **Môi trường Lab:** VMware Workstation (Windows 10 Pro x64 22H2 cô lập hoàn toàn, mạng Host-only / LAN Segment, không kết nối Internet thật)[cite: 29, 33].
* **Phân tích tĩnh:** Detect It Easy (DiE), PeStudio, Sysinternals Strings, FLOSS, `llvm-objdump`, `xxd`, GoReSym, Ghidra 12.2, Python (script giải mã payload & so sánh Import Table)[cite: 13, 22, 23, 24].
* **Phân tích động & Giả lập mạng:** Process Monitor (Procmon), Process Explorer, Regshot, Autoruns, FakeNet-NG, INetSim, Wireshark / `tcpdump`[cite: 13, 33].

---

## 🗺️ Ánh xạ MITRE ATT&CK

| Tactic | Technique ID | Tên kỹ thuật | Bằng chứng ghi nhận |
| :--- | :--- | :--- | :--- |
| **Execution** | `T1204.002` | User Execution: Malicious File | Yêu cầu thực thi tệp thực thi Windows GUI (Mẫu 1 yêu cầu quyền Administrator/UAC)[cite: 29, 42] |
| **Defense Evasion** | `T1027.002` / `T1027.009` | Software Packing / Embedded Payloads | Mẫu 1 nhúng payload RC4+zlib trong `.data`; Mẫu 2 nhúng PE64 trong `.data`[cite: 43] |
| **Defense Evasion** | `T1140` | Deobfuscate/Decode Files or Information | Giải mã chuỗi XOR, giải mã payload bằng khóa RC4 `acb4c6f45a3923b57e6e672fc24c76a1` và giải nén `zlib`[cite: 23, 42] |
| **Defense Evasion** | `T1036.005` | Masquerading: Match Legitimate Name | Mẫu 1 giả mạo metadata của công cụ hệ thống `DISM.EXE`[cite: 43] |
| **Defense Evasion** | `T1070.006` | Indicator Removal: Timestomp | Mẫu 1 dùng `SetBasicInformationFile` đặt lại thời gian tệp về `13/10/2026 09:11:57`[cite: 30, 43] |
| **Defense Evasion** | `T1622` | Debugger Evasion | Mẫu 1 đọc thanh ghi gỡ lỗi `Dr0-Dr3` (`CONTEXT_DEBUG_REGISTERS`)[cite: 23, 43]; Mẫu 2 import `IsDebuggerPresent`[cite: 25] |
| **Discovery** | `T1082` | System Information Discovery | Đọc giá trị `ComputerName` và thông tin môi trường hệ thống[cite: 30, 43] |
| **Credential Access** | `T1555.003` | Credentials from Web Browsers | Mẫu 2 truy cập `INetCookies` và chứa chuỗi nhắm tới `Local State` (`app_bound_encrypted_key`) của Chrome, Edge, Brave[cite: 27, 43] |
| **Command & Control** | `T1071.001` | Application Layer Protocol: Web Protocols | Mẫu 1 gửi yêu cầu `HTTP POST` (`Content-Type: application/json`) trực tiếp tới `193.111.117.22:80`[cite: 32, 43] |

---

## 🛡️ Quy tắc Phát hiện & Săn tìm (Detection Rules)

### 1. Luật YARA (Phát hiện Go Loader - Mẫu 1)
```yara
rule StealC_GoLoader_hzglqkrxt {
    meta:
        description = "Detects StealC V2 Go Loader masquerading as DISM.EXE"
        author = "Group 04 - PTIT"
        date = "2026-11-15"
    strings:
        $go = "Go build ID:" ascii
        $pkg1 = "hzglqkrxt/main.go" ascii
        $pkg2 = "hzglqkrxt/stealth/" ascii
        $sys1 = "do_syscall_indirect" ascii
        $sys2 = "GetTrampoline" ascii
        $peb = ".GetPEB" ascii
        $exec = "os/exec.(*Cmd).Start" ascii
        $rc4 = "crypto/rc4.(*Cipher).XORKeyStream" ascii
        $dism = "DISM.EXE" wide
    condition:
        uint16(0) == 0x5A4D and $go and
        (1 of ($pkg*) or (2 of ($sys1,$sys2, $peb) and$exec and $rc4)) and$dism
}