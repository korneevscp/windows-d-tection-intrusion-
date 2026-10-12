#define _WIN32_WINNT 0x0601
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <conio.h>
#include <shellapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")

#define MAX_ALERTS 256
#define MAX_ROWS 24
#define SCAN_INTERVAL_MS 10000
#define EVENT_BATCH_BYTES 65536

typedef struct {
    DWORD pid;
    char key[160];
} AlertKey;

typedef struct {
    DWORD pid;
    char name[MAX_PATH];
    char path[MAX_PATH];
    DWORD threads;
    SIZE_T memory;
    int suspicious;
} ProcessRow;

static AlertKey g_alerts[MAX_ALERTS];
static size_t g_alert_count = 0;
static unsigned long long g_scan_count = 0;
static unsigned int g_new_processes = 0;
static unsigned int g_suspicious_processes = 0;
static unsigned int g_connections = 0;
static unsigned int g_suspicious_connections = 0;
static char g_status[160] = "Initialisation";
static DWORD g_last_system_record = 0;
static DWORD g_last_application_record = 0;
static DWORD g_last_security_record = 0;
static unsigned int g_windows_events = 0;
static unsigned int g_security_events = 0;

static const char *g_allowlist[] = {
    "discord.exe", "discordcanary.exe", "discordptb.exe",
    "powershell.exe", "pwsh.exe", "powershell_ise.exe",
    "cmd.exe", "conhost.exe", " WindowsTerminal.exe",
    "explorer.exe", "svchost.exe", "lsass.exe", "csrss.exe",
    "winlogon.exe", "services.exe", "smss.exe", "wininit.exe",
    "taskhostw.exe", "RuntimeBroker.exe", "SearchHost.exe",
    "StartMenuExperienceHost.exe", "ShellExperienceHost.exe",
    "dwm.exe", "System", "Registry", "MsMpEng.exe",
    "SecurityHealthService.exe", "SecurityHealthSystray.exe",
    "OneDrive.exe", "steam.exe", "steamwebhelper.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe",
    "Code.exe", "devenv.exe", "notepad.exe", "notepad++.exe",
    "Teams.exe", "ms-teams.exe", "Spotify.exe", "obs64.exe"
};

static const char *g_suspicious_names[] = {
    "mimikatz.exe", "mimikatz", "psexec.exe", "paexec.exe",
    "pwdump.exe", "procdump.exe", "lazagne.exe", "rubeus.exe",
    "nanodump.exe", "keylogger.exe", "cryptolocker.exe",
    "meterpreter.exe", "nc.exe", "ncat.exe", "netcat.exe"
};

static int equals_i(const char *a, const char *b) {
    return _stricmp(a, b) == 0;
}

static void timestamp(char *out, size_t cap) {
    time_t now = time(NULL);
    struct tm tmv;
    localtime_s(&tmv, &now);
    strftime(out, cap, "%Y-%m-%d %H:%M:%S", &tmv);
}

static void ensure_log_dir(char *out, size_t cap) {
    DWORD n = GetEnvironmentVariableA("ProgramData", out, (DWORD)cap);
    if (!n || n >= cap) {
        snprintf(out, cap, "C:\\ProgramData");
    }
    strncat_s(out, cap, "\\KorneevIDS", _TRUNCATE);
    CreateDirectoryA(out, NULL);
}

static void log_alert(const char *severity, const char *message) {
    char dir[MAX_PATH * 2];
    char file[MAX_PATH * 2];
    char ts[40];
    ensure_log_dir(dir, sizeof(dir));
    snprintf(file, sizeof(file), "%s\\alerts.log", dir);
    timestamp(ts, sizeof(ts));
    FILE *f = NULL;
    if (fopen_s(&f, file, "a") == 0 && f) {
        fprintf(f, "[%s] [%s] %s\r\n", ts, severity, message);
        fclose(f);
    }
}

static int already_alerted(DWORD pid, const char *key) {
    for (size_t i = 0; i < g_alert_count; ++i) {
        if (g_alerts[i].pid == pid && equals_i(g_alerts[i].key, key)) return 1;
    }
    if (g_alert_count < MAX_ALERTS) {
        g_alerts[g_alert_count].pid = pid;
        strncpy_s(g_alerts[g_alert_count].key, sizeof(g_alerts[g_alert_count].key), key, _TRUNCATE);
        ++g_alert_count;
    } else {
        memmove(g_alerts, g_alerts + 1, (MAX_ALERTS - 1) * sizeof(AlertKey));
        g_alerts[MAX_ALERTS - 1].pid = pid;
        strncpy_s(g_alerts[MAX_ALERTS - 1].key, sizeof(g_alerts[MAX_ALERTS - 1].key), key, _TRUNCATE);
    }
    return 0;
}

static int is_allowlisted(const char *name) {
    for (size_t i = 0; i < sizeof(g_allowlist) / sizeof(g_allowlist[0]); ++i) {
        if (equals_i(name, g_allowlist[i])) return 1;
    }
    return 0;
}

static int suspicious_name(const char *name) {
    if (is_allowlisted(name)) return 0;
    for (size_t i = 0; i < sizeof(g_suspicious_names) / sizeof(g_suspicious_names[0]); ++i) {
        if (_stricmp(name, g_suspicious_names[i]) == 0) return 1;
    }
    return 0;
}

static void process_path(DWORD pid, char *out, size_t cap) {
    out[0] = '\0';
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!h) {
        strncpy_s(out, cap, "Acces refuse ou processus termine", _TRUNCATE);
        return;
    }
    DWORD n = (DWORD)cap;
    if (!QueryFullProcessImageNameA(h, 0, out, &n)) {
        if (!GetModuleFileNameExA(h, NULL, out, (DWORD)cap)) {
            strncpy_s(out, cap, "Chemin indisponible", _TRUNCATE);
        }
    }
    CloseHandle(h);
}

static int suspicious_system_path(const char *name, const char *path) {
    if (!(equals_i(name, "lsass.exe") || equals_i(name, "csrss.exe") ||
          equals_i(name, "winlogon.exe") || equals_i(name, "services.exe") ||
          equals_i(name, "smss.exe") || equals_i(name, "wininit.exe"))) return 0;
    char win[MAX_PATH];
    UINT n = GetWindowsDirectoryA(win, MAX_PATH);
    if (!n || n >= MAX_PATH) return 0;
    char expected[MAX_PATH];
    snprintf(expected, sizeof(expected), "%s\\System32\\", win);
    return _strnicmp(path, expected, strlen(expected)) != 0;
}

static int is_new_pid(DWORD pid) {
    static DWORD seen[4096];
    static size_t seen_count = 0;
    for (size_t i = 0; i < seen_count; ++i) if (seen[i] == pid) return 0;
    if (seen_count < sizeof(seen) / sizeof(seen[0])) seen[seen_count++] = pid;
    else {
        memmove(seen, seen + 1, (4095) * sizeof(DWORD));
        seen[4095] = pid;
    }
    return 1;
}

static void draw_line(void) {
    puts("+--------------------------------------------------------------------------------+");
}

static void draw_header(void) {
    system("cls");
    SetConsoleTitleA("KORNEEV IDS | Windows Security Monitor");
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    draw_line();
    puts("|                         KORNEEV IDS  |  WINDOWS MONITOR                       |");
    puts("|                Surveillance locale - detection non destructive                |");
    draw_line();
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

static void alert_event(DWORD pid, const char *key, const char *severity, const char *message) {
    if (already_alerted(pid, key)) return;
    log_alert(severity, message);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY);
    printf("  [ALERTE %s] %s\n", severity, message);
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    if (strcmp(severity, "CRITIQUE") == 0) {
        char title[128];
        snprintf(title, sizeof(title), "Korneev IDS - %s", severity);
        MessageBoxA(NULL, message, title, MB_ICONWARNING | MB_TOPMOST | MB_SETFOREGROUND);
    }
}

static void scan_processes(void) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        strncpy_s(g_status, sizeof(g_status), "Erreur enumeration processus", _TRUNCATE);
        return;
    }
    PROCESSENTRY32A pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);
    g_new_processes = 0;
    g_suspicious_processes = 0;
    if (Process32FirstA(snap, &pe)) {
        do {
            if (is_new_pid(pe.th32ProcessID)) ++g_new_processes;
            int suspicious = suspicious_name(pe.szExeFile);
            char path[MAX_PATH];
            path[0] = '\0';
            if (suspicious || equals_i(pe.szExeFile, "lsass.exe") || equals_i(pe.szExeFile, "csrss.exe") || equals_i(pe.szExeFile, "winlogon.exe") || equals_i(pe.szExeFile, "services.exe") || equals_i(pe.szExeFile, "smss.exe") || equals_i(pe.szExeFile, "wininit.exe")) {
                process_path(pe.th32ProcessID, path, sizeof(path));
            }
            if (suspicious) {
                ++g_suspicious_processes;
                char msg[1200];
                snprintf(msg, sizeof(msg), "Nom de processus associe a un outil sensible : %s | PID %lu | Chemin : %s. Verification humaine requise.", pe.szExeFile, pe.th32ProcessID, path[0] ? path : "indisponible");
                alert_event(pe.th32ProcessID, pe.szExeFile, "MOYEN", msg);
            }
            if (path[0] && suspicious_system_path(pe.szExeFile, path)) {
                char msg[1200];
                snprintf(msg, sizeof(msg), "Processus systeme dans un emplacement inattendu : %s | PID %lu | Chemin : %s", pe.szExeFile, pe.th32ProcessID, path);
                alert_event(pe.th32ProcessID, "SYSTEM_PATH", "CRITIQUE", msg);
            }
        } while (Process32NextA(snap, &pe));
    }
    CloseHandle(snap);
}

static int suspicious_port(DWORD port) {
    switch (port) {
        case 4444: case 5555: case 31337: case 12345: case 54321:
            return 1;
        default:
            return 0;
    }
}

static void port_to_string(DWORD value, char *out, size_t cap) {
    struct in_addr addr;
    addr.s_addr = value;
    const char *s = inet_ntoa(addr);
    strncpy_s(out, cap, s ? s : "?", _TRUNCATE);
}

static void scan_connections(void) {
    DWORD size = 0;
    DWORD rc = GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (rc != ERROR_INSUFFICIENT_BUFFER || size == 0) {
        g_connections = 0;
        g_suspicious_connections = 0;
        return;
    }
    PMIB_TCPTABLE_OWNER_PID table = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    if (!table) return;
    rc = GetExtendedTcpTable(table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    g_connections = 0;
    g_suspicious_connections = 0;
    if (rc == NO_ERROR) {
        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            MIB_TCPROW_OWNER_PID *r = &table->table[i];
            ++g_connections;
            DWORD local = ntohs((u_short)r->dwLocalPort);
            DWORD remote = ntohs((u_short)r->dwRemotePort);
            if (suspicious_port(local) || suspicious_port(remote)) {
                ++g_suspicious_connections;
                char local_ip[64], remote_ip[64], name[MAX_PATH] = "inconnu", path[MAX_PATH] = "indisponible";
                port_to_string(r->dwLocalAddr, local_ip, sizeof(local_ip));
                port_to_string(r->dwRemoteAddr, remote_ip, sizeof(remote_ip));
                HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
                if (snap != INVALID_HANDLE_VALUE) {
                    PROCESSENTRY32A pe;
                    ZeroMemory(&pe, sizeof(pe));
                    pe.dwSize = sizeof(pe);
                    if (Process32FirstA(snap, &pe)) {
                        do {
                            if (pe.th32ProcessID == r->dwOwningPid) {
                                strncpy_s(name, sizeof(name), pe.szExeFile, _TRUNCATE);
                                break;
                            }
                        } while (Process32NextA(snap, &pe));
                    }
                    CloseHandle(snap);
                }
                char msg[1000], key[160];
                snprintf(key, sizeof(key), "TCP_%lu_%lu_%lu", r->dwOwningPid, local, remote);
                snprintf(msg, sizeof(msg), "Connexion TCP sur port a surveiller | processus %s | PID %lu | %s:%lu -> %s:%lu. Un port seul ne prouve pas une infection.", name, r->dwOwningPid, local_ip, local, remote_ip, remote);
                if (!is_allowlisted(name)) alert_event(r->dwOwningPid, key, "FAIBLE", msg);
            }
        }
    }
    free(table);
}

static int interesting_event_id(DWORD id, const char *channel) {
    if (_stricmp(channel, "Security") == 0) {
        switch (id) {
            case 1102: case 4625: case 4697: case 4720: case 4728:
            case 4732: case 4756: case 4719: case 4964: case 4672:
                return 1;
            default: return 0;
        }
    }
    if (_stricmp(channel, "System") == 0) {
        switch (id) {
            case 12: case 13: case 41: case 1074: case 6005: case 6006:
            case 6008: case 7034: case 7036: case 7040: case 7045:
                return 1;
            default: return 0;
        }
    }
    if (_stricmp(channel, "Application") == 0) {
        switch (id) {
            case 1000: case 1001: case 1026: case 11707: case 11724:
                return 1;
            default: return 0;
        }
    }
    return 0;
}

static void scan_event_channel(const char *channel, DWORD *last_record) {
    HANDLE log_handle = OpenEventLogA(NULL, channel);
    if (!log_handle) return;
    DWORD bytes_read = 0, bytes_needed = 0;
    char *buffer = (char *)malloc(EVENT_BATCH_BYTES);
    if (!buffer) { CloseEventLog(log_handle); return; }
    if (!ReadEventLogA(log_handle, EVENTLOG_BACKWARDS_READ | EVENTLOG_SEQUENTIAL_READ,
                       0, buffer, EVENT_BATCH_BYTES, &bytes_read, &bytes_needed)) {
        free(buffer);
        CloseEventLog(log_handle);
        return;
    }
    DWORD newest_seen = *last_record;
    EVENTLOGRECORD *record = (EVENTLOGRECORD *)buffer;
    while ((BYTE *)record < (BYTE *)buffer + bytes_read) {
        DWORD id = record->EventID & 0xFFFF;
        if (record->RecordNumber > newest_seen) newest_seen = record->RecordNumber;
        if (record->RecordNumber > *last_record && interesting_event_id(id, channel)) {
            char msg[700];
            const char *level = "INFO";
            if (_stricmp(channel, "Security") == 0) {
                ++g_security_events;
                if (id == 1102 || id == 4697 || id == 4719) level = "MOYEN";
            } else if (id == 41 || id == 6008 || id == 7034 || id == 7045) {
                level = "MOYEN";
            }
            ++g_windows_events;
            snprintf(msg, sizeof(msg), "Evenement Windows | Journal=%s | ID=%lu | Enregistrement=%lu | Source=%s. Consulter l'Observateur d'evenements pour les details.",
                     channel, id, record->RecordNumber,
                     record->SourceNameOffset ? (char *)record + record->SourceNameOffset : "inconnue");
            char key[160];
            snprintf(key, sizeof(key), "EVT_%s_%lu", channel, record->RecordNumber);
            alert_event(0, key, level, msg);
        }
        if (record->Length == 0) break;
        record = (EVENTLOGRECORD *)((BYTE *)record + record->Length);
    }
    *last_record = newest_seen;
    free(buffer);
    CloseEventLog(log_handle);
}

static void scan_windows_events(void) {
    scan_event_channel("System", &g_last_system_record);
    scan_event_channel("Application", &g_last_application_record);
    scan_event_channel("Security", &g_last_security_record);
}

static void scan_resources(void) {
    MEMORYSTATUSEX mem;
    ZeroMemory(&mem, sizeof(mem));
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        if (mem.dwMemoryLoad >= 95) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Utilisation memoire tres elevee : %lu%%", mem.dwMemoryLoad);
            alert_event(0, "MEMORY_HIGH", "FAIBLE", msg);
        }
    }
    ULARGE_INTEGER free_bytes, total_bytes, total_free;
    if (GetDiskFreeSpaceExA("C:\\", &free_bytes, &total_bytes, &total_free) && total_bytes.QuadPart) {
        unsigned long used = 100 - (unsigned long)((total_free.QuadPart * 100) / total_bytes.QuadPart);
        if (used >= 98) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Espace disque C: critique : %lu%% utilise", used);
            alert_event(0, "DISK_HIGH", "FAIBLE", msg);
        }
    }
}

static void check_defender(void) {
    SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
    if (!manager) return;
    SC_HANDLE service = OpenServiceA(manager, "WinDefend", SERVICE_QUERY_STATUS);
    if (service) {
        SERVICE_STATUS_PROCESS status;
        DWORD needed = 0;
        if (QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (LPBYTE)&status, sizeof(status), &needed)) {
            if (status.dwCurrentState != SERVICE_RUNNING) {
                alert_event(0, "DEFENDER_STOPPED", "MOYEN", "Le service Windows Defender n'est pas en cours d'execution. Verifier l'etat dans Securite Windows.");
            }
        }
        CloseServiceHandle(service);
    }
    CloseServiceHandle(manager);
}

static void render_dashboard(void) {
    char ts[40];
    timestamp(ts, sizeof(ts));
    draw_header();
    printf("  Etat       : SURVEILLANCE ACTIVE\n");
    printf("  Dernier scan: %s\n", ts);
    printf("  Scan       : %llu\n", g_scan_count);
    printf("  Nouveaux PID observes ce scan : %u\n", g_new_processes);
    printf("  Indicateurs de processus sensibles : %u\n", g_suspicious_processes);
    printf("  Connexions TCP observees : %u\n", g_connections);
    printf("  Connexions avec ports a surveiller : %u\n", g_suspicious_connections);
    printf("  Evenements Windows pertinents : %u\n", g_windows_events);
    printf("  Evenements du journal Security : %u\n", g_security_events);
    draw_line();
    puts("  CONTROLES");
    puts("  [1] Lancer un scan immediat");
    puts("  [E] Ouvrir l'Observateur d'evenements Windows");
    puts("  [L] Ouvrir le journal d'alertes");
    puts("  [Q] Quitter");
    draw_line();
    puts("  Note : les detections par nom/port sont des indicateurs, pas une preuve.");
    printf("  Journal : %%ProgramData%%\\KorneevIDS\\alerts.log\n");
    printf("  Prochain scan automatique dans 10 secondes. Touche Q pour quitter.\n");
}

static void open_log(void) {
    char dir[MAX_PATH * 2], file[MAX_PATH * 2];
    ensure_log_dir(dir, sizeof(dir));
    snprintf(file, sizeof(file), "%s\\alerts.log", dir);
    ShellExecuteA(NULL, "open", file, NULL, NULL, SW_SHOWNORMAL);
}

int main(void) {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    for (;;) {
        ++g_scan_count;
        scan_processes();
        scan_connections();
        scan_resources();
        check_defender();
        scan_windows_events();
        strncpy_s(g_status, sizeof(g_status), "Surveillance active", _TRUNCATE);
        render_dashboard();
        DWORD start = GetTickCount();
        while (GetTickCount() - start < SCAN_INTERVAL_MS) {
            if (_kbhit()) {
                int c = _getch();
                if (c == 'q' || c == 'Q') {
                    WSACleanup();
                    return 0;
                }
                if (c == '1') {
                    start = 0;
                    break;
                }
                if (c == 'l' || c == 'L') open_log();
                if (c == 'e' || c == 'E') ShellExecuteA(NULL, "open", "eventvwr.msc", NULL, NULL, SW_SHOWNORMAL);
            }
            Sleep(100);
        }
    }
}
