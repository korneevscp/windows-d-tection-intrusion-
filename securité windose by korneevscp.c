#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <time.h>
#pragma comment(lib, "ws2_32")
#pragma comment(lib, "iphlpapi")
#pragma comment(lib, "advapi32")
#pragma comment(lib, "psapi")
#pragma comment(lib, "wininet")
#define MAX_PROCESSES 1000
#define MAX_CONNECTIONS 500

// Structures
typedef struct {
    char processName[MAX_PATH];
    DWORD pid;
    int isSuspicious;
} ProcessInfo;

typedef struct {
    DWORD localPort;
    DWORD remotePort;
    char remoteIP[64];
    DWORD pid;
} SimpleConnection;

// Variables globales
ProcessInfo baselineProcesses[MAX_PROCESSES];
int baselineCount = 0;
SimpleConnection activeConnections[MAX_CONNECTIONS];
int connectionCount = 0;

// Prototypes
void showPopup(const char* title, const char* message, UINT type);
void createBaseline();
void detectSuspiciousProcesses();
void monitorConnections();
void getProcessOwner(DWORD pid, char* username, size_t size);
int isProcessSuspicious(const char* name);
int isSuspiciousPort(int port);
void logAlert(const char* message);
void monitorSystemResources();
void checkRunningServices();
void printHeader();

// Fonction principale
int main() {
    system("color 0A");
    SetConsoleTitle("=== SYSTEME DE DETECTION D'INTRUSION WINDOWS ===");

    printHeader();

    printf("\n[*] Initialisation du systeme de detection...\n");
    Sleep(1000);

    showPopup("IDS Active", "Systeme de detection d'intrusion demarre !\n\nLes alertes apparaitront en popup.", MB_ICONINFORMATION);

    printf("[*] Creation de la baseline du systeme...\n");
    createBaseline();

    printf("\n[+] Surveillance continue activee\n");
    printf("[+] Notifications popup activees\n");
    printf("[+] Fichier log: C:\\IDS\\alerts.log\n");
    printf("[+] Appuyez sur Ctrl+C pour arreter\n\n");

    // Boucle de surveillance continue
    int scanNumber = 0;
    while(1) {
        scanNumber++;
        time_t now = time(NULL);
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

        printf("\n");
        printf("========================================\n");
        printf("  SCAN #%d - %s\n", scanNumber, timeStr);
        printf("========================================\n");

        detectSuspiciousProcesses();
        monitorConnections();
        monitorSystemResources();
        checkRunningServices();

        printf("\n[*] Prochain scan dans 60 secondes...\n");
        printf("[*] Surveillance active...\n");

        Sleep(60000); // 60 secondes
    }

    return 0;
}

void printHeader() {
    printf("\n");
    printf("  ================================================\n");
    printf("  ||                                            ||\n");
    printf("  ||  SYSTEME DE DETECTION D'INTRUSION (IDS)   ||\n");
    printf("  ||            Windows Edition                 ||\n");
    printf("  ||                                            ||\n");
    printf("  ||  Protection Active - Surveillance 24/7    ||\n");
    printf("  ||                                            ||\n");
    printf("  ================================================\n");
}

// Afficher une popup Windows
void showPopup(const char* title, const char* message, UINT type) {
    // Utiliser un thread séparé pour ne pas bloquer
    MessageBox(NULL, message, title, type | MB_TOPMOST | MB_SETFOREGROUND);
}

// Créer la baseline du système
void createBaseline() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;

    baselineCount = 0;

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur lors de la capture des processus\n");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (baselineCount < MAX_PROCESSES) {
                strcpy(baselineProcesses[baselineCount].processName, pe32.szExeFile);
                baselineProcesses[baselineCount].pid = pe32.th32ProcessID;
                baselineProcesses[baselineCount].isSuspicious = isProcessSuspicious(pe32.szExeFile);
                baselineCount++;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
    printf("[+] Baseline creee: %d processus enregistres\n", baselineCount);
}

// Détecter les processus suspects
void detectSuspiciousProcesses() {
    HANDLE hSnapshot;
    PROCESSENTRY32 pe32;
    char message[2048];
    int suspiciousFound = 0;
    int newProcessFound = 0;

    printf("\n[*] Analyse des processus en cours...\n");

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("[!] Erreur lors de la capture des processus\n");
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            // Vérifier si le processus est suspect
            if (isProcessSuspicious(pe32.szExeFile)) {
                suspiciousFound++;

                char username[256] = "Inconnu";
                getProcessOwner(pe32.th32ProcessID, username, sizeof(username));

                snprintf(message, sizeof(message),
                    "=== ALERTE MALWARE DETECTE ===\n\n"
                    "Processus: %s\n"
                    "PID: %lu\n"
                    "Utilisateur: %s\n\n"
                    "ACTION RECOMMANDEE:\n"
                    "Terminer ce processus immediatement !",
                    pe32.szExeFile, pe32.th32ProcessID, username);

                printf("[!] ALERTE CRITIQUE: %s (PID: %lu)\n", pe32.szExeFile, pe32.th32ProcessID);
                showPopup("MALWARE DETECTE", message, MB_ICONERROR);
                logAlert(message);
            }

            // Détecter les processus système dans des emplacements suspects
            if (strstr(pe32.szExeFile, "svchost.exe") ||
                strstr(pe32.szExeFile, "lsass.exe") ||
                strstr(pe32.szExeFile, "csrss.exe") ||
                strstr(pe32.szExeFile, "winlogon.exe")) {

                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProcess) {
                    char path[MAX_PATH];
                    if (GetModuleFileNameEx(hProcess, NULL, path, MAX_PATH)) {
                        // Convertir en minuscules pour comparaison
                        char lowerPath[MAX_PATH];
                        strcpy(lowerPath, path);
                        _strlwr(lowerPath);

                        // Vérifier si le chemin est suspect
                        if (!strstr(lowerPath, "system32") && !strstr(lowerPath, "syswow64")) {
                            snprintf(message, sizeof(message),
                                "=== ALERTE ROOTKIT POSSIBLE ===\n\n"
                                "Processus systeme suspect:\n"
                                "%s\n\n"
                                "PID: %lu\n"
                                "Emplacement anormal:\n%s\n\n"
                                "ATTENTION: Possible infection rootkit !",
                                pe32.szExeFile, pe32.th32ProcessID, path);

                            printf("[!] ROOTKIT SUSPECT: %s depuis %s\n", pe32.szExeFile, path);
                            showPopup("ALERTE ROOTKIT", message, MB_ICONERROR);
                            logAlert(message);
                        }
                    }
                    CloseHandle(hProcess);
                }
            }

            // Détecter les nouveaux processus
            int foundInBaseline = 0;
            for (int i = 0; i < baselineCount; i++) {
                if (strcmp(baselineProcesses[i].processName, pe32.szExeFile) == 0) {
                    foundInBaseline = 1;
                    break;
                }
            }

            if (!foundInBaseline && !isProcessSuspicious(pe32.szExeFile)) {
                newProcessFound++;
                printf("[*] Nouveau processus: %s (PID: %lu)\n", pe32.szExeFile, pe32.th32ProcessID);
            }

        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    if (suspiciousFound == 0 && newProcessFound == 0) {
        printf("[+] Aucune activite suspecte detectee\n");
    } else {
        printf("[*] Resume: %d processus suspects, %d nouveaux processus\n", suspiciousFound, newProcessFound);
    }
}

// Surveiller les connexions (version simplifiée)
void monitorConnections() {
    printf("\n[*] Surveillance des connexions reseau...\n");
    printf("[+] Analyse des ports en ecoute...\n");

    // Vérifier les ports suspects en écoute
    SOCKET testSocket;
    int suspiciousPorts[] = {4444, 5555, 6666, 31337, 1337, 12345, 54321};
    int numPorts = sizeof(suspiciousPorts) / sizeof(suspiciousPorts[0]);

    for (int i = 0; i < numPorts; i++) {
        testSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (testSocket != INVALID_SOCKET) {
            struct sockaddr_in addr;
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(suspiciousPorts[i]);

            // Tester si le port est en écoute
            if (bind(testSocket, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
                char message[512];
                snprintf(message, sizeof(message),
                    "=== PORT SUSPECT DETECTE ===\n\n"
                    "Port: %d\n"
                    "Statut: EN ECOUTE\n\n"
                    "Ce port est souvent utilise par:\n"
                    "- Backdoors\n"
                    "- Malwares\n"
                    "- Outils de piratage\n\n"
                    "Verifiez immediatement !",
                    suspiciousPorts[i]);

                printf("[!] ALERTE: Port suspect %d en ecoute !\n", suspiciousPorts[i]);
                showPopup("PORT SUSPECT", message, MB_ICONWARNING);
                logAlert(message);
            }
            closesocket(testSocket);
        }
    }

    printf("[+] Verification des ports terminee\n");
}

// Obtenir le propriétaire d'un processus
void getProcessOwner(DWORD pid, char* username, size_t size) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess == NULL) {
        strncpy(username, "Inconnu", size);
        return;
    }

    HANDLE hToken;
    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

        if (dwSize > 0) {
            PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwSize);
            if (pTokenUser != NULL) {
                if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                    char name[256] = "";
                    char domain[256] = "";
                    DWORD nameSize = sizeof(name);
                    DWORD domainSize = sizeof(domain);
                    SID_NAME_USE sidType;

                    if (LookupAccountSid(NULL, pTokenUser->User.Sid, name, &nameSize, domain, &domainSize, &sidType)) {
                        snprintf(username, size, "%s\\%s", domain, name);
                    } else {
                        strncpy(username, "Inconnu", size);
                    }
                }
                free(pTokenUser);
            }
        }
        CloseHandle(hToken);
    } else {
        strncpy(username, "Systeme", size);
    }

    CloseHandle(hProcess);
}

// Vérifier si un processus est suspect
int isProcessSuspicious(const char* name) {
    const char* suspiciousNames[] = {
        "nc.exe", "netcat", "ncat.exe",
        "mimikatz", "pwdump", "procdump",
        "keylog", "logger",
        "psexec", "paexec",
        "metasploit", "meterpreter",
        "cobalt", "beacon",
        "payload.exe", "shell.exe",
        "hack", "exploit",
        "backdoor", "trojan",
        "ransomware", "cryptolocker"
    };

    int numSuspicious = sizeof(suspiciousNames) / sizeof(suspiciousNames[0]);

    // Convertir en minuscules pour comparaison
    char lowerName[MAX_PATH];
    strncpy(lowerName, name, MAX_PATH);
    _strlwr(lowerName);

    for (int i = 0; i < numSuspicious; i++) {
        if (strstr(lowerName, suspiciousNames[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

// Vérifier si un port est suspect
int isSuspiciousPort(int port) {
    int suspiciousPorts[] = {4444, 5555, 6666, 31337, 1337, 12345, 54321, 9999, 8888};
    int numPorts = sizeof(suspiciousPorts) / sizeof(suspiciousPorts[0]);

    for (int i = 0; i < numPorts; i++) {
        if (port == suspiciousPorts[i]) {
            return 1;
        }
    }
    return 0;
}

// Enregistrer une alerte dans un fichier log
void logAlert(const char* message) {
    // Créer le dossier C:\IDS s'il n'existe pas
    CreateDirectory("C:\\IDS", NULL);

    FILE* logFile = fopen("C:\\IDS\\alerts.log", "a");
    if (logFile) {
        time_t now = time(NULL);
        char timeStr[100];
        strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&now));

        fprintf(logFile, "\n========================================\n");
        fprintf(logFile, "[%s]\n", timeStr);
        fprintf(logFile, "%s\n", message);
        fprintf(logFile, "========================================\n");
        fclose(logFile);
    }
}

// Surveiller les ressources système
void monitorSystemResources() {
    printf("\n[*] Surveillance des ressources systeme...\n");

    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(MEMORYSTATUSEX);
    GlobalMemoryStatusEx(&memInfo);

    DWORD memoryUsage = memInfo.dwMemoryLoad;

    printf("[*] Utilisation memoire: %lu%%\n", memoryUsage);

    if (memoryUsage > 90) {
        char message[512];
        snprintf(message, sizeof(message),
            "=== ALERTE MEMOIRE ===\n\n"
            "Utilisation memoire critique: %lu%%\n\n"
            "Causes possibles:\n"
            "- Fuite memoire (memory leak)\n"
            "- Malware en execution\n"
            "- Processus suspect\n\n"
            "Verifiez les processus actifs !",
            memoryUsage);

        printf("[!] ALERTE: %s\n", message);
        showPopup("MEMOIRE CRITIQUE", message, MB_ICONWARNING);
        logAlert(message);
    }

    // Vérifier l'espace disque
    ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
    if (GetDiskFreeSpaceEx("C:\\", &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
        DWORD diskUsage = 100 - (DWORD)((totalNumberOfFreeBytes.QuadPart * 100) / totalNumberOfBytes.QuadPart);
        printf("[*] Utilisation disque C: %lu%%\n", diskUsage);

        if (diskUsage > 95) {
            char message[512];
            snprintf(message, sizeof(message),
                "=== ALERTE DISQUE PLEIN ===\n\n"
                "Utilisation disque C: %lu%%\n\n"
                "Risque:\n"
                "- Ransomware encryptant les fichiers\n"
                "- Logiciel malveillant creant des fichiers\n\n"
                "Action: Verifier les fichiers recents !",
                diskUsage);

            showPopup("DISQUE PLEIN", message, MB_ICONWARNING);
            logAlert(message);
        }
    }
}

// Vérifier les services en cours d'exécution
void checkRunningServices() {
    printf("\n[*] Verification des services critiques...\n");

    SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
    if (schSCManager) {
        // Vérifier Windows Defender
        SC_HANDLE schService = OpenService(schSCManager, "WinDefend", SERVICE_QUERY_STATUS);
        if (schService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD dwBytesNeeded;

            if (QueryServiceStatusEx(schService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp,
                                     sizeof(SERVICE_STATUS_PROCESS), &dwBytesNeeded)) {
                if (ssp.dwCurrentState != SERVICE_RUNNING) {
                    char message[512];
                    snprintf(message, sizeof(message),
                        "=== ALERTE SECURITE ===\n\n"
                        "Windows Defender est DESACTIVE !\n\n"
                        "Risque:\n"
                        "- Systeme non protege\n"
                        "- Possible malware\n\n"
                        "Action: Reactiver immediatement !");

                    printf("[!] ALERTE: Windows Defender desactive !\n");
                    showPopup("DEFENDER DESACTIVE", message, MB_ICONERROR);
                    logAlert(message);
                } else {
                    printf("[+] Windows Defender: ACTIF\n");
                }
            }
            CloseServiceHandle(schService);
        }
        CloseServiceHandle(schSCManager);
    }

    printf("[+] Verification des services terminee\n");
}
