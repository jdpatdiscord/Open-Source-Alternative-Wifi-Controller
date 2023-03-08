#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <io.h>
#include <fcntl.h>

#include <Windows.h>

#include <wlanapi.h>
#include <wtypes.h>

typedef struct _WLAN_CALLBACK_INFO {
    GUID InterfaceGuid;
    HANDLE scanEvent;
    DWORD succeeded;
} WLAN_CALLBACK_INFO, *PWLAN_CALLBACK_INFO;

// the following is defined and used because of mingw
#define O_WLAN_PROFILE_GROUP_POLICY                   0x00000001
#define O_WLAN_PROFILE_USER                           0x00000002
#define O_WLAN_PROFILE_GET_PLAINTEXT_KEY              0x00000004
#define O_WLAN_PROFILE_CONNECTION_MODE_SET_BY_CLIENT  0x00010000
#define O_WLAN_PROFILE_CONNECTION_MODE_AUTO           0x00020000

#define O_WLAN_NOTIFICATION_SOURCE_ALL 0xffff

#define O_WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES           0x00000001
#define O_WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES   0x00000002

#define O_WLAN_AVAILABLE_NETWORK_CONNECTED                    0x00000001  // This network is currently connected
#define O_WLAN_AVAILABLE_NETWORK_HAS_PROFILE                  0x00000002  // There is a profile for this network
#define O_WLAN_AVAILABLE_NETWORK_CONSOLE_USER_PROFILE         0x00000004  // The profile is the active console user's per user profile
#define O_WLAN_AVAILABLE_NETWORK_INTERWORKING_SUPPORTED       0x00000008  // Interworking is supported
#define O_WLAN_AVAILABLE_NETWORK_HOTSPOT2_ENABLED             0x00000010  // Hotspot2 is enabled
#define O_WLAN_AVAILABLE_NETWORK_ANQP_SUPPORTED               0x00000020  // ANQP is supported
#define O_WLAN_AVAILABLE_NETWORK_HOTSPOT2_DOMAIN              0x00000040  // Domain network 
#define O_WLAN_AVAILABLE_NETWORK_HOTSPOT2_ROAMING             0x00000080  // Roaming network
#define O_WLAN_AVAILABLE_NETWORK_AUTO_CONNECT_FAILED          0x00000100  // This network failed to connect

#if defined( __MINGW32__ ) || defined(__MINGW64__)
typedef VOID(*T_WlanFreeMemory)(PVOID mem);
typedef DWORD(*T_WlanOpenHandle)(DWORD dwClientVersion, PVOID pReserved, PDWORD pdwNegotiatedVersion, PHANDLE phClientHandle);
typedef DWORD(*T_WlanEnumInterfaces)(HANDLE hClientHandle, PVOID pReserved, PWLAN_INTERFACE_INFO_LIST* ppInterfaceList);
typedef DWORD(*T_WlanDisconnect)(HANDLE hClientHandle, const GUID* pInterfaceGuid, PVOID pReserved);
typedef DWORD(*T_WlanGetProfileList)(HANDLE hClientHandle, const GUID* pInterfaceGuid, PVOID pReserved, PWLAN_PROFILE_INFO_LIST* ppProfileList);
typedef DWORD(*T_WlanGetProfile)(HANDLE hClientHandle, const GUID* pInterfaceGuid, LPCWSTR strProfileName, PVOID pReserved, LPWSTR* pstrProfileXml, PDWORD pdwFlags, PDWORD pdwGrantedAccess);
typedef DWORD(*T_WlanRegisterNotification)(HANDLE hClientHandle, DWORD dwNotifSource, BOOL bIgnoreDuplicate, WLAN_NOTIFICATION_CALLBACK funcCallback, PVOID pCallbackCtx, PVOID pReserved, PDWORD pdwPrevNotifSource);
typedef DWORD(*T_WlanScan)(HANDLE hClientHandle, const GUID* pInterfaceGuid, const PDOT11_SSID pDot11Ssid, const PWLAN_RAW_DATA pIeData, PVOID pReserved);
typedef DWORD(*T_WlanGetAvailableNetworkList)(HANDLE hClientHandle, const GUID* pInterfaceGuid, DWORD dwFlags, PVOID pReserved, PWLAN_AVAILABLE_NETWORK_LIST* ppAvailableNetworkList);
typedef DWORD(*T_WlanConnect)(HANDLE hClientHandle, const GUID* pInterfaceGuid, const PWLAN_CONNECTION_PARAMETERS pConnectionParameters, PVOID pReserved);
typedef DWORD(*T_WlanSetProfile)(HANDLE hClientHandle, const GUID* pInterfaceGuid, DWORD dwFlags, LPCWSTR strProfileXml, LPCWSTR strAllUserProfileSecurity, BOOL bOverwrite, PVOID pReserved, DWORD* pdwReasonCode);
typedef DWORD(*T_WlanCloseHandle)(HANDLE hClientHandle, PVOID pReserved);
typedef DWORD(*T_WlanReasonCodeToString)(DWORD dwReasonCode, DWORD dwBufferSize, PWCHAR pStringBuffer, PVOID pReserved);

T_WlanFreeMemory F_WlanFreeMemory = NULL;
T_WlanOpenHandle F_WlanOpenHandle = NULL;
T_WlanEnumInterfaces F_WlanEnumInterfaces = NULL;
T_WlanDisconnect F_WlanDisconnect = NULL;
T_WlanGetProfileList F_WlanGetProfileList = NULL;
T_WlanGetProfile F_WlanGetProfile = NULL;
T_WlanRegisterNotification F_WlanRegisterNotification = NULL;
T_WlanScan F_WlanScan = NULL;
T_WlanGetAvailableNetworkList F_WlanGetAvailableNetworkList = NULL;
T_WlanConnect F_WlanConnect = NULL;
T_WlanSetProfile F_WlanSetProfile = NULL;
T_WlanCloseHandle F_WlanCloseHandle = NULL;
T_WlanReasonCodeToString F_WlanReasonCodeToString = NULL;

#else
#define F_WlanFreeMemory WlanFreeMemory
#define F_WlanOpenHandle WlanOpenHandle
#define F_WlanEnumInterfaces WlanEnumInterfaces
#define F_WlanDisconnect WlanDisconnect
#define F_WlanGetProfileList WlanGetProfileList
#define F_WlanGetProfile WlanGetProfile
#define F_WlanRegisterNotification WlanRegisterNotification
#define F_WlanScan WlanScan
#define F_WlanGetAvailableNetworkList WlanGetAvailableNetworkList
#define F_WlanConnect WlanConnect
#define F_WlanSetProfile WlanSetProfile
#define F_WlanCloseHandle WlanCloseHandle
#define F_WlanReasonCodeToString WlanReasonCodeToString
#endif

//#pragma comment(lib, "wlanapi.lib")
 
int bSilentMode = 0;

int bLoadInterfaces = 0;
int bLoadNetworks = 0;
int bLoadProfiles = 0;
int bExportProfiles = 0;

int bPassFlag = 0;
int bSsidFlag = 0;
int bProfileFlag = 0;
int bImportProfileFlag = 0;
int bVerboseFlag = 0;

int bDisconnectFlag = 0;

int bListInterfacesFlag = 0;
int bListNetworksFlag = 0;
int bListProfilesFlag = 0;

DWORD dwWaitMillis = 30000;

char* targetProfile = NULL;
char* targetSsid = NULL;
char* networkPass = NULL;
char* newProfileName = (char*)"(Unknown)";
char* existingProfileName = NULL;

#define COND_ERR(cond, msg) if (cond) { if (!bSilentMode) { puts(msg); }; exit(1); }

static const char* intro_en = ""\
        "Open Source Alternative Wi-Fi Controller (OSAWC) Copyright 2022, jdpatdiscord (alias)"                      "\n" \
        ""                                                                                                           "\n" \
        "FLAG | SHORTHAND | ARG COUNT | DESCRIPTION"                                                                 "\n" \
        "/n,  (SSID)        1   Specify SSID (Name) of network to connect to."                                       "\n" \
        "/k,  (Password)    1   Specify network key (password)"                                                      "\n" \
        "/c,  (New Profile) 1   Specify a new profile name to use for connecting."                                   "\n" \
        "/p,  (Profile)     1   Specify existing connection profile to connect with."                                "\n" \
        "/d,  (Disconnect)  1   Disconnect from all interfaces.                     "                                "\n" \
        "/li, (List)        0   Generate a list of interfaces"                                                       "\n" \
        "/ln, (List)        0   Generate a list of networks"                                                         "\n" \
        "/ep, (Export)      0   Export all existing connection profiles to disk as XML (requires Administrator)"     "\n" \
        "/ip, (Import)      1   Import an existing XML file describing a Wi-Fi profile."                             "\n" \
        "/t,  (T-Limit)     1   Specify a integer time limit for scanning Wi-Fi networks, in milliseconds."          "\n" \
        "/v,  (Verbose)     0   More information printed"                                                            "\n" \
/*      "/s,  (Silent)      0   A mode where no output whatsoever is generated."                                     "\n" \ */
        ""                                                                                                           "\n" \
        "Connect to Wi-Fi:                   osawc.exe /n ssid_here /k passwd_here /c new_profile_name"              "\n" \
        "Disconnect from Wi-Fi:              osawc.exe /d"                                                           "\n" \
        "Export network profiles as XML:     osawc.exe /ep"                                                          "\n" \
        "Import network profiles as XML:     osawc.exe /ip <profile.XML>"                                            "\n" \
        "Disconnect from Wi-Fi:              osawc.exe /d"                                                           "\n" ;

void arg_parser(int argc, char* argv[])
{
    // argv[0] is program name, typically

    int i; // current argument index

    //if (argc > 1)
    {
        for (i = 1; i < argc; ++i)
        {
            {
                const char* new_flag = argv[i];
                if (!strcmp(new_flag, "/ep"))
                {
                    bLoadInterfaces = 1;
                    bLoadProfiles = 1;
                    bExportProfiles = 1;
                    continue;
                }
                if (!strcmp(new_flag, "/ip"))
                {
                    COND_ERR(bImportProfileFlag != 0, "/n has already been set");
                    bImportProfileFlag = 1;
                    bLoadInterfaces = 1;
                    bLoadProfiles = 1;
                    if (argc >= i - 1)
                    {
                        existingProfileName = argv[++i];
                        continue;
                    }
                    else
                    {
                        puts("Argument required"); exit(0);
                    }
                    break;
                }
                if (!strcmp(new_flag, "/n"))
                {
                    COND_ERR(bSsidFlag != 0, "/n has already been set");
                    bLoadInterfaces = 1;
                    bLoadNetworks = 1;
                    bSsidFlag = 1;
                    if (argc >= i - 1)
                    {
                        targetSsid = argv[++i];
                        continue;
                    }
                    else
                    {
                        puts("Argument required"); exit(0);
                    }
                    break;
                }
                if (!strcmp(new_flag, "/k"))
                {
                    COND_ERR(bPassFlag != 0, "/k has already been set");
                    bLoadInterfaces = 1;
                    bLoadNetworks = 1;
                    bPassFlag = 1;
                    if (argc >= i - 1)
                    {
                        networkPass = argv[++i];
                        continue;
                    }
                    else
                    {
                        puts("Argument required"); exit(0);
                    }
                    break;
                }
                if (!strcmp(new_flag, "/p"))
                {
                    COND_ERR(bProfileFlag != 0, "/p has already been set");
                    bLoadInterfaces = 1;
                    bLoadNetworks = 1;
                    bProfileFlag = 1;
                    if (argc >= i - 1)
                    {
                        targetProfile = argv[++i];
                        continue;
                    }
                    else
                    {
                        puts("Argument required"); exit(0);
                    }
                    break;
                }
                if (!strcmp(new_flag, "/c"))
                {
                    //COND_ERR(bPassFlag != 0, "/c has already been set");
                    if (argc >= i - 1)
                    {
                        newProfileName = argv[++i];
                        continue;
                    }
                    break;
                }
                if (!strcmp(new_flag, "/d"))
                {
                    bDisconnectFlag = 1;
                    bLoadInterfaces = 1;
                    continue;
                }
                //if (!strcmp(new_flag, "/s"))
                //{
                //    bSilentMode = 1;
                //    continue;
                //}
                if (!strcmp(new_flag, "/li"))
                {
                    bLoadInterfaces = 1;
                    bListInterfacesFlag = 1;
                    continue;
                }
                if (!strcmp(new_flag, "/ln"))
                {
                    bLoadInterfaces = 1;
                    bLoadNetworks = 1;
                    bListNetworksFlag = 1;
                    continue;
                }
                if (!strcmp(new_flag, "/lp"))
                {
                    bLoadInterfaces = 1;
                    bListProfilesFlag = 1;
                    continue;
                }
                if (!strcmp(new_flag, "/v"))
                {
                    bVerboseFlag = 1;
                    continue;
                }
                if (!strcmp(new_flag, "/t"))
                {
                    //dwWaitMillis = atoi()
                    if (argc >= i - 1)
                    {
                        dwWaitMillis = atoi(argv[++i]);
                        if (dwWaitMillis == 0) // if invalid:
                            dwWaitMillis = 30000;
                        continue;
                    }
                    else
                    {
                        puts("Argument required"); exit(0);
                    }
                    continue;
                }
            }
        }
    }
}

static const char* const dot11_auth_algorithm_str[] = {
    "(NULL)",
    "DOT11_AUTH_ALGO_80211_OPEN",
    "DOT11_AUTH_ALGO_80211_SHARED_KEY (WEP)",
    "DOT11_AUTH_ALGO_WPA (WPA)",
    "DOT11_AUTH_ALGO_WPA_PSK (WPA-PSK)",
    "DOT11_AUTH_ALGO_WPA_NONE", //?
    "DOT11_AUTH_ALGO_RSNA (WPA2)",
    "DOT11_AUTH_ALGO_RSNA_PSK (WPA2-PSK)",
    "DOT11_AUTH_ALGO_WPA3 (WPA3)",
    "DOT11_AUTH_ALGO_WPA3_SAE (WPA3-SAE)",
    "DOT11_AUTH_ALGO_OWE",
    "DOT11_AUTH_ALGO_WPA3_ENT"
};

const char* get_dot11_auth_string_enum(DOT11_AUTH_ALGORITHM algo)
{
    if (algo >= 1 && algo <= 12)
    {
        return dot11_auth_algorithm_str[algo];
    }
    return "(Unknown)";
}

const char* get_dot11_cipher_string_enum(DOT11_CIPHER_ALGORITHM value)
{
    switch ((unsigned)value)
    {
        case 0: return "DOT11_CIPHER_ALGO_NONE";
        case 1: return "DOT11_CIPHER_ALGO_WEP40";
        case 2: return "DOT11_CIPHER_ALGO_TKIP";
        case 4: return "DOT11_CIPHER_ALGO_CCMP";
        case 5: return "DOT11_CIPHER_ALGO_WEP104";
        case 6: return "DOT11_CIPHER_ALGO_BIP";
        case 8: return "DOT11_CIPHER_ALGO_GCMP";
        case 9: return "DOT11_CIPHER_ALGO_GCMP_256";
        case 10: return "DOT11_CIPHER_ALGO_CCMP_256";
        case 11: return "DOT11_CIPHER_ALGO_BIP_GMAC_128";
        case 12: return "DOT11_CIPHER_ALGO_BIP_GMAC_256";
        case 13: return "DOT11_CIPHER_ALGO_BIP_CMAC_256";
        case 256: return "DOT11_CIPHER_ALGO_WPA_USE_GROUP";
        case 257: return "DOT11_CIPHER_ALGO_WEP";

        default: return "(Unknown)";
    }
}

const char* get_interface_string_enum(WLAN_INTERFACE_STATE value)
{
    switch (value)
    {
        case wlan_interface_state_not_ready:             return "wlan_interface_state_not_ready";
        case wlan_interface_state_connected:             return "wlan_interface_state_connected";
        case wlan_interface_state_ad_hoc_network_formed: return "wlan_interface_state_ad_hoc_network_formed";
        case wlan_interface_state_disconnecting:         return "wlan_interface_state_disconnecting";
        case wlan_interface_state_disconnected:          return "wlan_interface_state_disconnected";
        case wlan_interface_state_associating:           return "wlan_interface_state_associating";
        case wlan_interface_state_discovering:           return "wlan_interface_state_discovering";
        case wlan_interface_state_authenticating:        return "wlan_interface_state_authenticating";
        default:
            return "(Unknown)";
    }
}

PWLAN_INTERFACE_INFO_LIST pInterfaceList = NULL;
PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
PWLAN_PROFILE_INFO_LIST pProfileList = NULL;

void osawc_free()
{
    if (pInterfaceList)
    {
        F_WlanFreeMemory(pInterfaceList);
        pInterfaceList = NULL;
    }
    if (pNetworkList)
    {
        F_WlanFreeMemory(pNetworkList);
        pNetworkList = NULL;
    }
    if (pProfileList)
    {
        F_WlanFreeMemory(pProfileList);
        pProfileList = NULL;
    }
}

void OupScanCb(WLAN_NOTIFICATION_DATA* notif, PVOID userdata)
{
    PWLAN_CALLBACK_INFO cbInfo = (PWLAN_CALLBACK_INFO)userdata;
    if (!cbInfo)
        return;
    if (cbInfo->InterfaceGuid != notif->InterfaceGuid)
        return;
    if (notif->NotificationCode == wlan_notification_acm_scan_complete || notif->NotificationCode == wlan_notification_acm_scan_fail)
    {
        cbInfo->succeeded = (notif->NotificationCode == wlan_notification_acm_scan_complete);
        SetEvent(cbInfo->scanEvent);
    }
}

const wchar_t* templateF_WlanProfileXml = LR"(<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>%S</name>
    <SSIDConfig>
        <SSID>
            <name>%S</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <autoSwitch>false</autoSwitch>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>%S</keyType>
                <protected>false</protected>
                <keyMaterial>%S</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>)";

int main(int argc, char* argv[])
{
    if (argc <= 1)
    {
        puts(intro_en);
        return 0;
    }
    arg_parser(argc, argv);

#if defined(__MINGW32__) || defined(__MINGW64__)
    LoadLibraryA("wlanapi.dll");
    HMODULE hWlanapiDll = GetModuleHandleA("wlanapi.dll");

    F_WlanFreeMemory = (T_WlanFreeMemory)GetProcAddress(hWlanapiDll, "WlanFreeMemory");
    F_WlanOpenHandle = (T_WlanOpenHandle)GetProcAddress(hWlanapiDll, "WlanOpenHandle");
    F_WlanEnumInterfaces = (T_WlanEnumInterfaces)GetProcAddress(hWlanapiDll, "WlanEnumInterfaces");
    F_WlanDisconnect = (T_WlanDisconnect)GetProcAddress(hWlanapiDll, "WlanDisconnect");
    F_WlanGetProfileList = (T_WlanGetProfileList)GetProcAddress(hWlanapiDll, "WlanGetProfileList");
    F_WlanGetProfile = (T_WlanGetProfile)GetProcAddress(hWlanapiDll, "WlanGetProfile");
    F_WlanRegisterNotification = (T_WlanRegisterNotification)GetProcAddress(hWlanapiDll, "WlanRegisterNotification");
    F_WlanScan = (T_WlanScan)GetProcAddress(hWlanapiDll, "WlanScan");
    F_WlanGetAvailableNetworkList = (T_WlanGetAvailableNetworkList)GetProcAddress(hWlanapiDll, "WlanGetAvailableNetworkList");
    F_WlanConnect = (T_WlanConnect)GetProcAddress(hWlanapiDll, "WlanConnect");
    F_WlanSetProfile = (T_WlanSetProfile)GetProcAddress(hWlanapiDll, "WlanSetProfile");
    F_WlanCloseHandle = (T_WlanCloseHandle)GetProcAddress(hWlanapiDll, "WlanCloseHandle");
    F_WlanReasonCodeToString = (T_WlanReasonCodeToString)GetProcAddress(hWlanapiDll, "WlanReasonCodeToString");
#endif

    WCHAR wstrDefaultBuf[3072];
    CHAR strDefaultBuf[3072];

    DWORD dwResult = 0;

    DWORD negotiatedWifiVersion = 0;
    HANDLE wlanHandle = 0;

    if (F_WlanOpenHandle(2, NULL, &negotiatedWifiVersion, &wlanHandle) != ERROR_SUCCESS)
    {
        fprintf(stdout, "Opening Win32 WLAN API failed (F_WlanOpenHandle)\n");
        return -1;
    }

    if (bLoadInterfaces)
    {
        dwResult = F_WlanEnumInterfaces(wlanHandle, NULL, &pInterfaceList);
        if (dwResult != ERROR_SUCCESS)
        {
            fprintf(stdout, "Enumerating device list failed (F_WlanEnumInterfaces)\n");
            return -1;
        };

        if (pInterfaceList->dwNumberOfItems == 0)
        {
            fprintf(stdout, "There are no devices available (F_WlanEnumInterfaces)\n");
            return -1;
        }

        HANDLE scanEvent = NULL;
        if (bLoadNetworks)
            scanEvent = CreateEventA(NULL, FALSE, FALSE, NULL);

        for (DWORD dwCurrentInterfaceIndex = 0; 
                   dwCurrentInterfaceIndex < pInterfaceList->dwNumberOfItems; 
                   ++dwCurrentInterfaceIndex)
        {
            WLAN_INTERFACE_INFO interfaceInfo = pInterfaceList->InterfaceInfo[dwCurrentInterfaceIndex];
            GUID interfaceGuid = interfaceInfo.InterfaceGuid;

            while (interfaceInfo.isState != wlan_interface_state_connected && interfaceInfo.isState != wlan_interface_state_disconnected)
            {
                // Do not try to do stuff while intermittent between connected & disconnected
                Sleep(0);
            }

            if (bDisconnectFlag)
            {
                /* TODO: Yield until disconnect completed */
                if (interfaceInfo.isState != wlan_interface_state_disconnected)
                {
                    dwResult = F_WlanDisconnect(wlanHandle, &interfaceGuid, NULL);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "Failed to disconnect interface %ls\n", interfaceInfo.strInterfaceDescription);
                    }
                }
                else fprintf(stdout, "Inteface was not marked as connected. (%ls)\n", interfaceInfo.strInterfaceDescription);
            }

            if (bListInterfacesFlag)
            {
                fprintf(stdout, "Interface = %ls, State = %s\n", interfaceInfo.strInterfaceDescription, get_interface_string_enum(interfaceInfo.isState));
                if (interfaceInfo.isState == wlan_interface_state_connected)
                {
                    fprintf(stdout, "Currently connected with %ls.\n", interfaceInfo.strInterfaceDescription);
                }
            }

            if (bImportProfileFlag)
            {
                FILE* f = fopen(existingProfileName, "r");
                if (!f)
                {
                    fprintf(stdout, "\n\t\tFailed to open existing profile\n");
                    osawc_free();
                    return -1;
                }

                size_t filesize;
                fseek(f, 0, SEEK_END);
                filesize = ftell(f);
                rewind(f);

                fread(wstrDefaultBuf, 2, filesize / 2, f);

                DWORD notValidReason = 0;
                dwResult = F_WlanSetProfile(wlanHandle, &interfaceGuid, WLAN_PROFILE_USER, wstrDefaultBuf, NULL, TRUE, NULL, &notValidReason);
                if (dwResult != ERROR_SUCCESS || notValidReason != ERROR_SUCCESS)
                {
                    F_WlanReasonCodeToString(notValidReason, sizeof(wstrDefaultBuf) / sizeof(decltype(*wstrDefaultBuf)), wstrDefaultBuf, NULL);

                    fprintf(stdout, "Failed to set profile. result = %08X, reason: %ls (F_WlanSetProfile)\n", dwResult, wstrDefaultBuf);

                    osawc_free();

                    return -1;
                }
                else fprintf(stdout, "Imported profile successfully.\n");
            }

            if (bListProfilesFlag || bExportProfiles || bLoadProfiles)
            {
                dwResult = F_WlanGetProfileList(wlanHandle, &interfaceGuid, NULL, &pProfileList);
                if (dwResult != ERROR_SUCCESS)
                {
                    fprintf(stdout, "Failed to get profile list on interface (%ls) (F_WlanGetProfileList)", interfaceInfo.strInterfaceDescription);
                    continue;
                }

                for (DWORD pi = 0; pi < pProfileList->dwNumberOfItems; ++pi)
                {
                    WLAN_PROFILE_INFO profileInfo = pProfileList->ProfileInfo[pi];
                    fprintf(stdout, "\tProfile name: %ls\n", profileInfo.strProfileName);

                    DWORD profileFlags = O_WLAN_PROFILE_GET_PLAINTEXT_KEY;
                    LPWSTR profileXmlWstr = NULL;
                    dwResult = F_WlanGetProfile(wlanHandle, &interfaceGuid, profileInfo.strProfileName, NULL, &profileXmlWstr, &profileFlags, NULL);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "\tRun as administrator to get plaintext key.\n");
                        profileFlags = 0;
                        dwResult = F_WlanGetProfile(wlanHandle, &interfaceGuid, profileInfo.strProfileName, NULL, &profileXmlWstr, &profileFlags, NULL);
                        if (dwResult != ERROR_SUCCESS || profileXmlWstr == NULL)
                        {
                            fprintf(stdout, "\tFailed to get profile. result: %08X\n", dwResult);
                            continue;
                        }
                    }

                    if (bExportProfiles)
                    {
                        wcscpy(wstrDefaultBuf, profileInfo.strProfileName);
                        wcscat(wstrDefaultBuf, L".xml");

                        FILE* f = _wfopen(wstrDefaultBuf, L"w+,ccs=UTF-16LE");
                        if (f)
                        {
                            fseek(f, 0, SEEK_SET);
                            fwrite(profileXmlWstr, 2, wcslen(profileXmlWstr), f);
                            fclose(f);
                        }
                    }

                    F_WlanFreeMemory(profileXmlWstr);
                }
            }

            if (bLoadNetworks)
            {
                WLAN_CALLBACK_INFO cbInfo;
                cbInfo.InterfaceGuid = interfaceGuid;
                cbInfo.scanEvent = scanEvent;

                dwResult = F_WlanRegisterNotification(wlanHandle, O_WLAN_NOTIFICATION_SOURCE_ALL, TRUE, (WLAN_NOTIFICATION_CALLBACK)OupScanCb, &cbInfo, NULL, NULL);
                if (dwResult != ERROR_SUCCESS)
                {
                    // doesn't necessarily need to fail, but if it does, something worse is going on

                    fprintf(stdout, "Failed to register a notifier (F_WlanRegisterNotification)\n");
                    osawc_free();
                    return -1;
                }

                dwResult = F_WlanScan(wlanHandle, &interfaceGuid, NULL, NULL, NULL);
                if (dwResult != ERROR_SUCCESS)
                {
                    fprintf(stdout, "Failed to scan network (F_WlanScan), continuing to next network\n");
                    continue; // Not over yet, continue to next interface
                }

                dwResult = WaitForSingleObject(cbInfo.scanEvent, dwWaitMillis);

                switch (dwResult)
                {
                case WAIT_OBJECT_0:
                    fprintf(stdout, "\tScan succeeded\n");
                    ResetEvent(scanEvent);
                    break;
                case WAIT_TIMEOUT:
                    fprintf(stdout, "\tScan failed, proceeding anyways\n");
                    break;
                default:
                    fprintf(stdout, "Default case after WaitForSingleObject\n");
                    break;
                }

                if (bProfileFlag)
                {
                    dwResult = MultiByteToWideChar(CP_UTF8, 0, targetProfile, strlen(targetProfile), wstrDefaultBuf, sizeof(wstrDefaultBuf) / sizeof(WCHAR));

                    WLAN_CONNECTION_PARAMETERS params;
                    params.dot11BssType = dot11_BSS_type_any;
                    params.pDot11Ssid = NULL; // Looks to profile
                    params.pDesiredBssidList = NULL;
                    params.dwFlags = 0;
                    params.wlanConnectionMode = wlan_connection_mode_profile;
                    params.strProfile = wstrDefaultBuf;

                    dwResult = F_WlanConnect(wlanHandle, &interfaceGuid, &params, NULL);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "Failed to connect with profile (%s) (F_WlanConnect)\n", targetSsid);
                        fprintf(stdout, "Return code is %08X, where ERROR_INVALID_PARAMETER = %08X\n", dwResult, ERROR_INVALID_PARAMETER);

                        osawc_free();

                        return -1;
                    }
                }

                if (bListNetworksFlag || bSsidFlag || bPassFlag)
                {
                    dwResult = F_WlanGetAvailableNetworkList(wlanHandle, &interfaceGuid, O_WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES | O_WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES, NULL, &pNetworkList);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "\n\tFailed to get available network list on interface (%ls) (F_WlanGetAvailableNetworkList)", pInterfaceList->InterfaceInfo[dwCurrentInterfaceIndex].strInterfaceDescription);
                        continue;
                    }

                    for (DWORD ni = 0; ni < pNetworkList->dwNumberOfItems; ++ni)
                    {
                        WLAN_AVAILABLE_NETWORK targetNetwork = pNetworkList->Network[ni];

                        if (bListNetworksFlag)
                        {
                            if (bVerboseFlag)
                            {
                                fprintf(stdout, "\tAvailable network on interface: %.*s\n", targetNetwork.dot11Ssid.uSSIDLength, (char*)targetNetwork.dot11Ssid.ucSSID);
                                fprintf(stdout, "\t\tConnectable?: %s\n", targetNetwork.bNetworkConnectable ? "TRUE" : "FALSE");
                                if (!targetNetwork.bNetworkConnectable)
                                    fprintf(stdout, "\t\tNot connectable reason -> WLAN_REASON_CODE = %08X\n", targetNetwork.wlanNotConnectableReason);
                                fprintf(stdout, "\t\tSecurity enabled on network?: %s\n", targetNetwork.bSecurityEnabled ? "TRUE" : "FALSE");
                                fprintf(stdout, "\t\tSignal strength: %u\n", targetNetwork.wlanSignalQuality);
                                fprintf(stdout, "\t\tDefault algorithm: %s\n", get_dot11_auth_string_enum(targetNetwork.dot11DefaultAuthAlgorithm));
                                fprintf(stdout, "\t\tDefault cipher: %s\n", get_dot11_cipher_string_enum(targetNetwork.dot11DefaultCipherAlgorithm));
                            }
                            else
                            {
                                fprintf(stdout, "\tStrength: %2i | %.*s\n", targetNetwork.wlanSignalQuality, targetNetwork.dot11Ssid.uSSIDLength, (char*)targetNetwork.dot11Ssid.ucSSID);
                            }
                        }

                        if (bSsidFlag || bPassFlag)
                        {
                            if (!strncmp((char*)targetNetwork.dot11Ssid.ucSSID, targetSsid, targetNetwork.dot11Ssid.uSSIDLength))
                            {
                                if (targetNetwork.bNetworkConnectable == FALSE)
                                {
                                    fprintf(stdout, "\n\t\tThe specified SSID (%.*s) is marked as not connectable. WLAN_REASON_CODE = %04X\n", targetNetwork.dot11Ssid.uSSIDLength, (char*)targetNetwork.dot11Ssid.ucSSID, targetNetwork.wlanNotConnectableReason);
                                    osawc_free();
                                    return -1;
                                }

                                if (targetNetwork.dwFlags & O_WLAN_AVAILABLE_NETWORK_CONNECTED)
                                {
                                    fprintf(stdout, "\n\t\tAlready connected to this network (%s)\n", (char*)targetNetwork.dot11Ssid.ucSSID);
                                    osawc_free();
                                    return -1;
                                }

                                // need to create a new profile
                                swprintf_s(wstrDefaultBuf, sizeof(wstrDefaultBuf) / sizeof(decltype(*wstrDefaultBuf)), templateF_WlanProfileXml, newProfileName, targetSsid, "passPhrase", networkPass);

                                DWORD notValidReason = 0;
                                dwResult = F_WlanSetProfile(wlanHandle, &interfaceGuid, WLAN_PROFILE_USER, wstrDefaultBuf, NULL, TRUE, NULL, &notValidReason);
                                if (dwResult != ERROR_SUCCESS || notValidReason != ERROR_SUCCESS)
                                {
                                    F_WlanReasonCodeToString(notValidReason, sizeof(wstrDefaultBuf) / sizeof(decltype(*wstrDefaultBuf)), wstrDefaultBuf, NULL);

                                    fprintf(stdout, "\n\t\tFailed to set profile. result = %08X, reason: %ls (F_WlanSetProfile)\n", dwResult, wstrDefaultBuf);

                                    osawc_free();

                                    return -1;
                                }

                                MultiByteToWideChar(CP_UTF8, 0, targetProfile, strlen(targetProfile), wstrDefaultBuf, sizeof(wstrDefaultBuf) / sizeof(decltype(*wstrDefaultBuf)));

                                // connect with new profile
                                WLAN_CONNECTION_PARAMETERS params;
                                params.dot11BssType = dot11_BSS_type_any;
                                params.pDot11Ssid = NULL; // Looks to profile
                                params.pDesiredBssidList = NULL;
                                params.dwFlags = 0;
                                params.wlanConnectionMode = wlan_connection_mode_profile;
                                params.strProfile = wstrDefaultBuf;

                                dwResult = F_WlanConnect(wlanHandle, &interfaceGuid, &params, NULL);
                                if (dwResult != ERROR_SUCCESS)
                                {
                                    fprintf(stdout, "\n\t\tFailed to connect with new profile. (F_WlanConnect)\n");
                                    fprintf(stdout, "\t\tresult = %08X, where ERROR_INVALID_PARAMETER = %08X\n", dwResult, ERROR_INVALID_PARAMETER);

                                    osawc_free();

                                    return -1;
                                }

                                // fall through to free and exit

                            }//if (!strncmp((char*)targetNetwork.dot11Ssid.ucSSID, targetSsid, targetNetwork.dot11Ssid.uSSIDLength))
                        }//if (bSsidFlag || bPassFlag)
                    }//for (DWORD ni = 0; ni < pNetworkList->dwNumberOfItems; ++ni)
                }//if (bListNetworksFlag || bSsidFlag || bPassFlag)
            }//if (bLoadNetworks)
        }//for (DWORD dwCurrentInterfaceIndex = 0; dwCurrentInterfaceIndex < pInterfaceList->dwNumberOfItems; ++dwCurrentInterfaceIndex)
    }//if (bLoadInterfaces)

    osawc_free();

    if (F_WlanCloseHandle(wlanHandle, NULL) != ERROR_SUCCESS)
    {
        fprintf(stdout, "\nClosing Win32 WLAN API failed (F_WlanCloseHandle)\n");
        exit(-1);
    };

    return 0;
}