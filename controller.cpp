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

int bSilentMode = 0;

int bLoadInterfacesAndNetworks = 0;
int bLoadInterfaces = 0;
int bLoadNetworks = 0;

int bPassFlag = 0;
int bSsidFlag = 0;
int bProfileFlag = 0;

int bDisconnectFlag = 0;

int bListInterfacesFlag = 0;
int bListNetworksFlag = 0;
int bListProfilesFlag = 0;

char* targetProfile = NULL;
char* targetSsid = NULL;
char* networkPass = NULL;
char* newProfileName = NULL;

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
        "/lp, (List)        0   Generate a list of existing profiles"                                                "\n" \
        "/s,  (Silent)      0   A mode where no output whatsoever is generated."                                     "\n" \
        ""                                                                                                           "\n" \
        "Connect to Wi-Fi: osawc.exe /n ssid_here /k passwd_here /c new_profile_name"                                "\n" \
        "Note: New profile name cannot already exist."                                                               "\n" \
        ""                                                                                                           "\n" \
        "Disconnect from Wi-Fi: osawc.exe /d"                                                                        "\n" ;

void arg_parser(int argc, char* argv[])
{
    // argv[0] is program name, typically

    int i; // current argument index

    if (argc > 1)
    {
        for (i = 1; i < argc; ++i)
        {
            {
                const char* new_flag = argv[i];
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
                    continue;
                }
                if (!strcmp(new_flag, "/s"))
                {
                    bSilentMode = 1;
                    continue;
                }
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
            }
        }
    }
    else
    {
        puts(intro_en);
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
        case 0: return "DOT11_CIPHER_ALGO_NONE"; break;
        case 1: return "DOT11_CIPHER_ALGO_WEP40"; break;
        case 2: return "DOT11_CIPHER_ALGO_TKIP"; break;
        case 4: return "DOT11_CIPHER_ALGO_CCMP"; break;
        case 5: return "DOT11_CIPHER_ALGO_WEP104"; break;
        case 6: return "DOT11_CIPHER_ALGO_BIP"; break;
        case 8: return "DOT11_CIPHER_ALGO_GCMP"; break;
        case 9: return "DOT11_CIPHER_ALGO_GCMP_256"; break;
        case 10: return "DOT11_CIPHER_ALGO_CCMP_256"; break;
        case 11: return "DOT11_CIPHER_ALGO_BIP_GMAC_128"; break;
        case 12: return "DOT11_CIPHER_ALGO_BIP_GMAC_256"; break;
        case 13: return "DOT11_CIPHER_ALGO_BIP_CMAC_256"; break;
        case 256: return "DOT11_CIPHER_ALGO_WPA_USE_GROUP"; break;
        case 257: return "DOT11_CIPHER_ALGO_WEP"; break;

        default: return "(Unknown)";
    }
}

PWLAN_INTERFACE_INFO_LIST pInterfaceList = NULL;
PWLAN_AVAILABLE_NETWORK_LIST pNetworkList = NULL;
PWLAN_PROFILE_INFO_LIST pProfileList = NULL;

void osawc_free()
{
    if (pInterfaceList)
    {
        WlanFreeMemory(pInterfaceList);
        pInterfaceList = NULL;
    }
    if (pNetworkList)
    {
        WlanFreeMemory(pNetworkList);
        pNetworkList = NULL;
    }
    if (pProfileList)
    {
        WlanFreeMemory(pProfileList);
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

const wchar_t* templateWlanProfileXml = LR"(<?xml version="1.0"?>
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
    arg_parser(argc, argv);

    DWORD dwResult = 0;

    DWORD negotiatedWifiVersion = 0;
    HANDLE wlanHandle = 0;

    if (WlanOpenHandle(2, NULL, &negotiatedWifiVersion, &wlanHandle) != ERROR_SUCCESS)
    {
        fprintf(stdout, "Opening Win32 WLAN API failed (WlanOpenHandle)\n");
        exit(-1);
    }

    if (bLoadInterfaces)
    {
        dwResult = WlanEnumInterfaces(wlanHandle, NULL, &pInterfaceList);
        if (dwResult != ERROR_SUCCESS)
        {
            fprintf(stdout, "Enumerating device list failed (WlanEnumInterfaces)\n");
            exit(-1);
        };

        if (pInterfaceList->dwNumberOfItems == 0)
        {
            fprintf(stdout, "There are no devices available (WlanEnumInterfaces)\n");
            exit(-1);
        }

        HANDLE scanEvent = NULL;
        if (bLoadNetworks)
            scanEvent = CreateEventA(NULL, NULL, NULL, NULL);

        for (DWORD ii = 0; ii < pInterfaceList->dwNumberOfItems; ++ii)
        {
            WLAN_INTERFACE_INFO interfaceInfo = pInterfaceList->InterfaceInfo[ii];
            GUID interfaceGuid = interfaceInfo.InterfaceGuid;

            while (interfaceInfo.isState != wlan_interface_state_connected && interfaceInfo.isState != wlan_interface_state_disconnected)
            {
                fprintf(stdout, "yielding\n");
                Sleep(0); // dont mess with it while its doing stuff(?)
            }

            if (bDisconnectFlag)
            {
                if (interfaceInfo.isState == wlan_interface_state_connected)
                {
                    dwResult = WlanDisconnect(wlanHandle, &interfaceGuid, NULL);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "Failed to disconnect interface %ls\n", interfaceInfo.strInterfaceDescription);
                    }
                }
            }

            if (bListInterfacesFlag)
            {
                fprintf(stdout, "%ls\n", interfaceInfo.strInterfaceDescription);
                if (interfaceInfo.isState == wlan_interface_state_connected)
                {
                    fprintf(stdout, "Currently connected with %ls.\n", interfaceInfo.strInterfaceDescription);
                }
            }

            if (bListProfilesFlag)
            {
                dwResult = WlanGetProfileList(wlanHandle, &interfaceGuid, NULL, &pProfileList);
                if (dwResult != ERROR_SUCCESS)
                {
                    fprintf(stdout, "Failed to get profile list on interface (%ls) (WlanGetProfileList)", interfaceInfo.strInterfaceDescription);
                    continue;
                }

                for (DWORD pi = 0; pi < pProfileList->dwNumberOfItems; ++pi)
                {
                    WLAN_PROFILE_INFO profileInfo = pProfileList->ProfileInfo[pi];
                    fprintf(stdout, "\tProfile name: %ls\n", profileInfo.strProfileName);

                    DWORD profileFlags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                    LPWSTR profileXmlWstr = NULL;
                    dwResult = WlanGetProfile(wlanHandle, &interfaceGuid, profileInfo.strProfileName, NULL, &profileXmlWstr , &profileFlags, NULL);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "\tRun as administrator to get plaintext key.\n");
                        profileFlags = 0;
                        dwResult = WlanGetProfile(wlanHandle, &interfaceGuid, profileInfo.strProfileName, NULL, &profileXmlWstr, &profileFlags, NULL);
                        if (dwResult != ERROR_SUCCESS)
                        {
                            fprintf(stdout, "\tFailed to get profile. result: %08X\n", dwResult);
                            continue;
                        }
                    }
                    fprintf(stdout, "\n%ls\n", profileXmlWstr);
                    WlanFreeMemory(profileXmlWstr);
                }
            }

            if (bLoadNetworks)
            {
                WLAN_CALLBACK_INFO cbInfo;
                cbInfo.InterfaceGuid = interfaceGuid;
                cbInfo.scanEvent = scanEvent;

                dwResult = WlanRegisterNotification(wlanHandle, WLAN_NOTIFICATION_SOURCE_ALL, TRUE, (WLAN_NOTIFICATION_CALLBACK)OupScanCb, &cbInfo, NULL, NULL);
                if (dwResult != ERROR_SUCCESS)
                {
                    // doesn't necessarily need to fail, but if it does, something worse is going on

                    fprintf(stdout, "Failed to register a notifier (WlanRegisterNotification)\n");
                    osawc_free();
                    exit(-1);
                }

                dwResult = WlanScan(wlanHandle, &interfaceGuid, NULL, NULL, NULL);
                if (dwResult != ERROR_SUCCESS)
                {
                    fprintf(stdout, "Failed to scan network (WlanScan), continuing to next network\n");
                    continue;
                    // Continue because it isn't over yet
                }

                dwResult = WaitForSingleObject(cbInfo.scanEvent, INFINITE); // change to a reasonable time limit later

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
                    WLAN_CONNECTION_PARAMETERS params;
                    params.dot11BssType = dot11_BSS_type_any;
                    params.pDot11Ssid = NULL; // Looks to profile
                    params.pDesiredBssidList = NULL; // pray
                    params.dwFlags = 0;
                    params.wlanConnectionMode = wlan_connection_mode_profile;

                    WCHAR fmtProfileName[512];
                    dwResult = MultiByteToWideChar(CP_UTF8, 0, targetProfile, strlen(targetProfile), fmtProfileName, sizeof(fmtProfileName) / sizeof(WCHAR));
                    if (dwResult != 0)
                    {
                        //
                    }

                    params.strProfile = fmtProfileName;

                    dwResult = WlanConnect(wlanHandle, &interfaceGuid, &params, NULL);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "Failed to connect with profile (%s) (WlanConnect)\n", targetSsid);
                        fprintf(stdout, "Return code is %08X, where ERROR_INVALID_PARAMETER = %08X\n", dwResult, ERROR_INVALID_PARAMETER);

                        osawc_free();

                        exit(-1);
                    }
                }

                if (bListNetworksFlag || bSsidFlag || bPassFlag)
                {
                    dwResult = WlanGetAvailableNetworkList(wlanHandle, &interfaceGuid, WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES | WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES, NULL, &pNetworkList);
                    if (dwResult != ERROR_SUCCESS)
                    {
                        fprintf(stdout, "Failed to get available network list on interface (%ls) (WlanGetAvailableNetworkList)", pInterfaceList->InterfaceInfo[ii].strInterfaceDescription);
                        continue;
                    }

                    for (DWORD ni = 0; ni < pNetworkList->dwNumberOfItems; ++ni)
                    {
                        WLAN_AVAILABLE_NETWORK targetNetwork = pNetworkList->Network[ni];

                        if (bListNetworksFlag)
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

                        if (bSsidFlag || bPassFlag)
                        {
                            if (!strncmp((char*)targetNetwork.dot11Ssid.ucSSID, targetSsid, targetNetwork.dot11Ssid.uSSIDLength))
                            {
                                if (targetNetwork.bNetworkConnectable == FALSE)
                                {
                                    fprintf(stdout, "The specified SSID (%.*s) is marked as not connectable. WLAN_REASON_CODE = %04X\n", targetNetwork.dot11Ssid.uSSIDLength, (char*)targetNetwork.dot11Ssid.ucSSID, targetNetwork.wlanNotConnectableReason);
                                    osawc_free();
                                    exit(-1);
                                }

                                if (targetNetwork.dwFlags & WLAN_AVAILABLE_NETWORK_CONNECTED)
                                {
                                    fprintf(stdout, "Already connected to this network (%s)\n", (char*)targetNetwork.dot11Ssid.ucSSID);
                                    osawc_free();

                                    exit(-1);
                                }

                                // need to create a new profile
                                WCHAR newProfileXmlBuf[3072];
                                swprintf_s(newProfileXmlBuf, 3072, templateWlanProfileXml, newProfileName, targetSsid, "passPhrase", networkPass);

                                DWORD notValidReason = 0;
                                dwResult = WlanSetProfile(wlanHandle, &interfaceGuid, WLAN_PROFILE_USER, newProfileXmlBuf, NULL, TRUE, NULL, &notValidReason);
                                if (dwResult != ERROR_SUCCESS)
                                {
                                    fprintf(stdout, "Failed to set profile. result = %08X, notValidReason: %08X (WlanSetProfile)\n", dwResult, notValidReason);
                                    
                                    //fprintf(stdout, "%.*ls\n", 3072, newProfileXmlBuf);

                                    WCHAR reasonStr[512];
                                    WlanReasonCodeToString(notValidReason, 512, reasonStr, NULL);

                                    fprintf(stdout, "Validation reason: %ls\n", reasonStr);

                                    osawc_free();

                                    exit(-1);
                                }

                                // connect with new profile
                                WLAN_CONNECTION_PARAMETERS params;
                                params.dot11BssType = dot11_BSS_type_any;
                                params.pDot11Ssid = NULL; // Looks to profile
                                params.pDesiredBssidList = NULL; // pray
                                params.dwFlags = 0;
                                params.wlanConnectionMode = wlan_connection_mode_profile;

                                WCHAR fmtProfileName[512];
                                MultiByteToWideChar(CP_UTF8, 0, targetProfile, strlen(targetProfile), fmtProfileName, sizeof(fmtProfileName) / sizeof(WCHAR));

                                params.strProfile = fmtProfileName;
                                
                                dwResult = WlanConnect(wlanHandle, &interfaceGuid, &params, NULL);
                                if (dwResult != ERROR_SUCCESS)
                                {
                                    fprintf(stdout, "Failed to connect with new profile. (WlanConnect)\n");
                                    fprintf(stdout, "result = %08X, where ERROR_INVALID_PARAMETER = %08X\n", dwResult, ERROR_INVALID_PARAMETER);

                                    osawc_free();

                                    exit(-1);
                                }

                                osawc_free();

                                if (WlanCloseHandle(wlanHandle, NULL) != ERROR_SUCCESS)
                                {
                                    fprintf(stdout, "Closing Win32 WLAN API failed (WlanCloseHandle)\n");
                                    exit(-1);
                                }

                                return 0;
                            }
                        }
                    }
                }
            }
        }
    }

    osawc_free();

    if (WlanCloseHandle(wlanHandle, NULL) != ERROR_SUCCESS)
    {
        fprintf(stdout, "Closing Win32 WLAN API failed (WlanCloseHandle)\n");
        exit(-1);
    };

    return 0;
}