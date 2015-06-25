
#include <malloc.h>
#include <memory.h>
#include <string.h>

#include <string>

#include <windows.h>
#include <winsock.h>

#pragma comment (lib,"ws2_32")

using std::string;

#define IPV4_LENGTH 16
#define READ_BUFFER_LENGTH 64

#define MAX_ADAPTER_NAME_LENGTH 256
#define MAX_ADAPTER_DESCRIPTION_LENGTH 128
#define MAX_ADAPTER_ADDRESS_LENGTH 8

#define RESOLVE_BUFFER_LENGTH 1024
#define RESOLVE_STRING "wlanuserip="
#define RESOLVE_URL "http://1.1.1.1:8000/ext_portal.magi?url=\"\"&radnum=\"1234\"&a.magi"
#define URL_HEADER "GET /ext_portal.magi?url=\"\"&radnum=\"1234\"&a.magi HTTP/1.1\r\n" \
                   "User-Agent: GET_REAL_IP\r\n" \
                   "Host: 1.1.1.1:8000\r\n\r\n"


typedef struct {
    char String[4 * 4];
} IP_ADDRESS_STRING, *PIP_ADDRESS_STRING, IP_MASK_STRING, *PIP_MASK_STRING;
 
typedef struct _IP_ADDR_STRING {
    struct _IP_ADDR_STRING* Next;
    IP_ADDRESS_STRING IpAddress;
    IP_MASK_STRING IpMask;
    DWORD Context;
} IP_ADDR_STRING, *PIP_ADDR_STRING;

 typedef struct _IP_ADAPTER_INFO {  
  struct _IP_ADAPTER_INFO *Next;
  DWORD ComboIndex;  
  char AdapterName[MAX_ADAPTER_NAME_LENGTH + 4];
  char Description[MAX_ADAPTER_DESCRIPTION_LENGTH + 4];
  UINT AddressLength;  
  BYTE Address[MAX_ADAPTER_ADDRESS_LENGTH];
  DWORD Index;
  UINT Type;  
  UINT DhcpEnabled;
  PIP_ADDR_STRING CurrentIpAddress;
  IP_ADDR_STRING IpAddressList;
  IP_ADDR_STRING GatewayList;
  IP_ADDR_STRING DhcpServer;
  BOOL HaveWins;
  IP_ADDR_STRING PrimaryWinsServer;
  IP_ADDR_STRING SecondaryWinsServer;
  time_t LeaseObtained;
  time_t LeaseExpires;
 } IP_ADAPTER_INFO,  *PIP_ADAPTER_INFO;

typedef DWORD (__stdcall *_GetAdaptersInfo)(PIP_ADAPTER_INFO,PULONG);
typedef DWORD (__stdcall *_GetNetworkParams)(void*,long*);
typedef DWORD (__stdcall *_GetInterfaceInfo)(void*,long*);
typedef DWORD (__stdcall *_IpReleaseAddress)(void*);
typedef DWORD (__stdcall *_IpRenewAddress)(void*);
typedef DWORD (__stdcall *_AddIPAddress)(void*,void*,long,long*,long*);
typedef DWORD (__stdcall *_DeleteIPAddress)(long*);

_GetAdaptersInfo  GetAdaptersInfo_=NULL;
_GetNetworkParams GetNetworkParams_=NULL;
_GetInterfaceInfo GetInterfaceInfo_=NULL;
_IpReleaseAddress IpReleaseAddress_=NULL;
_IpRenewAddress   IpRenewAddress_=NULL;
_AddIPAddress     AddIPAddress_=NULL;
_DeleteIPAddress  DeleteIPAddress_=NULL;

HMODULE dll_iphlpapi=NULL;
HANDLE  file_config=INVALID_HANDLE_VALUE;

bool auto_state=false;
bool send_ip=false;
char send_ip_addr[IPV4_LENGTH]={0};

DWORD __stdcall Hook_GetAdaptersInfo(PIP_ADAPTER_INFO output_data,PULONG output_length);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (DLL_PROCESS_ATTACH==ul_reason_for_call) {
        WSADATA startup;
        WSAStartup(1,&startup);

        dll_iphlpapi=LoadLibrary("iphlpapi.dll");
        GetAdaptersInfo_=(_GetAdaptersInfo)GetProcAddress(dll_iphlpapi,"GetAdaptersInfo");
        GetNetworkParams_=(_GetNetworkParams)GetProcAddress(dll_iphlpapi,"GetNetworkParams");
        GetInterfaceInfo_=(_GetInterfaceInfo)GetProcAddress(dll_iphlpapi,"GetInterfaceInfo");
        IpReleaseAddress_=(_IpReleaseAddress)GetProcAddress(dll_iphlpapi,"IpReleaseAddress");
        IpRenewAddress_=(_IpRenewAddress)GetProcAddress(dll_iphlpapi,"IpRenewAddress");
        AddIPAddress_=(_AddIPAddress)GetProcAddress(dll_iphlpapi,"AddIPAddress");
        DeleteIPAddress_=(_DeleteIPAddress)GetProcAddress(dll_iphlpapi,"DeleteIPAddress");

        if (NULL!=dll_iphlpapi && NULL!=GetAdaptersInfo_) {
            file_config=CreateFile("ip_config.dat",GENERIC_READ,0,NULL,OPEN_EXISTING,0,NULL);
            if (INVALID_HANDLE_VALUE!=file_config) {
                char read_buffer[READ_BUFFER_LENGTH]={0};
                unsigned long read_buffer_length=0;
                if (ReadFile(file_config,read_buffer,READ_BUFFER_LENGTH,&read_buffer_length,NULL)) {
                    /*
                        config file data:
                        line 1:ipchange=true:ipaddress=123.456.789.000
                    */
                    if (13<=read_buffer_length) {
                        string resolve_string(read_buffer);
                        if (resolve_string.find(':')) {
                            long string_length=resolve_string.length();
                            long point_comment=resolve_string.find(':');
                            char ipchange_buffer[READ_BUFFER_LENGTH/2]={0};
                            char ipaddress_buffer[READ_BUFFER_LENGTH/2]={0};
                            memcpy(ipchange_buffer,resolve_string.c_str(),point_comment);
                            memcpy(ipaddress_buffer,resolve_string.c_str()+point_comment+1,string_length-point_comment-1);
                            
                            resolve_string=ipchange_buffer;
                            string_length=resolve_string.length();
                            point_comment=resolve_string.find('=');
                            memset(ipchange_buffer,0,READ_BUFFER_LENGTH/2);
                            memcpy(ipchange_buffer,resolve_string.c_str()+point_comment+1,string_length-point_comment-1);

                            if (!strcmp(strlwr(ipchange_buffer),"true")) {
                                resolve_string=ipaddress_buffer;
                                string_length=resolve_string.length();
                                point_comment=resolve_string.find('=');
                                memcpy(send_ip_addr,resolve_string.c_str()+point_comment+1,string_length-point_comment-1);
								send_ip=true;
                            } else if (!strcmp(strlwr(ipchange_buffer),"auto")) {
                                SOCKET sock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);

                                try {
                                    sockaddr_in local;
                                    local.sin_family=AF_INET;
                                    local.sin_port=0;
                                    bind(sock,(const sockaddr*)&local,sizeof(local));

                                    sockaddr_in remote;
                                    remote.sin_addr.S_un.S_addr=inet_addr("1.1.1.1");
                                    remote.sin_family=AF_INET;
                                    remote.sin_port=htons(8000);
                                    connect(sock,(const sockaddr*)&remote,sizeof(remote));

                                    send(sock,URL_HEADER,strlen(URL_HEADER),0);
                                    char buffer[RESOLVE_BUFFER_LENGTH]={0};
                                    recv(sock,buffer,RESOLVE_BUFFER_LENGTH,0);
                                    closesocket(sock);

                                    string resolve_string(buffer);
                                    string ip;
                                    ip=resolve_string.substr(resolve_string.find(RESOLVE_STRING)+strlen(RESOLVE_STRING),16);
                                    ip=ip.substr(0,ip.find('&'));
                                    if (-1==inet_addr(ip.c_str())) {
                                        __asm {
                                            xor eax,eax;
                                            div eax;
                                        }
                                    }
                                    memcpy(send_ip_addr,ip.c_str(),ip.length());
                                    auto_state=true;
                                } catch(...) {
                                    MessageBox(NULL,"自动获取IP 失败,要设置为普通模式","启动失败ERROR!",MB_ICONERROR);
                                    ExitProcess(0);
                                    return FALSE;
                                }
                                return TRUE;
                            }
                        }
                    }
                }
            }
            return TRUE;
        }
    } else if (DLL_PROCESS_DETACH) {
        FreeLibrary(dll_iphlpapi);
        WSACleanup();
    }
    return FALSE;
}

DWORD __stdcall GetAdaptersInfo(PIP_ADAPTER_INFO output_data,PULONG output_length) {
    DWORD return_code=GetAdaptersInfo_(output_data,output_length);
    if (NULL!=output_data && (send_ip || auto_state))
        memcpy(output_data->IpAddressList.IpAddress.String,send_ip_addr,IPV4_LENGTH);
    return return_code;
}

DWORD __stdcall GetNetworkParams(void* a,long* b) {
    return GetNetworkParams_(a,b);
}
DWORD __stdcall GetInterfaceInfo(void* a,long* b) {
    return GetInterfaceInfo_(a,b);
}
DWORD __stdcall IpReleaseAddress(void* a) {
    return IpReleaseAddress_(a);
}
DWORD __stdcall IpRenewAddress(void* a) {
    return IpRenewAddress_(a);
}
DWORD __stdcall AddIPAddress(void* a,void* b,long c,long* d,long* f) {
    return AddIPAddress_(a,b,c,d,f);
}
DWORD __stdcall DeleteIPAddress(long* a) {
    return DeleteIPAddress_(a);
}


