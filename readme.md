###supplicant_getadaptersinfo_dll 安腾蝴蝶NAT 后认证绕过DLL

supplicant_getadaptersinfo_dll 利用导入DLL 的方式hook 掉原来安腾蝴蝶从**iphlpapi.dll** 导出的**GetAdaptersInfo** 而获取本地网卡的信息,其中就包含有本机的IP 地址.绕过NAT 认证的关键点是要把蝴蝶登陆数据包的IP 地址换成在校园网中`172.16` 网段的IP 地址而不是由路由器NAT 之后的`192.168` 或者`10.0.0` 之类的内网IP 地址(虽然`172.16` 也是内网IP 地址).绕过NAT 认证DLL 获取校园网IP 地址的原理是任意访问一个外网网站,然后蝴蝶流量计服务器会拦截访问,并且在返回的HTTP 响应数据包中的URL 携带有本机在校园网内的真实IP 地址

如果想自己动手把DLL 附加到红蝴蝶中,找到下面的代码:


	.text:0040DDD5                 push    offset aIphlpapi_dll ; "iphlpapi.dll"
	.text:0040DDDA                 mov     GetAdaptersInfo_FunctionAddress, edi
	.text:0040DDE0                 mov     dword_4629C0, edi
	.text:0040DDE6                 mov     dword_4629BC, edi
	.text:0040DDEC                 mov     dword_4629B8, edi
	.text:0040DDF2                 mov     dword_4629B4, edi
	.text:0040DDF8                 mov     dword_4629B0, edi
	.text:0040DDFE                 mov     dword_4629AC, edi
	.text:0040DE04                 call    ds:LoadLibraryA
	.text:0040DE0A                 cmp     eax, edi
	.text:0040DE0C                 mov     hModule, eax
	.text:0040DE11                 jz      loc_40DED1


把`0x40DDD5` 中的**aIphlpapi.dll** 字符串(地址`0x004562A8` )数据修改为**ip_data.dll** ,然后把**ip_data.dll** 和红蝴蝶客户端放在同一目录下即可.

---

###怎么设置NAT 认证绕过配置文件

配置文件格式如下:

	ipchange=true|false|auto:ipaddress=%set_ip_address%

不需要开启NAT 认证绕过,则把**ipchange** 设置为`ipchange=false` 
自动绕过NAT 认证`ipchange=auto` 
启用自定义IP 地址则设置为`ipchange=true` ,**ipaddress** 设置为需要填写到登陆数据包的IP 地址

TIPS:当然你也可以利用这个DLL 来开发防BAN MAC 地址的蝴蝶,任务留给你们啦..
