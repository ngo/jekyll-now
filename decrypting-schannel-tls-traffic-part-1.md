---
layout: page
title: Decrypting Schannel TLS traffic. Part 1. Getting secrets from lsass
permalink: /decrypting-schannel-tls-part-1/
---

## TL;DR

 - This article is about ways to **decrypt TLS traffic of windows apps** that use schannel. This includes **IIS, RDP, IE and older Edge, Outlook, Powershell** and many others, but **excludes everything that uses OpenSSL or NSS** (most notably, all browsers except for Edge and IE). 
 - This is **not an exploit**. Applying this method **requires admin privilege** on the host and also **being able to debug lsass.exe** (i.e. bypassing protections such as Protected Process and Virtualization-based security is out of scope). 
 - There are ways to do similar things without admin privilege. Some of them are briefly mentioned in [related work](#2.-Related-work), and there also will be follow-up parts of the article about this.
 - The **tool** for exporting the keys **is available** at [win-frida-scripts repository](https://github.com/sldlb/win-frida-scripts/tree/master/lsasslkeylog-easy), along with a short howto.

This work is part of my R&D activities at [SolidLab LLC](https://solidlab.ru) and was fully funded by the company. I'm grateful to be able to do reseach as part of my job. We do offensive security, web application analysis and SDL consunting. We also develop [a WAF](https://solidwall.io/)

The article below is quite long and describes my journey in reverse-engineering schannel in much detail. For people experienced in windows internals and WinDBG it might be too verbose, but I inteded for it to be useful to people with little to no experience.

Feel free to contact me by email (ngo at solidlab.ru) or [@webpentest on twitter](twitter.com/webpentest). There is also a comments section at the bottom of the page.

## Table of contents

* TOC
{:toc}

## <a href="#sect1" id="sect1">1</a> Introduction

### <a href="#sect1.1" id="sect1.1">1.1</a> What is SChannel

SChannel a.k.a Secure Channel [\[23\]](#ref23) is a windows subsystem that is used whenever a windows application wants to do anything related to TLS - establish an encrypted session to a remote server or, on the contrary, accept a TLS connection from a client. 

From an architectural point of view, schannel implements the Security Support Provider Interface (SSPI) and is one of the SSP packages shipped by Microsoft. Other examples of SSP packages include CredSSP, Negotiate, NTLM, Kerberos and Digest [\[24\]](#ref24). 

As said earlier, schannel is used whenever windows application wants to establish a TLS connection. Some examples of that include:
* **HTTPS connections** made from `Internet Explorer` and `Edge` and from powershell's `Invoke-WebRequest`,  as well as HTTPS connections received by the `IIS web server`;
* **RDP connections**. schannel is used both on the client (`mstsc.exe`) and in the Terminal Service on the server (which runs `termsrv.dll` inside `svchost.exe`);
* **LDAPS connections** to the Active Directory LDAP server.
* Some **WinRM (PS remoting) connections**, when HTTPS listener is enabled on the server. PS remoting also supports SSL authentication with TLS client certificates, which, when enabled, is also implemented via schannel.

As said earlier,other browsers such as `Firefox` and `Google Chrome` use other libraries to handle TLS, namely NSS and OpenSSL, so their traffic is out of scope for this article. But both NSS and OpenSSL are open source and have documented ways to export secrets; for Firefox and Chrome key export is built-in and can be activated by using `SSLKEYLOGFILE` env var.

### <a href="#sect1.2" id="sect1.2">1.2</a> TLS traffic decryption and ephemeral keys - TLS1.2

The scope of this research is to obtain information needed to decrypt TLS traffic. This is not an exploit or a weakness of the protocol, because we fully control the application and OS that establish or accept the connection, thus being able to retrieve any keys and secrets that are used.

We won't cover the inner workings of TLS in very much detail here, because this would greatly increase the size of the article. A good summary is presented in section 2.2 of [\[1\]](#ref1).

A quick reminder of the most important things about TLS 1.2 connections and their decryption:

1. Whenever a **TLS session is created**, a number of keys are associated with this connection. Some of the keys might be used for encryption, others - for message authentication. There are different keys for different directions (client to server and server to client). These keys are called **ephemeral** to underline that they are short-lived in contrast with long-term keys such as a server TLS certificate key.
2. TLS can use different methods for key exchange, encryption and authentication, the exact combination of algorithms used for a given TLS session is called a **ciphersuite**. There are many ciphersuites available in TLS; server and client negotiate a ciphersuite that suits both of them.
3. All ciphersuites can be classified by whether they support Perfect Forward Secrecy [\[25\]](#ref25) or not. When a non-PFS ciphersuite is used, any encrypted connection can be decrypted by using its traffic capture and the server TLS private key. On the contrary, for the PFS ciphersuites you'll need the ephemeral keys of the session in question in order to decrypt it.
4. The process of deriving ephemeral keys is multi-step. In TLS1.2 it starts with server and client working together some blob of key material called the **Pre-Master Secret** which is then extended into the **Master Secret**, which, in turn, is then used to generate a set of keys and ivs that are used for encryption and authentication - **write keys** and **MAC keys**. MAC keys are only used nor non_AEAD ciphers.
5. Multiple separate TLS connections can belong to the same TLS session, thus eliminating the need to work out keys every time. The older way to do that is by using the **session ID** that is sent from server to client and then used by client on the succeeding connections. The server is supposed to store the keys associated with sessions, so this method requires a lot of memory on the server. That's why later the **TLS session tickets** (rfc5077) were proposed, where the server sends to the client an encrypted session state, which is sent back by the client on the next connection and decrypted by the server. This encryption is done using a key that only server knows. All of this means that although the ephemeral keys are supposed to be destroyed after the connection, in reality they might persist in memory both for the server and the client. For a thorough review of the security implications of TLS session tickets, see [\[12\]](#ref12).
6. In order to decrypt a TLS traffic dump we'll need a way to **a) get the secrets used for each of the sessions** and **b) correlate these keys to the sessions**. For TLS 1.2 the standard way to provide this information is via a **ssl keylog file**, which is supported by both OpenSSL and NSS ([\[2\]](#ref2),[\[3\]](#ref3)). Each line of the keylog file consists of a constant label string, the value that identifies the TLS session and the value of the secrets. For the reference, the keylog parsing routine of Wireshark can be found in [\[4\]](#ref4).
7. Keylog files for TLS1.2  support providing either **pre-master or the master secret** for a session. Sessions can be identified with either the **client random** (a non-encrypted value sent by the client during the TLS handshake) or the **session id** (a non-encrypted value sent by the server). An example line of keylog file for TLS1.2 is as follows:
```bash
CLIENT_RANDOM <client_random> <master_secret>
```
8. Keylog file format does not support providing directly the write and MAC **keys**, it needs either the premaster or the master **secret**, supposedly because this way you only need one keylog line per session, and secrets can be the expanded to the needed keys by the application that parses the keylog.

### <a href="#sect1.3" id="sect1.3">1.3</a> TLS traffic decryption - TLS1.3

Many of the things said above about TLS1.2 are also applicable to TLS1.3. There are, however, many changes in the way the secrets are generated. 

For TLS1.2 we have the following key generation scheme: 
```
(1) Pre-Master Secret
    => (2) Master Secret 
        => (3) A set of write keys and IVs 
               and possibly mac keys for client and server
```
In the case of TLS1.2, the keylog file format expects you to provide either stage (1) or stage (2) secrets.

For TLS1.3 the scheme has evolved into the following (see page 93 of RFC8446 [\[34\]](#ref34)) :
```
(1) Input Keying Material (IKM)
    => (2) A set of Secrets: Early, Handshake, Master etc
            => (3) A set of keys and IVs
```

The TLS1.3 keylog file also expects you to provide stage (2) secrets. Unlike TLS 1.2 you'll need multiple lines per TLS session, each line will provide one specific secret and tie it a TLS session by client random. You'll need at least four secrets -  the client and server handshake secret and client and server traffic secret. An example keylog file would be:

```
CLIENT_HANDSHAKE_TRAFFIC_SECRET <client_random> <client_hs_traffic_secret>
SERVER_HANDSHAKE_TRAFFIC_SECRET <client_random> <server_hs_traffic_secret>
CLIENT_TRAFFIC_SECRET_0 <client_random> <client_traffic_secret_0>
CLIENT_TRAFFIC_SECRET_0 <client_random> <server_traffic_secret_0>
```

### <a href="#sect1.4" id="sect1.4">1.4</a> Schannel, lsass and key isolation

The windows schannel API has the concept of key isolation (see [\[5\]](#ref5)), that is designed to make it harder to leak various confidential data by storing it in a centralized isolated place.  Suppose we have a process (say, terminal services client, mstsc) that wishes to establish a TLS connection. The actual TLS handshake would be performed inside another process (namely, *lsass.exe*) and the secrets generated during the handshake (i.e. pre-master and master keys for TLS1.2) will never leave the memory of lsass.exe and never reach mstsc.exe. All of this is done transparently to the application, which just uses functions from schannel.dll. 

Under the hood (see Figures 2.6 and 2.7 in [\[1\]](#ref1)) schannel.dll on the application side uses ALPC (a windows local IPC framework) to connect to schannel.dll on lsass side. The ALPC calls are processed by a copy of schannel.dll loaded into the lsass.exe, which then uses a set of cryptography API (CNG, [\[6\]](#ref6), implemented manly in `ncrypt.dll` and `bcrypt.dll`) to perform varios key-related tasks.

Note that this mode of operation is not specific to schannel but applies to all security providers that implement SSPI. When you call provider's `InitializeSecurityContext` ([\[37\]](#ref37)), this call is processed on LSA-side using provider's `SpInitLsaModeContextFn` callback (hence the `LsaMode` in the name) and the result is then passed to its `SpInitUserModeContext` on application side (hence `UserMode`). That is why windows applications are able to use, for example, NTLM or Kerberos authentication without having credentials in their memory.

And for us this means that lsass.exe would be a nice centralized place to extract **all** ephemeral TLS keys used by any schannel-enabled application. We'll need to either hook the key creation/manipulation routines or find a way to reliably find them in memory. In order to make use of the obtained keys we will also need to tie them somehow to a TLS session, preferably in a way supported by Wireshark (i.e. either session id or client random).

## <a href="#sect2" id="sect2">2</a> Related work

My interest in extracting keys from Schannel is not something new; a number of previous authors have explored this topic.

1. The seminal paper that thoroughly explores the same area is a MsC thesis by Jacob Kambic ([\[1\]](#ref1)), which was also presented on DefCon 24 and Blackhat 2016. The paper features an excellent overview of the relevant parts of TLS specifications and windows internals, and explores the problem of retrieving TLS keys from the forensics standpoint. The main contribution of the paper is  a method to walk the memory dump of lsass.exe, get the master secrets that are persisted in a structure called `NcryptSslKey` and linked to by the `SslCache{Client,Server}Item` for later use in session resumption. The `SslCache{Client,Server}Item` structure contains the much needed TLS session ID that allows matching the extracted secret to the session. The paper also outlines the methodology to find key material in memory and document some "magic values" that are used in some classes that hold data associated with keys or TLS sessions. As you will see, these magic tag (e.g. `BDDD`, `UUUR` and `?lss`) have proven to be extremely useful in figuring out what some of the structures I found in memory really mean. Finally, the paper describes a plugin developed for Volatility/Rekall that can be used with a memory dump to output the keys. Sadly, it seems that the plugin was never publicly released, nor was I able to contact the author. 
2. Other than the mentioned paper, there are some relevant comments by Brendan Dolan-Gavitt on RE stack exchange, e.g. in [\[7\]](#ref7) and [\[8\]](#ref8) the response suggests hooking the `ncrypt!_Tls1ComputeMasterKey` function inside lsass.exe  and reading the result of the computation. No implementation is provided.
3. There is also a paper "Extraction of TLS master secret key in windows" by Choi and Lee [\[9\]](#ref9), who implement an approach based on lsass.exe hooking. They hook `ncrypt!NcryptDeriveKey` in which takes the master secret as an argument to generate derived keys and also hook `ncrypt!SslGenerateMasterKey` to extract the client random. The exact details of extracting the required data are never mentioned. The authors of the paper never discuss how they were able to correlate the two calls in order to link the client random with the corresponding key. The tool they developed is not publicly available and, according to the paper, it only targets 32-bit windows, making it unsuitable for the current Windows.
4. The post by Gary Nebbett on Microsoft TechNet [\[10\]](#ref10) mentions the papers [\[1\]](#ref1) and [\[9\]](#ref9) while also proposing a novel way to extract the keys from the client application instead of lsass. The idea is to use the *ExportSecurityContext* from SSPI that per documentation exports a TLS security context as some opaque blob. According to the author of the post, this blob contains the client and server write keys, which are teoretically enough to decrypt the traffic, but Wireshark does not support their use.
5. Finally, many authors propose directly hooking the functions that encrypt and decrypt data (ie *sspicli!{Encrypt,Decrypt}Message*, *ncrypt!Ssl{Encrypt,Decrypt}Packet*) and get the plaintext without the need to extract keys. However, this approach is less preferable for network analysis, because one will need either to find a way to export these plaintext messages to a fake pcap file ingestable by Wireshark or to reimplement all the dissection logic for the protocol inside the TLS connection that Wireshark already has. One example of the tool that uses the hooking of encryption/decryption calls is NetRipper by Ionut Popescu [\[11\]](#ref11).

To the best of my knowlege, this concludes the list of publicly available research related to schannel TLS key extraction. 

To conclude this section, I would like to thank **Peter Wu** from wireshark-dev mailing list for helping me with the links to relevant research on the topic.

## <a href="#sect3" id="sect3">3</a> Problem statement

My goal was to develop a tool to decrypt schannel TLS traffic in Wireshark, while being in full control of the application and/or operating system on either the client or the server side of the connection. Compared to the problem statement of Jacob Kambic's thesis ([\[1\]](#ref1)), that targeted forensic extraction of the keys from memory dumps, I have more flexibility of the approach, because I can not only use memory scanning, but also debugging and function hooks. Other key requirements for the tool are as follows:
 * do not rely on session resumption and other mechanisms that prevent the keys from being wiped out of the memory as soon as the connection is closed;
 * if possible, do not rely on hardcoded offsets or other things specific to exact versions of Windows and/or libraries;
 * extract keys both from the client and from the server-side of the connection;
 * explore the area of extracting keys without administrative access, i.e. not touching memory of lsass.exe, similar to the approach proposed in [\[10\]](#ref10) (this is out of scope for part 1).

Besides developing the tool, I wanted to gain deeper understanding of windows internals, develop some reverse engineering skill and document the process I used.

## <a href="#sect4" id="sect4">4</a> Setting up testbeds

When researching ways to obtain ephemeral keys from non-collaborating applications it is very convenient to have full control over the other side of the connection and be able to easily extract keys from there. This applies both when our schannel part is a client and a server.

### <a href="#sect4.1" d="sect4.1">4.1</a> sslsplit server mitm testbed

Sslsplit [\[15\]](#ref15) is an excellent tool to MITM ssl connections. It supports various modes of operation and has built-in functionality to export TLS session keys to a keylog file. You'll need to generate a new self-signed certificate with a private key and write key+cert to a combined PEM file. After that you can launch sslsplit:
```command
$ ./sslsplit -L conn.log -M keys.log -P -A cert.pem autossl \ 
    0.0.0.0 3389 192.168.88.183 3389 
```

The line above will listen on port 3389 and forward all traffic to 192.168.88.183:3389. The `autossl` mode of operation makes sure that any non-TLS traffic before the start of TLS handshake is just passed through (for RDP connections this is actually needed because it has some initial non-TLS packets before starting TLS).

The file keys.log will contain ephemeral keys for all connections it makes in the format `CLIENT_RANDOM <client_random> <master secret>`.

### <a href="#sect4.2" id="sect4.2">4.2</a> OpenSSL sample server with libsslkeylog

When we do not need the MITM, it might be easier to just use the `openssl s_server` utility from the openssl package. In this case, in order to get the key log we will need to LD_PRELOAD libsslkeylog library by Peter Wu  ([\[41\]](#ref41)). The final command line will look like the following:
```command
$ sudo SSLKEYLOGFILE=log.txt ./sslkeylog.sh openssl s_server -port 443
```

The keys will go to log.txt

## <a href="#sect5" id="sect5">5</a> Obtaining TLS1.2 keys by hooking lsass.exe

### <a href="#sect5.1" id="sect5.1">5.1</a> Setting up the environment for debugging lsass

lsass.exe is a process that is very much involved in the normal functioning of Windows, so if you try to just attach WinDBG to it and pause its execution, the system will start to behave strangely and will autoreboot in a couple of minutes. In order to get a normal debugging experience one need to set up remote debugging.

To do that you'll need two windows machines with windows SDK installed.

On the debugee you'll need to open an administrative cmd or powershell, go to the location of x64 debugging tools (in my case - `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64`) and run dbgsrv:

```command
PS > .\dbgsrv.exe -t tcp:port=1025
```

Also you'll need to take note of the PID of `lsass.exe`.

On the debugger machine you'll need to go to debugging tools and run

```command
PS > .\windbg.exe -premote "tcp:server=<ip>,port=1025" -p <PID>
```

You can also connect from windbg GUI , using the connection string above.
Note that if you get an error 0n10049 in your client windbg, make sure to enclose the full connection string inside quotes. For some reason in some cases windbg only gets the first part of the arg, before the comma, and fails to connect.

### <a href="#sect5.2" id="sect5.2">5.2</a> Getting master keys on their generation

First of all, let's check the approach of hooking master key generation propesed in [\[7\]](#ref7),[\[8\]](#ref8),[\[9\]](#ref9). After attaching to lsass, we'll install a breakpoint on `SslGenerateMasterKey` from `ncrypt.dll` (`bm ncrypt!SslGenerateMasterKey`) and continue execution (`g`). Note: here and below I'll provide WinDBG commands for people who, like me, have never before used WinDBG, because for gdb users these commands are awkward to say the least.

As our model example is in this case mstsc, on the debugee we then open the terminal services client and connect to our sslsplit mitm. After we press the connect button and enter credentials, the breakpoint is hit. In WinDbg we enter `k` to get the backtrace and get the following:

```
#  Call Site
00 ncrypt!SslGenerateMasterKey
01 schannel!MakeEccDhPskSessionKeysHelper+0x189
02 schannel!CSsl3TlsClientContext::EccGenerateClientExchangeValue+0x4fa
03 schannel!CSsl3TlsClientContext::DigestServerKeyX+0x8c
04 schannel!CSsl3TlsClientContext::ProcessHandshake+0xa12
05 schannel!CSsl3TlsContext::ProcessHandshakeCommon+0x5c
06 schannel!CSsl3TlsContext::ProcessRecord+0xab
07 schannel!CSsl3TlsClientContext::ProcessRecord+0x24a
08 schannel!CSsl3TlsContext::TlsProtocolHandlerWorker+0x229
09 schannel!CSsl3TlsContext::SslProtocolHandler+0x79
0a schannel!SpInitLsaModeContext+0x3b2
0b lsasrv!WLsaInitContext+0x4e3
0c lsasrv!SspiExProcessSecurityContext+0xb21
0d SspiSrv!SspirProcessSecurityContext+0x27a
0e RPCRT4!Invoke+0x73
0f RPCRT4!Ndr64StubWorker+0xb56
10 RPCRT4!NdrServerCallAll+0x3c
11 RPCRT4!DispatchToStubInCNoAvrf+0x18
12 RPCRT4!RPC_INTERFACE::DispatchToStubWorker+0x2d1
13 RPCRT4!RPC_INTERFACE::DispatchToStub+0xcb
14 RPCRT4!LRPC_SCALL::DispatchRequest+0x31f
15 RPCRT4!LRPC_SCALL::HandleRequest+0x7fa
16 RPCRT4!LRPC_ADDRESS::HandleRequest+0x341
17 RPCRT4!LRPC_ADDRESS::ProcessIO+0x89e
18 RPCRT4!LrpcIoComplete+0xc5
19 ntdll!TppAlpcpExecuteCallback+0x14d
1a ntdll!TppWorkerThread+0x462
1b KERNEL32!BaseThreadInitThunk+0x14
1c ntdll!RtlUserThreadStart+0x21
```

We can immediately deduct the following:
1. Judging by the lower lines of the backtrace, we are currently inside the ALPC callback - a function that handles the incoming ALPC call from the client application (which is `mstsc.exe`, though we currently do not have a way to check that).
2. The client application wants to initialize an schannel context and the schannel.dll inside lsass handles this request starting from the `SpInitLsaModeContext` call and using methods of classes `CSsl3TlsClientContext` and `CSsl3TlsContext` (the former most probably inherits from the latter). 
3. The key generation itself is performed via CNG API of `ncrypt.dll`. 

Let us examine the docs that are available for `SslGenerateMasterKey` ([\[13\]](#ref13)):

```c
SECURITY_STATUS WINAPI SslGenerateMasterKey(
  _In_  NCRYPT_PROV_HANDLE hSslProvider,
  _In_  NCRYPT_KEY_HANDLE  hPrivateKey,
  _In_  NCRYPT_KEY_HANDLE  hPublicKey,
  _Out_ NCRYPT_KEY_HANDLE  *phMasterKey,
  _In_  DWORD              dwProtocol,
  _In_  DWORD              dwCipherSuite,
  _In_  PNCryptBufferDesc  pParameterList,
  _Out_ PBYTE              pbOutput,
  _In_  DWORD              cbOutput,
  _Out_ DWORD              *pcbResult,
  _In_  DWORD              dwFlags
);

```

As we can see, the fourth argument is annotated as `_Out_` (a type of a "header annotation", see [\[14\]](#ref14)), which means that this is the pointer that will be filled with the key after the call finishes. It is not immediately clear from the function definition, though, how the authors of [\[9\]](#ref9) have managed to extract the client random from hooking this call.

Anyway, lets prove that we can indeed get the master key from this invokation. As per x64 calling conventions [\[16\]](#ref16), the fourth parameter is passed in `R9` register. The type is `NCRYPT_KEY_HANDLE  *`, which means that R9 contains an address where the function will write the address of `NCRYPT_KEY`.  We can use `r r9` to examine the value of R9 before the call, then execute until return (`gu`), use `dq <address that was in R9 before the call> L1` to get the address of `NCRYPT_KEY` and then use `db <address that you got from dq> L100` to examine the newly-generated key:

```
Breakpoint 1 hit
ncrypt!SslGenerateMasterKey:
00007ffe`08e01e50 488bc4          mov     rax,rsp
0:007> r r9
r9=000000b1d231d8e8
0:007> gu
schannel!MakeEccDhPskSessionKeysHelper+0x189:
00007ffe`085e0e79 f60580e1060001  test    byte ptr [schannel!Microsoft_Windows_Schannel_EventsEnableBits (00007ffe`0864f000)],1 ds:00007ffe`0864f000=00
0:007> dq 000000b1d231d8e8 L1
000000b1`d231d8e8  000002a8`bcd8e300
0:007> db 000002a8`bcd8e300 L100
000002a8`bcd8e300  20 00 00 00 42 44 44 44-00 00 00 00 01 00 00 00   ...BDDD........
000002a8`bcd8e310  70 1e d8 bc a8 02 00 00-60 4a 4e bc a8 02 00 00  p.......`JN.....
000002a8`bcd8e320  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd8e330  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd8e340  0d 00 00 00 00 00 00 00-50 74 d8 bc a8 02 00 00  ........Pt......
000002a8`bcd8e350  20 ec d8 bc a8 02 00 00-00 00 00 00 00 00 00 00   ...............
000002a8`bcd8e360  10 c3 44 bc a8 02 00 00-01 00 00 00 01 00 00 00  ..D.............
000002a8`bcd8e370  20 ce cc bc a8 02 00 00-00 00 00 00 00 00 00 00   ...............
000002a8`bcd8e380  50 bc 44 bc a8 02 00 00-01 00 00 00 01 00 00 00  P.D.............
000002a8`bcd8e390  01 01 00 00 00 00 00 02-00 00 00 00 a8 02 04 00  ................
000002a8`bcd8e3a0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd8e3b0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd8e3c0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd8e3d0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd8e3e0  0d 00 00 00 00 00 00 00-50 66 d8 bc a8 02 00 00  ........Pf......
000002a8`bcd8e3f0  a0 83 d8 bc a8 02 00 00-60 e7 d8 bc a8 02 00 00  ........`.......

```

In the memory dump we get a very important tag `BDDD` that is mentioned in [\[1\]](#ref1) on page 77. This magic value corresponds to a NcryptSslKey structure that holds the magic at offset 4 and at offset 0x10 it holds a pointer to another structure with a magic value `5lss` (see [\[1\]](#ref1), pages 64-68). Lets read and dereference the pointer to check that:

```
0:007> dq 000002a8`bcd8e300+10 L1
000002a8`bcd8e310  000002a8`bcd81e70
0:007> db 000002a8`bcd81e70 L100
000002a8`bcd81e70  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
000002a8`bcd81e80  60 55 18 fa fd 7f 00 00-01 00 00 00 dc 49 52 f3  `U...........IR.
000002a8`bcd81e90  6d c4 a4 00 6b 25 3a f2-53 17 4e 6f 46 89 b3 f7  m...k%:.S.NoF...
000002a8`bcd81ea0  1b 4d 41 7d 1d a9 f4 8d-06 f3 9c 29 70 12 62 20  .MA}.......)p.b 
000002a8`bcd81eb0  e4 0b 1a 69 c2 be a8 4c-1e 60 3f d1 00 00 00 00  ...i...L.`?.....
000002a8`bcd81ec0  01 00 00 00 00 00 00 00-30 78 ca bc a8 02 00 00  ........0x......
000002a8`bcd81ed0  10 00 00 00 a8 02 00 00-c8 bc d8 bc a8 02 00 00  ................
000002a8`bcd81ee0  a0 bc d8 bc a8 02 00 00-60 f5 cc bc a8 02 00 00  ........`.......
000002a8`bcd81ef0  00 00 00 00 00 00 00 00-40 58 c4 bc a8 02 00 00  ........@X......
000002a8`bcd81f00  c2 01 00 00 00 00 00 00-00 00 00 00 00 00 08 00  ................
000002a8`bcd81f10  45 4e 43 44 00 00 00 00-e0 33 43 bc a8 02 00 00  ENCD.....3C.....
000002a8`bcd81f20  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd81f30  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd81f40  00 00 00 00 00 04 00 00-00 10 00 00 00 00 00 00  ................
000002a8`bcd81f50  10 1f d8 bc a8 02 00 00-00 00 00 00 00 00 00 00  ................
000002a8`bcd81f60  00 00 31 bc a8 02 00 00-66 77 36 aa 57 fd ff ff  ..1.....fw6.W...
```

As detailed on page 68 of [\[1\]](#ref1), the master key itself is located at offset 0x1c and has size of 48 (0x30) bytes:

```
0:007> db 000002a8`bcd81e70+1c L30
000002a8`bcd81e8c  dc 49 52 f3 6d c4 a4 00-6b 25 3a f2 53 17 4e 6f  .IR.m...k%:.S.No
000002a8`bcd81e9c  46 89 b3 f7 1b 4d 41 7d-1d a9 f4 8d 06 f3 9c 29  F....MA}.......)
000002a8`bcd81eac  70 12 62 20 e4 0b 1a 69-c2 be a8 4c 1e 60 3f d1  p.b ...i...L.`?.
```

Then we can disable our breakpoints (`bd *`), continue execution (`g`) and review the keylog file generated by sslsplit (edited for brevity):
```command
 % cat keys.log 
CLIENT_RANDOM 87EC<...>D986 284AD9<...>476F
CLIENT_RANDOM 5EEA<...>38DE DC4952<...>3FD1
```
We can see two keys: the first one is for the connection that sslsplit initiated to its configured destination, the second one - for the connection that originated from mstsc. As we can see, the master key in the log (`DC4952...3FD1`) is identical to the key that we've just read from memory. Okay great, now we just need something that ties this key to a session in a traffic dump, so that wireshark will know how to choose which key to use for which TLS connection.

Interestingly enough, the authors of [\[9\]](#ref9) didn't seem to undestand a way to extract master keys from `SslGenerateMasterKey` and used `ncrypt!NCryptDeriveKey` instead. When placing a breakpoint on that function we can see that it is indeed eventually called from `SslGenerateMasterKey` :
```
ncrypt!NCryptDeriveKey:
00007ffe`08e02040 48895c2408      mov     qword ptr [rsp+8],rbx ss:000000b1`d267da10=0000000000000000
0:008> k
 #  Call Site
00  ncrypt!NCryptDeriveKey
01  ncryptsslp!TlsGenerateSecretAgreementMasterKey+0xf3
02  ncryptsslp!SPSslGenerateMasterKey+0x23c
03  ncrypt!SslGenerateMasterKey+0x164
04  schannel!MakeEccDhPskSessionKeysHelper+0x189
<SNIP>
```

### <a href="#sect5.3" id="sect5.3">5.3</a> Matching keys to sessions

If we once again review the arguments of `SslGenerateMasterKey` ([\[13\]](#ref13)), we can see an interesting remark for the pParameterList argument:

```
...
_In_  PNCryptBufferDesc  pParameterList,
...
pParameterList [in]

    A pointer to an array of NCryptBuffer buffers that contain 
    information used as part of the key exchange operation.
    The precise set of buffers is dependent on the protocol 
    and cipher suite that is used. At the minimum, the list
    will contain buffers that hold the client and server
    supplied random values.
```

The client and server random values is precisely the thing we need to tie keys and sessions.  Fortunately, the `NCryptBuffer` and `NCryptBufferDesc` structs are documented as a part MS reference source for .NET Framework, see [\[17\]](#ref17):
```c
typedef struct _NCryptBufferDesc {
    ULONG         ulVersion;
    ULONG         cBuffers;
    PNCryptBuffer pBuffers;
} NCryptBufferDesc, *PNCryptBufferDesc;

typedef struct _NCryptBuffer {
    ULONG cbBuffer;
    ULONG BufferType;
    PVOID pvBuffer;
} NCryptBuffer, *PNCryptBuffer;
```

Let us again return to our breakpoint on `ncrypt!SslGenerateMasterKey` and examine the `pParameterList`!

The `pParameterList` is the 7th parameter out of 11. Parameters are pushed to stack right to left and concluded with return address. Between the return address and stack parameters there is also a 32-byte wide "register parameter area" which means that after the call instruction, the stack will have the following layout (see also [\[22\]](#ref22)):
```command
| RSP+0x58 |    11th arg    |
| RSP+0x50 |    10th arg    |
| RSP+0x48 |     9th arg    |
| RSP+0x40 |     8th arg    |
| RSP+0x38 |     7th arg    |
| RSP+0x30 |     6th arg    |
| RSP+0x28 |     5th arg    |
-----------------------------
| RSP+0x20 |  register      |
| RSP+0x18 |    parameter   |
| RSP+0x10 |                |
| RSP+0x08 |      area      |
-----------------------------
| RSP      | return address |
```

So, `RSP+0x38` will contain `pParameterList` and point to an `NCryptBufferDesc`. After dereferencing that pointer we will have the number of NCryptBuffer's at offset 4 and the pointer to an array of `NCryptBuffer`'s at offset 8:
```
0:003> dp rsp+0x38 L1
000000b1`d2a7deb0  000000b1`d2a7def0  // address of NCryptBufferDesc:
0:003> dd 000000b1`d2a7def0 + 4 L1
000000b1`d2a7def4  00000002           // NCryptBufferDesc.cBuffers:	   
0:003> dp 000000b1`d2a7def0 + 8 L1
000000b1`d2a7def8  000000b1`d2a7df10  // NCryptBufferDesc.pBuffers
```
Okay, so we have two NCryptBuffers of 0x10 bytes each in an array at address NCryptBufferDesc.pBuffers. How do we make sense of the NCryptBuffer.BufferType ULONG? The answer lies in NCRYPTBUFFER_SSL_* constans in ncrypt.h (see, for example, [\[18\]](#ref18)). Let us examine which types of NCryptBuffers do we have in our call:
```
0:003> dd  000000b1`d2a7df10  L1
000000b1`d2a7df10  00000020           // NCryptBufferDesc.pBuffers[0].cbBuffer (0x20 bytes)         
0:003> dd  000000b1`d2a7df10+4  L1    
000000b1`d2a7df14  00000014           // NCryptBufferDesc.pBuffers[0].BufferType
                                      // 0x14 == 20 == NCRYPTBUFFER_SSL_CLIENT_RANDOM 
0:003> dp  000000b1`d2a7df10+8  L1
000000b1`d2a7df18  000002a8`bce02720
0:003> db 000002a8`bce02720 L20       // NCryptBufferDesc.pBuffers[0].pvBuffer:
000002a8`bce02720  5e ea 28 e3 63 b1 bb b5-8f 8a 27 b7 4e 4c 8d 99  ^.(.c.....'.NL..      
000002a8`bce02730  58 f7 0e 21 aa b1 c5 01-bc 26 19 6b 79 5c 37 1a  X..!.....&.ky\7.      
0:003> dd  000000b1`d2a7df10+10  L1
000000b1`d2a7df20  00000020           // NCryptBufferDesc.pBuffers[1].cbBuffer (0x20 bytes)
0:003> dd  000000b1`d2a7df10+10+4  L1
000000b1`d2a7df24  00000015           // NCryptBufferDesc.pBuffers[1].BufferType
                                      // 0x15 == 21 == NCRYPTBUFFER_SSL_SERVER_RANDOM
0:003> dp  000000b1`d2a7df10+10+8  L1
000000b1`d2a7df28  000002a8`bce02740
0:003> db 000002a8`bce02740 L20       // NCryptBufferDesc.pBuffers[1].pvBuffer
000002a8`bce02740  5e ea 28 e3 93 ac 93 7b-64 96 3c 5e 21 a9 aa 00  ^.(....{d.<^!...   
000002a8`bce02750  06 52 40 b0 03 6c 09 27-44 4f 57 4e 47 52 44 01  .R@..l.'DOWNGRD.   
```

So, it seems that we can get both the client and server random and the master key from hooking this one call, sweet.

Also, notice this strange `DOWNGRD` in the server random above? This is a downgrade-preventing feature of servers that support TLS1.3 (in my case - sslsplit linked with a modern version of OpenSSL). When they receive connection from a client that says it does not support TLS1.3 (in my case, mstsc), they include this string in server random, so that if the client really supports TLS1.3, but this info was stripped away by a MITM in an attempt to downgrade to TLS1.2, the client will detect the downgrade.

Another thing to notice here is the fact that both the client and the server random start with the same 4-byte sequence. This is because as per TLS1.2 spec, they should contain the unix time of the connection (see [\[20\]](#ref20), section 7.4.1.2). Windows clients and servers conform to this, while for OpenSSL it really depends on the version - modern versions of OpenSSL use just random bytes instead.

### <a href="#sect5.4" id="sect5.4">5.4</a> Automation with frida-trace

Knowing all the things above is good, but the windbg-based approach will not scale well for automation. The easiest way to perform all of this extraction is to use the frida dynamic instrumentation toolkit [\[21\]](#ref21). 

To get a quick prototype we'll use the frida-trace tool. First we need to create a javascript handler for the calls to `SslGenerateMasterKey` and store it in `__handlers__\ncrypt.dll\SslGenerateMasterKey.js`. The content of the handler is as follows:
```javascript
{
    onEnter: function (log, args, state) {
        var buf2hex = function (buffer) {
            return Array.prototype.map.call(
                    new Uint8Array(buffer),
                    function(x){
                        return ('00' + x.toString(16)).slice(-2)
                    }
            ).join('');
        }
        // https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey
        this.phMasterKey = ptr(args[3]);
        this.hSslProvider = ptr(args[0]);

        this.pParameterList = ptr(args[6]);
        /*
           typedef struct _NCryptBufferDesc {
           ULONG         ulVersion;
           ULONG         cBuffers;
           PNCryptBuffer pBuffers;
           } NCryptBufferDesc, *PNCryptBufferDesc;

           typedef struct _NCryptBuffer {
           ULONG cbBuffer;
           ULONG BufferType;
           PVOID pvBuffer;
           } NCryptBuffer, *PNCryptBuffer;
           */
        var buffer_count = this.pParameterList.add(4).readU32();
        var buffers = this.pParameterList.add(8).readPointer();
        for(var i = 0 ; i < buffer_count ; i ++){
            var buf = buffers.add(16*i);
            var buf_size = buf.readU32();
            var buf_type = buf.add(4).readU32();
            var buf_buf = buf.add(8).readPointer().readByteArray(buf_size);
            // For buf_type values see NCRYPTBUFFER_SSL_* constans in ncrypt.h
            if (buf_type == 20){ // NCRYPTBUFFER_SSL_CLIENT_RANDOM
                this.client_random = buf2hex(buf_buf);
            }else if(buf_type == 21){ // NCRYPTBUFFER_SSL_SERVER_RANDOM
                this.server_random = buf2hex(buf_buf);
            }
        }
    },
    onLeave: function (log, retval, state) {
        var buf2hex = function (buffer) {
            return Array.prototype.map.call(
                    new Uint8Array(buffer),
                    function(x){
                        return ('00' + x.toString(16)).slice(-2)
                    }
            ).join('');
        }
        var ret_addr = this.returnAddress;
        var NcryptSslKey_ptr = this.phMasterKey.readPointer(); // NcryptSslKey
        var ssl5_ptr = NcryptSslKey_ptr.add(0x10).readPointer();
        var master_key = ssl5_ptr.add(28).readByteArray(48);
        var crandom = "???";
        if(this.client_random){
            crandom = this.client_random;
        }
        console.log("CLIENT_RANDOM " + crandom + " " + buf2hex(master_key))
    }
}
```

The we can launch frida-trace  the following way (from an administrative powershell prompts):

```
PS C:\tools\frida> frida-trace.exe lsass.exe -i SslGenerateMasterKey | tee keylog.log
Attaching...
Resolving functions...
Instrumenting functions...
SslGenerateMasterKey: Loaded handler at "C:\\tools\\frida\\__handlers__\\ncrypt.dll\\SslGenerateMasterKey.js"
Started tracing 1 function. Press Ctrl+C to stop.
CLIENT_RANDOM 5eea40a6be36c68877e1d5bfbdc0796e3e2b5cc24ebfef17c10786ea00a03e8f afd8f7ad08b1d1f0c3d3b5ae6bc1184674971d7a3cfa4462a3e518fc4a43fdb2b62a18ba71a070217744ec67e0c19fc5
CLIENT_RANDOM 5eea40a7f48e12896355cc433a209e42f97d5238da5b999a7f527c2d785776d3 781e7063934ff693e42ae7d77e22728a2a11715c60d06f8aaaa48545b6b51fea52a922ffa743725a9d7a28a70da94dfd
....
```

### <a href="#sect5.5" id="sect5.5">5.5</a> Dealing with non-PFS ciphersuites on the server

The frida script above works for keys exchanged using PFS ciphers (i.e. those based on diffie-hellman exchange) both on client and on server. This also works when windows client connects to a server using a non-PFS ciphersuite.
However, this does not work when a windows server accepts a connection that uses a non-PFS ciphersuite - the `SslGenerateMasterKey` function is never called. Nor, for that matter, the `ncrypt!NCryptDeriveKey` used in [\[9\]](#ref9). This is because for RSA-based key exchange the master key is not computed during diffie-hellman exchange, but generated by the client and sent to server, encrypted by the server's public key (thats why it is not forwardly-secret - we can decrypt it at any time if we have the server private key).
Let's find out what is used instead. As we can see from stack traces above, there is a function `schannel!CSsl3TlsContext::ProcessHandshakeCommon` that might be responsible for generic processing of handshakes, with any type of key exchange. Trying setting a breakpoint on it reveals that it is not called on server when handling incoming RDP. Going down the stack and setting breakpoints, we eventually reach `lsasrv!SspiExProcessSecurityContext` that *does* get called in this case. 
Then we can repeat `pct` (go to next call) + `p` (step over) to find out which interesting functions are called from `SspiExProcessSecurityContext`.

After a couple of `memset`s we get a call to `lsasrv!SspipBuildCallInfo` and after skipping it - a call to `lsasrv!WLsaAcceptContext`, which seems to be related to accepting connections. 

We also know that schannel.dll and/or ncrypt.dll are certainly related to key calculation. While stopped at `lsasrv!WLsaAcceptContext`, we can breakpoint all of the ncrypt.dll functions using `bm ncrypt!`.


One `g;k` later we get the following backtrace (from here and below I will omit everything below `lsasrv!WLsaAcceptContext`):
```
00 00000095`87c7d858 00007ffe`49e60194 ncrypt!SslHashHandshake
01 00000095`87c7d860 00007ffe`49e66a18 schannel!CSsl3TlsContext::UpdateHandshakeHash+0x64
02 00000095`87c7d8a0 00007ffe`49e6e5da schannel!CSsl3TlsServerContext::ProcessHandshake+0x1b8
03 00000095`87c7d920 00007ffe`49e52759 schannel!CSsl3TlsServerContext::ProcessRecord+0xea
04 00000095`87c7d980 00007ffe`49e52499 schannel!CSsl3TlsContext::TlsProtocolHandlerWorker+0x229
05 00000095`87c7da60 00007ffe`49e6d70c schannel!CSsl3TlsContext::SslProtocolHandler+0x79
06 00000095`87c7daa0 00007ffe`4a7c0cc0 schannel!SpAcceptLsaModeContext+0xbbc
07 00000095`87c7dea0 00007ffe`4a7bfd14 lsasrv!WLsaAcceptContext+0x370
<SNIP>
```

Not exactly what we expect, let's continue until next call to ncrypt (`g;k`):
```
 # Child-SP          RetAddr           Call Site
00 00000095`87c7d658 00007ffe`35aece9a ncrypt!NCryptGetProperty
01 00000095`87c7d660 00007ffe`4a68c04a ncryptsslp!SPSslGetKeyProperty+0x19a
02 00000095`87c7d6c0 00007ffe`49eb03f1 ncrypt!SslGetKeyProperty+0x7a
03 00000095`87c7d700 00007ffe`49eb1051 schannel!GetRsaKeyModulus+0x29
04 00000095`87c7d740 00007ffe`49e7f66c schannel!CSslContext::I_RsaGenerateServerMasterKey+0xb1
05 00000095`87c7d8a0 00007ffe`49e6e5da schannel!CSsl3TlsServerContext::ProcessHandshake+0x18e0c
06 00000095`87c7d920 00007ffe`49e52759 schannel!CSsl3TlsServerContext::ProcessRecord+0xea
07 00000095`87c7d980 00007ffe`49e52499 schannel!CSsl3TlsContext::TlsProtocolHandlerWorker+0x229
08 00000095`87c7da60 00007ffe`49e6d70c schannel!CSsl3TlsContext::SslProtocolHandler+0x79
09 00000095`87c7daa0 00007ffe`4a7c0cc0 schannel!SpAcceptLsaModeContext+0xbbc
0a 00000095`87c7dea0 00007ffe`4a7bfd14 lsasrv!WLsaAcceptContext+0x370
```

This `CSslContext::I_RsaGenerateServerMasterKey` sounds really interesting, lets keep searching for next ncrypt calls with `g;k`. A couple of iterations later we get:

```
 # Child-SP          RetAddr           Call Site
00 00000095`87c7d4a8 00007ffe`4a68d621 ncrypt!ValidateClientKeyHandle
01 00000095`87c7d4b0 00007ffe`35af005b ncrypt!NCryptDecrypt+0x71
02 00000095`87c7d540 00007ffe`35aed1e3 ncryptsslp!TlsDecryptMasterKey+0x123
03 00000095`87c7d670 00007ffe`4a68c3ce ncryptsslp!SPSslImportMasterKey+0x1b3
04 00000095`87c7d6e0 00007ffe`49eb11e1 ncrypt!SslImportMasterKey+0x11e
05 00000095`87c7d740 00007ffe`49e7f66c schannel!CSslContext::I_RsaGenerateServerMasterKey+0x241
06 00000095`87c7d8a0 00007ffe`49e6e5da schannel!CSsl3TlsServerContext::ProcessHandshake+0x18e0c
07 00000095`87c7d920 00007ffe`49e52759 schannel!CSsl3TlsServerContext::ProcessRecord+0xea
08 00000095`87c7d980 00007ffe`49e52499 schannel!CSsl3TlsContext::TlsProtocolHandlerWorker+0x229
09 00000095`87c7da60 00007ffe`49e6d70c schannel!CSsl3TlsContext::SslProtocolHandler+0x79
0a 00000095`87c7daa0 00007ffe`4a7c0cc0 schannel!SpAcceptLsaModeContext+0xbbc
0b 00000095`87c7dea0 00007ffe`4a7bfd14 lsasrv!WLsaAcceptContext+0x370
```

Bingo! Documentation for `ncrypt!SslImportMasterKey` ([\[26\]](#ref26)) seems to confirm that it does exactly what we expect - given a private key `hPrivateKey`, a master key that was sent by client (encrypted by server's public key) -- `pbEncryptedKey`, it will decrypt the master key and write it to `phMasterKey`:

```
SECURITY_STATUS WINAPI SslImportMasterKey(
  _In_  NCRYPT_PROV_HANDLE hSslProvider,
  _In_  NCRYPT_KEY_HANDLE  hPrivateKey,
  _Out_ NCRYPT_KEY_HANDLE  *phMasterKey,
  _In_  DWORD              dwProtocol,
  _In_  DWORD              dwCipherSuite,
  _In_  PNCryptBufferDesc  pParameterList,
  _In_  PBYTE              pbEncryptedKey,
  _In_  DWORD              cbEncryptedKey,
  _In_  DWORD              dwFlags
);
```

What is event better, we can reuse our logic for parsing `pParameterList` that we already have for getting the client random.

### <a href="#sect5.6" id="sect5.6">5.6</a> Dealing with TLS session hashes

While testing the above approach, I've found that sometimes, when trying to get the client_random from the args of `Ssl{Generate,Import}MasterKey`, I see that it is not passed inside `pParameterList`! Though the docs ([\[26\]](#ref26)) say that `At the minimum, the list will contain buffers that contain the client and server supplied random values`, in some cases it only contains buffers of type 22 and 25. 22 is `NCRYPTBUFFER_SSL_HIGHEST_VERSION`, which is not useful at all. 25 is `NCRYPTBUFFER_SSL_SESSION_HASH`. WTF is the SSL session hash?

Well, it seems that the use of client and server random values in the process of deriving the Master Secrets opens up some very specific types of abuse, so a TLS extension called TLS Session Hash and Extended Master Secret (RFC 7627, [\[27\]](#ref27)) was developed. When this extension is in use, the calculation of the master secret instead of just using client and server random values, involves a hash of contents of hanshake messages (ClientHello, ServerHello) instead of just client and server randoms, which is why we get this hash instead of them. Unfortunately, wireshark does not support tying keys to sessions using a session hash. 

By the way, we have encountered session hash instead of client random when trying to get keys from a server connection (Win10 terminal services in this case), but in reality it can of course also be used in client connections, if the remote server supports and is willing to use it. 

Now we have two ways to proceed:

1. Modify wireshark to support tying sessions to keys in a keylog file by a session hash;
2. Find a way to either extract the client random without relying on it being present in `pParameterList` or  extract the TLS session id.

Let's try option 2 and leave patching Wireshark for future. Remember when we were trying to find the function which was responsible for getting master secret for non-PFS connections? We've seen the following backtrace:

```
00 00000095`87c7d858 00007ffe`49e60194 ncrypt!SslHashHandshake
01 00000095`87c7d860 00007ffe`49e66a18 schannel!CSsl3TlsContext::UpdateHandshakeHash+0x64
02 00000095`87c7d8a0 00007ffe`49e6e5da schannel!CSsl3TlsServerContext::ProcessHandshake+0x1b8
03 00000095`87c7d920 00007ffe`49e52759 schannel!CSsl3TlsServerContext::ProcessRecord+0xea
04 00000095`87c7d980 00007ffe`49e52499 schannel!CSsl3TlsContext::TlsProtocolHandlerWorker+0x229
05 00000095`87c7da60 00007ffe`49e6d70c schannel!CSsl3TlsContext::SslProtocolHandler+0x79
06 00000095`87c7daa0 00007ffe`4a7c0cc0 schannel!SpAcceptLsaModeContext+0xbbc
07 00000095`87c7dea0 00007ffe`4a7bfd14 lsasrv!WLsaAcceptContext+0x370
<SNIP>
```
When we dig into the documentation of `SslHashHandshake` ([\[28\]](#ref28)) we find the following:
```
The SslHashHandshake function is one of three functions 
used to generate a hash to use during the SSL handshake.

    The SslCreateHandshakeHash function 
    	is called to obtain a hash handle.
    The SslHashHandshake function 
    	is called any number of times with 
    	the hash handle to add data to the hash.
    The SslComputeFinishedHash function 
    	is called with the hash handle to obtain 
    	the digest of the hashed data.
```

As per RFC 7627, the hash includes the whole client and server hello, which means that during the calculation of the hash the `SslHashHandshake` will be fed with all the bytes from the Client Hello, which, of course, includes the client random. Let's verify that using a quick frida-trace and creating a RDP connection to our server while capturing the traffic with wireshark:
```command
PS > type __handlers__/ncrypt.dll/SslHashHandshake.js
{
  onEnter: function (log, args, state) {    
    var buf = ptr(args[2]);
    var len = args[3].toInt32();
    var mem = buf.readByteArray(len);
    log(hexdump(mem));
  },
  onLeave: function (log, retval, state) {
  }
}

PS > frida-trace.exe lsass.exe -i SslHashHandshake
  3485 ms             0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  0123456789ABCDEF
00000000  01 00 01 33 03 03 79 ea fd 05 d4 89 61 6d 5e e4  ...3..y.....am^.
00000010  a9 ee 5d 6a 13 65 76 2b 11 81 5e 43 ac 8e f0 f3  ..]j.ev+..^C....
00000020  09 66 d5 04 06 05 20 de 20 2f 5d 18 af 23 5d 58  .f.... . /]..#]X
00000030  7f a6 42 d5 68 f4 55 b4 9b c0 72 74 1b 06 0a e8  ..B.h.U...rt....
00000040  de ee c7 7c f6 95 4f 00 3e 13 02 13 03 13 01 c0  ...|..O.>.......
00000050  2c c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00  ,.0.........+./.
00000060  9e c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0  ..$.(.k.#.'.g...
00000070  14 00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00  ..9.....3.....=.
00000080  3c 00 35 00 2f 00 ff 01 00 00 ac 00 00 00 13 00  <.5./...........
00000090  11 00 00 0e 31 39 32 2e 31 36 38 2e 38 38 2e 31  ....192.168.88.1
000000a0  39 33 00 0b 00 04 03 00 01 02 00 0a 00 0c 00 0a  93..............
000000b0  00 1d 00 17 00 1e 00 19 00 18 00 23 00 00 00 16  ...........#....
000000c0  00 00 00 17 00 00 00 0d 00 30 00 2e 04 03 05 03  .........0......
000000d0  06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05  ................
000000e0  08 06 04 01 05 01 06 01 03 03 02 03 03 01 02 01  ................
000000f0  03 02 02 02 04 02 05 02 06 02 00 2b 00 09 08 03  ...........+....
00000100  04 03 03 03 02 03 01 00 2d 00 02 01 01 00 33 00  ........-.....3.
00000110  26 00 24 00 1d 00 20 16 fc 5f 22 81 bf c1 24 53  &.$... .._"...$S
00000120  a1 f6 eb ad 03 0b 96 0e 46 a1 86 1b a8 7a a3 0f  ........F....z..
00000130  42 19 99 31 a1 7b 44                             B..1.{D
<SNIP> ....
```

If we then examine the Client Hello in Wireshark we'll see the following:

```command
Handshake Protocol: Client Hello
    Handshake Type: Client Hello (1)
    Length: 307
    Version: TLS 1.2 (0x0303)
    Random: 79eafd05d489616d5ee4a9ee5d6a1365762b11815e43ac8e…
        GMT Unix Time: Oct 26, 2034 05:42:13.000000000 RTZ 2 (зима)
        Random Bytes: d489616d5ee4a9ee5d6a1365762b11815e43ac8ef0f30966…
    Session ID Length: 32
    Session ID: de202f5d18af235d587fa642d568f455b49bc072741b060a…
    Cipher Suites Length: 62
    Cipher Suites (31 suites)
    <SNIP>
```

As we can see, the argument of SslHashHandshake contains exactly the ClientHello we see in Wireshark. The first byte (01) signifies that we are looking at a Client Hello, after that we have three bytes for the length (0x000133 == 307), after that 03 03 for TLS 1.2, and after that - the client random.

SslHashHandshake is called three times, but we can distinguish the needed call by the `01 ?? ?? ?? 03 03` prefix and grab the client secret starting at offset 6. With this, we have all the instruments we need to grab the keys and client randoms for TLS1.2 connections.


## <a href="#sect6" id="sect6">6</a> Obtaining TLS1.3 keys

All of the above was relevant for TLS1.2 key extraction only. During discussions on wireshark-dev ML, Peter Wu pointed to me that, starting from 1909, Windows 10 also includes experimental support for TLS1.3 ([\[30\]](#ref30)). I decided to look into extracting TLS1.3 secrets as well.

While TLS1.3 can be used instead of TLS1.2 for common TCP connections, it is also a building block for the new UDP-based QUIC protocol, which relies on TLS 1.3 for keys an encryption ([\[32\]](#ref32)). Microsoft has an cross-platform implementation of the QUIC protocol called MsQuic, which is open source and this implementation is helpful in many ways.   
First of all, it contains instructions to enable TLS1.3 support ([\[31\]](#ref31)). Secondly, as Peter has pointed out, it supports schannel as one of its TLS backends ([\[33\]](#ref33)).


After editing registry in accordance with [\[31\]](#ref31), I was able to test that TLS1.3 works using Invoke-WebRequest powershell cmdlet:
```command
PS C:\> iwr https://enabled.tls13.com/
```

Note, however, that this is not very convenient for debugging - powershell currently is not able to connect to openssl 1.1.1 servers because of an issue in .NET runtime ([\[35\]](#ref35)).

Also, I wasn't able to make the older non-chromium Edge or Internet Explorer use TLS1.3 even though I've enabled TLS1.3 in IE settings. 

So, in order to be able to comfortly test TLS1.3 on windows I used a small SSLWrapper library by PJ Naughter ([\[36\]](#ref36)). This library has an example application called SSLWrappersDemo, which is capable of making TLS1.3 connections via shannel, and can be used as follows:
```command
PS C:\> .\SSLWrappersDemo.exe 0 192.168.88.193 443
```

After setting a breakpoint on SslGenerateMasterKey as before, we can verify that this function is no longer called during the connection. We then set a breakpoint on any ncrypt.dll call via `bm ncrypt!` and repeat our tls1.3 request. Continuing a couple of times, we eventually get the following backtrace:
```
 # Child-SP          RetAddr           Call Site
00 00000044`1707dba8 00007ffd`4f7c7a62 ncrypt!SslCreateEphemeralKey
01 00000044`1707dbb0 00007ffd`4f7c7bde schannel!CTls13Handshake<CTls13ClientContext,CTls13ExtClient>::ComputeKeyShareEntrySize+0x8e
02 00000044`1707dc20 00007ffd`4f7c7582 schannel!CTls13ClientHandshake::ComputeKeyShareExtensionSize+0x22
03 00000044`1707dc50 00007ffd`4f7c7718 schannel!CTls13ClientHandshake::ComputeClientHelloExtensionsSize+0xda
04 00000044`1707dc80 00007ffd`4f7cc903 schannel!CTls13ClientHandshake::ComputeClientHelloSize+0x114
05 00000044`1707dcb0 00007ffd`4f77a6c2 schannel!CTls13ClientContext::GenerateHello+0x213
06 00000044`1707dec0 00007ffd`501450d3 schannel!SpInitLsaModeContext+0x652
07 00000044`1707e030 00007ffd`50140461 lsasrv!WLsaInitContext+0x4e3
<SNIP>
```

As we can see, we're indeed inside a TLS1.3 client context as hinted by `CTls13ClientContext` class. Examining some other ncrypt.dll functions that are called did not quickly reveal candidates for a function that calculates any of the second-stage traffic secrets that we need for TLS1.3.

Another approach to understanding TLS1.3 in schannel was suggested by Peter Wu on the wireshark-dev and was based on schannel-related code from MsQuic ([\[33\]](#ref33)). 
There we can see that inside a `QuicTlsWriteDataToSchannel` function we call a `AcceptSecurityContext`or `InitializeSecurityContextW`, which are SSPI entrypoints into schannel (the code is heavily edited for brevity):
```c

_IRQL_requires_max_(PASSIVE_LEVEL)
QUIC_TLS_RESULT_FLAGS
QuicTlsWriteDataToSchannel(
    _In_ QUIC_TLS* TlsContext,
    _In_reads_(*InBufferLength)
    const uint8_t* InBuffer,
    _Inout_ uint32_t* InBufferLength,
    _Inout_ QUIC_TLS_PROCESS_STATE* State
    )
{
    /* SNIP */
    SecBufferDesc OutSecBufferDesc;
    OutSecBufferDesc.ulVersion = SECBUFFER_VERSION;
    OutSecBufferDesc.pBuffers = OutSecBuffers;
    OutSecBufferDesc.cBuffers = 0;
    /* SNIP */
    //
    // Four more output secbuffers for any traffic secrets generated.
    //
    for (uint8_t i = 0; i < SEC_TRAFFIC_SECRETS_COUNT; ++i) {
        OutSecBuffers[OutSecBufferDesc.cBuffers].BufferType = SECBUFFER_TRAFFIC_SECRETS;
        OutSecBuffers[OutSecBufferDesc.cBuffers].cbBuffer = MAX_SEC_TRAFFIC_SECRETS_SIZE;
        OutSecBuffers[OutSecBufferDesc.cBuffers].pvBuffer =
            TlsContext->Workspace.OutTrafSecBuf + i * MAX_SEC_TRAFFIC_SECRETS_SIZE;
        OutSecBufferDesc.cBuffers++;
    }
    /* SNIP */
    if (TlsContext->IsServer) {
        QUIC_SERVER_SEC_CONFIG* SecConfig = (QUIC_SERVER_SEC_CONFIG*)TlsContext->SecConfig;
        QUIC_DBG_ASSERT(SecConfig->IsServer == TRUE);

        SecStatus =
            AcceptSecurityContext(
                &SecConfig->CertificateHandle,
                SecIsValidHandle(&TlsContext->SchannelContext) ? &TlsContext->SchannelContext : NULL,
                &InSecBufferDesc,
                ContextReq,
                0,
                &(TlsContext->SchannelContext),
                &OutSecBufferDesc,
                &ContextAttr,
                NULL); // FYI, used for client authentication certificate.

    } else {
        QUIC_CLIENT_SEC_CONFIG* SecConfig = (QUIC_CLIENT_SEC_CONFIG*)TlsContext->SecConfig;
        QUIC_DBG_ASSERT(SecConfig->IsServer == FALSE);

        SecStatus =
            InitializeSecurityContextW(
                &SecConfig->SchannelHandle,
                SecIsValidHandle(&TlsContext->SchannelContext) ? &TlsContext->SchannelContext : NULL,
                TargetServerName, // Only set to non-null on client initial.
                ContextReq,
                0,
                SECURITY_NATIVE_DREP,
                &InSecBufferDesc,
                0,
                &TlsContext->SchannelContext,
                &OutSecBufferDesc,
                &ContextAttr,
                NULL);
    }
    /* SNIP */
    for (uint32_t i = 0; i < OutSecBufferDesc.cBuffers; ++i) {
    	if(...)
        /* SNIP */
        } else if (OutSecBufferDesc.pBuffers[i].BufferType == SECBUFFER_TRAFFIC_SECRETS) {
            SEC_TRAFFIC_SECRETS* TrafficSecret =
                (SEC_TRAFFIC_SECRETS*)OutSecBufferDesc.pBuffers[i].pvBuffer;
            /* SNIP */
        }
    }
```



As we can see learn the docs, the 10th parameter of `InitializeSecurityContextW` and the 7th for `AcceptSecurityContext`, is used for returning additional output data from the call. Before calling these SSPI functions, the calling code will pre-allocate a data structure called OutSecBuffers that will be populated by schannel with various pieces of information after the call. Among others, the calling code allocates place for data of type SECBUFFER_TRAFFIC_SECRETS, which might be related to the secrets we need to extract! The returned data is later cast to type SEC_TRAFFIC_SECRETS, and the according definitions from ntifs.h seem to be promising:

```c
    //
    //  Traffic secret types:
    //
    typedef enum _SEC_TRAFFIC_SECRET_TYPE
    {
        SecTrafficSecret_None,
        SecTrafficSecret_Client,
        SecTrafficSecret_Server
    } SEC_TRAFFIC_SECRET_TYPE, *PSEC_TRAFFIC_SECRET_TYPE;

    #define SZ_ALG_MAX_SIZE 64

    typedef struct _SEC_TRAFFIC_SECRETS {
        wchar_t SymmetricAlgId[SZ_ALG_MAX_SIZE];     // Negotiated symmetric key algorithm. e.g. BCRYPT_AES_ALGORITHM.
        wchar_t ChainingMode[SZ_ALG_MAX_SIZE];       // Negotiated symmetric key algorithm chaining mode. e.g. BCRYPT_CHAIN_MODE_GCM or BCRYPT_CHAIN_MODE_CCM.
        wchar_t HashAlgId[SZ_ALG_MAX_SIZE];          // Negotiated hash algorithm. e.g. BCRYPT_SHA256_ALGORITHM or BCRYPT_SHA384_ALGORITHM.
        unsigned short KeySize;                      // Size in bytes of the symmetric key to derive from this traffic secret.
        unsigned short IvSize;                       // Size in bytes of the IV to derive from this traffic secret.
        unsigned short MsgSequenceStart;             // Offset of the first byte of the TLS message sequence to be protected with a key derived from TrafficSecret. Zero to indicate the first byte of the buffer.
        unsigned short MsgSequenceEnd;               // Offset of the last byte of the TLS message sequence to be protected with a key derived from TrafficSecret. Zero if the secret is for the encryption of application data or decryption of incoming records.
        SEC_TRAFFIC_SECRET_TYPE TrafficSecretType;   // Type of traffic secret from the TRAFFIC_SECRET_TYPE enumeration.
        unsigned short TrafficSecretSize;            // Size in bytes of the traffic secret.
        unsigned char  TrafficSecret[ANYSIZE_ARRAY]; // Traffic secret of type TrafficSecretType, TrafficSecretSize bytes long, used to derive write key and IV for message protection.
    } SEC_TRAFFIC_SECRETS, *PSEC_TRAFFIC_SECRETS;

```


So, maybe we can just get the secrets from these OutSecBuffers after the return from the `AcceptSecurityContext` or `InitializeSecurityContextW` call?

The answer is, sadly, a no. When I tried hooking the function that corresponds to InitializeSecurityContextW, which is `schannel!SpInitLsaModeContext` and examined the 10th parameter before and after the call, I've found that neither powershell's invoke-WebRequest nor my SSLWrapper test application actually allocate OutSecBuffers of type SECBUFFER_TRAFFIC_SECRETS, and, logically, these are not returned from the `InitializeSecurityContextW` call. This means that this way of extraction is more suited for applications, whose code we can modify. In order to be able to get secrets this way without recompilation, we would need to dynamically rewrite the arguments to `InitializeSecurityContextW` and after the call rewrite the result back, because the calling code might freak out if it receives OutBuffers of type it does not expect. While this is certainly doable, this is a cumbersome task that I would rather not implement.

As an additional test I tried to use the MsQuic itself, because, as we can see in the code, its implementatin does allocate OutSecBuffers of type SECBUFFER_TRAFFIC_SECRETS. 
After getting the source from github (do not forget to do a recursive clone to get all the submodules, and also I recommend that you use a stable tag, not the master - I used `v0.9-draft-28`), I builе MsQuic using instructions in doc/BUILD.md. After that I used the `quicinterop` tool (`\artifacts\windows\x64_Debug_schannel\quicinterop.exe`) that issues a number of QUIC connections to various public testing points. After again hooking the  `schannel!SpInitLsaModeContext` function, I could indeed see those buffers of type SEC_TRAFFIC_SECRETS (=28, see [\[39\]](#ref39)). However, both before and after the call to `InitializeSecurityContextW` those buffers remained filled with zeroes. I'm not sure if this is a bug in schannel, MsQuic or my hooking process, but I wasn't able to get the keys this way even for the client application whose code I controlled.

Let us return to ncrypt.dll and try some static analysis. Instead of looking for usages of ncrypt.dll APIs while debugging, I tried to look through the symbols that are exported by ncrypt.dll and correlate their names with some key/secret names from RFC 8446 ([\[34\]](#ref34)). After a little bit of analysis the following functions came into my attention:
```command
SslExpandTrafficKeys
SslExpandWriteKey
```

The `Expand` part might have something to do with `HKDF-Expand-Label` primitive from RFC, at least for the `WriteKey` this makes perfect sense. I then hook these functions with frida-trace to find out if any of them are called during a TLS1.3 handshake. This resulted in calls in the following order:
```command
SslExpandTrafficKeys
SslExpandWriteKey
SslExpandWriteKey
SslExpandTrafficKeys
SslExpandWriteKey
SslExpandWriteKey
```

As you can see, `SslExpandTrafficKeys` is called twice and `SslExpandWriteKey` is called four times. Reading RFC 8446 ([\[34\]](#ref34), pages 92-94), I found out that during a normal (not resumed) handshake the following will be generated: 
 - two handshake traffic secrets,
 - two application traffic secrets, 
 - one exporter master secret,
 - one resumption master secret. 

Each of the traffic secrets is then used to generate a write key and IV. Given the pattern of calls (one `SslExpandTrafficKeys` followed by two `SslExpandWriteKey`) we can deduce that `SslExpandTrafficKeys` probably calculates both the client and the server **secrets**, and then for each of them `SslExpandWriteKey` is called. This happens two times - one for handshake traffic secrets and one for application traffic secrets. 

This seems to also be supported by the ghidra's decompilation of `schannel!CTls13Context::ExpandTrafficAndWriteKeys`, which contains a call to `SslExpandTrafficKeys` followed by two calls to `SslExpandWriteKey`:

```c

ulong __thiscall
ExpandTrafficAndWriteKeys
          (CTls13Context *this,__uint64 param_1,__uint64 param_2,__uint64 param_3,__uint64 *param_4,
          __uint64 *param_5,__uint64 *param_6,__uint64 *param_7,eSslErrorState *param_8)

{
    // <SNIP>
    uVar1 = (*(code *)__imp_SslExpandTrafficKeys)(param_1,param_2,param_3,param_4,param_5,0,0);
    if (uVar1 == 0) {
      if (this[0xa9] != (CTls13Context)0x0) {
        uVar1 = (*(code *)__imp_SslExpandWriteKey)
                          (param_1,*param_4,param_6,0,(ulonglong)param_5._4_4_ << 0x20);
        if (uVar1 != 0) {
          *param_8 = 0x25e;
          return uVar1;
        }
        uVar1 = (*(code *)__imp_SslExpandWriteKey)
                          (param_1,*param_5,param_7,0,(ulonglong)param_5._4_4_ << 0x20);
        if (uVar1 != 0) {
          *param_8 = 0x25f;
          return uVar1;
        }
      }
      uVar1 = 0;
    }
    // <SNIP>
}

```
From ghidra we can also find that the aforementioned `CTls13Context::ExpandTrafficAndWriteKeys` is called from two places, namely `CTls13Context::GenerateHandshakeWriteKeys` and `CTls13Context::GenerateApplicationWriteKeys`. This confirms our suspicions.

Note that there is a naming confusion between the RFC 8446 and `ncrypt.dll` symbols. In RFC 8446 the intermediate secret values are called **secrets** and only the end keys that are used to actually encrypt/decrypt traffic are called (write) **keys**. In ncrypt.dll all sorts of secrets are called keys. We have already established that `SslExpandTrafficKeys` expands traffic **secrets**, not  **keys**. 

But secrets (and not keys) is exactly what I needede for SSLKEYLOGFILE (see [section 1.3](#sect1.3))! This means that it should be enough to hook the output of `SslExpandTrafficKeys` - each call should provide me with two secrets.

Looking at the listing of `CTls13Context::ExpandTrafficAndWriteKeys` above, we can deduce that `SslExpandTrafficKeys` places the two resulting keys into param_4 and param_5. Let's try to check them in the debugger, but before doing that, we'll fire up our openssl s_server testbed (see [section 4.2](#sect4.2)) in order to be able to see the keys and match them to the contents of the memory.

So, first I set the breakpoint (`bm ncrypt!SslExpandTrafficKeys`) and issued a TLS connection to our testbed. As we've already discussed in [section 5.3](#sect5.3), the fourth arg will be in the register `R9` and the fifth will be on stack at `RSP+0x28`. These are the adresses where the pointers to the newly-created keys will be written after the call finishes. Let's take a note before proceeding with the call:
```
0:005> r r9
r9=000001e0fe6b9a40
0:005> dp rsp+0x28 L1
00000047`9eafdc00  000001e0`fe6b9a48
```

Then I waited for the function to finish with `pt` and examined the memory at these addresses. Let's take address from R9 as an example. I dereferenced it to find the actual address of the newly-generated key and then examined the memory.
```
0:009> dp 000001e0fe6b9a40 L1
000001e0`fe6b9a40  000001e0`ff0ceae0
```
The key structure is as follows:
```
0:009> db 000001e0`ff0ceae0 L50
000001e0`ff0ceae0  20 00 00 00 42 44 44 44-00 00 00 00 01 00 00 00   ...BDDD........
000001e0`ff0ceaf0  40 cb 5d fe e0 01 00 00-20 e3 cb fd e0 01 00 00  @.]..... .......
000001e0`ff0ceb00  60 eb 0c ff e0 01 00 00-00 eb 0c ff e0 01 00 00  `...............
000001e0`ff0ceb10  00 00 00 00 00 00 00 80-00 00 00 80 e0 01 08 00  ................
000001e0`ff0ceb20  01 00 00 80 00 10 00 00-00 00 00 00 00 00 00 00  ................
```

So far so good, the `BDDD` magic tag is described in [\[1\]](#ref1) as an `NcryptSslKey` structure. As we already know, the pointer to the actual key is at offset 0x10. Lets follow it:
```
0:009> dp 000001e0`ff0ceae0+0x10 L1
000001e0`ff0ceaf0  000001e0`fe5dcb40
0:009> db 000001e0`fe5dcb40 L100
000001e0`fe5dcb40  70 00 00 00 33 6c 73 73-04 03 00 00 00 00 00 00  p...3lss........
000001e0`fe5dcb50  80 66 0c c4 f9 7f 00 00-00 00 00 00 00 00 00 00  .f..............
000001e0`fe5dcb60  80 29 6a fe e0 01 00 00-00 00 00 00 00 00 00 00  .)j.............
000001e0`fe5dcb70  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe5dcb80  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe5dcb90  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe5dcba0  00 00 00 00 00 00 00 00-00 00 00 00 04 00 00 00  ................
000001e0`fe5dcbb0  60 6d 77 fe e0 01 00 00-58 6a 79 01 00 00 00 00  `mw.....Xjy.....
000001e0`fe5dcbc0  00 00 00 00 00 00 00 00-2b 00 00 00 00 00 00 00  ........+.......
000001e0`fe5dcbd0  01 00 00 00 01 00 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe5dcbe0  e0 cb 5d fe e0 01 00 00-e0 cb 5d fe e0 01 00 00  ..].......].....
000001e0`fe5dcbf0  9c 8c 09 26 b8 54 99 0b-d7 54 41 ce 4a fa 64 90  ...&.T...TA.J.d.
000001e0`fe5dcc00  7c 76 07 60 97 2e a6 c5-94 5e 4c a7 c8 7e 6f 83  |v.`.....^L..~o.
000001e0`fe5dcc10  c0 a6 ea fe e0 01 00 00-00 00 00 00 00 00 08 00  ................
000001e0`fe5dcc20  80 e8 78 fe e0 01 00 00-0a 79 ed 01 00 00 00 00  ..x......y......
000001e0`fe5dcc30  00 00 00 00 00 00 00 00-2e 00 00 00 00 00 00 00  ................
```

Contrary to what we've seen before, the tag we see is `3lss`, not `5lss` as before. This tag is also mentioned in [\[1\]](#ref1) (page 70). The stucture definition from [\[1\]](#ref1) is as follows:
```c
typedef struct _SSL3_Struct {
  ULONG cbLength,// the count in bytes (cb), of the structure (usually 0x027C on x64)       -- offset 0
  ULONG dwMagic,// a dword (dw) of the ASCII value ’ssl3’ [stored as ’3lss’]                -- offset 0x4
  ULONG dwProtocol,// One of the CNG SSL Provider Protocol Identifier values (TLS Version)  -- offset 0x8
  ULONG dwCipherSuite,// numeric cipher suite identifier                                    -- offset 0xc
  ULONG dwUnknown1// boolean value -- read or write key?                                    -- offset 0x10
  ULONG cbSymmKey// this value observed to match the size value for MSSK                    -- offset 0x14
  ULONG cbHashLength,// the size of the ensuing hash, based on MAC algo                     -- offset 0x18
  UCHAR[48] HashData,// fixed field - if preceding length is not 48 bytes, then 0 padded    -- offset 0x1c -
  MSSK_Struct SymmKey// the associated MSSK Structure
}SSL3_Struct,*PSSL3_Struct;
```
In our case, though, we don't see the contain the MSSK Structure (denoted by KSSM tag) at the end. Also, in our case the `dwUnknown1` field is clearly not a boolean, `cbSymmKey` is 0x7ff9, which is larger than a typical structure size. This means that, most probably, for our case the definition from [\[1\]](#ref1)  does not apply. 
We can clearly see, though, that at offset 0x20 in  our `3lss` structure we have something resembling a pointer (`80 29 6a fe e0 01 00 00`), let's examine where it points:
```
0:009> dp 000001e0`fe5dcb40+0x20 L1
000001e0`fe5dcb60  000001e0`fe6a2980
0:009> db 000001e0`fe6a2980 L100
000001e0`fe6a2980  20 00 00 00 52 55 55 55-40 39 5a fe e0 01 00 00   ...RUUU@9Z.....
000001e0`fe6a2990  a0 29 6a fe e0 01 00 00-80 29 6a fe e0 01 00 00  .)j......)j.....
000001e0`fe6a29a0  80 02 00 00 59 4b 53 4d-07 00 06 00 80 01 00 00  ....YKSM........
000001e0`fe6a29b0  30 00 00 00 e0 01 00 00-a0 a5 54 ff e0 01 00 00  0.........T.....
000001e0`fe6a29c0  00 00 00 00 00 00 00 00-e0 09 4c fe e0 01 00 00  ..........L.....
000001e0`fe6a29d0  01 00 00 00 e0 01 00 00-80 a0 6f fe e0 01 00 00  ..........o.....
000001e0`fe6a29e0  0e 00 00 00 00 00 00 00-00 60 96 d7 f9 7f 00 00  .........`......
000001e0`fe6a29f0  64 36 3e 62 26 29 d5 a5-0c 48 7a 77 5e 88 2e 21  d6>b&)...Hzw^..!
000001e0`fe6a2a00  bb d0 60 b4 3f e7 41 26-0d ef c3 58 9f 00 ba 0a  ..`.?.A&...X....
000001e0`fe6a2a10  3c e2 4f a0 58 4a 33 cd-35 b9 a1 d9 9a ee 72 72  <.O.XJ3.5.....rr
000001e0`fe6a2a20  b4 1b 23 91 1f 44 18 ba-c2 f4 b8 d5 a5 fb d9 dd  ..#..D..........
000001e0`fe6a2a30  e4 06 2c c5 dd 73 96 61-86 57 dc b9 27 3e 67 0f  ..,..s.a.W..'>g.
000001e0`fe6a2a40  df 6d b8 aa 17 50 16 e2-4d e6 1c ea 37 0c 16 c7  .m...P..M...7...
000001e0`fe6a2a50  8d 7c 7d 19 3d f3 9f 7f-f5 d2 54 b4 00 a0 72 4c  .|}.=.....T...rL
000001e0`fe6a2a60  e1 2c 8d d1 d8 1b c0 41-5a a5 4f 1e a4 e0 31 8e  .,.....AZ.O...1.
000001e0`fe6a2a70  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

Interesting, we can see here two magic tags, RUUU (UUUR) and YKSM (MSKY). The first one is also mentioned in [\[1\]](#ref1) on page 58 and corresponds to a BCrypt key structure. MSKY along with UUUR is mentioned in mimikatz sources, with an enigmatic TODO ([\[42\]](#ref42)). 
Anyway, reading the mimikatz source reveals the following structure for a UUUR key:
```
typedef struct _KIWI_BCRYPT_HANDLE_KEY {
	ULONG size;
	ULONG tag;	// 'UUUR'
	PVOID hAlgorithm;
	PKIWI_BCRYPT_KEY key;
	PVOID unk0;
} KIWI_BCRYPT_HANDLE_KEY, *PKIWI_BCRYPT_HANDLE_KEY;
```

It seems that once again, our princess is in another castle and we'll need to again follow some pointers (this time - at offset 0x10):
```
0:009> dp 000001e0`fe6a2980+0x10 L1
000001e0`fe6a2990  000001e0`fe6a29a0
0:009> db  000001e0`fe6a29a0 L100
000001e0`fe6a29a0  80 02 00 00 59 4b 53 4d-07 00 06 00 80 01 00 00  ....YKSM........
000001e0`fe6a29b0  30 00 00 00 e0 01 00 00-a0 a5 54 ff e0 01 00 00  0.........T.....
000001e0`fe6a29c0  00 00 00 00 00 00 00 00-e0 09 4c fe e0 01 00 00  ..........L.....
000001e0`fe6a29d0  01 00 00 00 e0 01 00 00-80 a0 6f fe e0 01 00 00  ..........o.....
000001e0`fe6a29e0  0e 00 00 00 00 00 00 00-00 60 96 d7 f9 7f 00 00  .........`......
000001e0`fe6a29f0  64 36 3e 62 26 29 d5 a5-0c 48 7a 77 5e 88 2e 21  d6>b&)...Hzw^..!
000001e0`fe6a2a00  bb d0 60 b4 3f e7 41 26-0d ef c3 58 9f 00 ba 0a  ..`.?.A&...X....
000001e0`fe6a2a10  3c e2 4f a0 58 4a 33 cd-35 b9 a1 d9 9a ee 72 72  <.O.XJ3.5.....rr
000001e0`fe6a2a20  b4 1b 23 91 1f 44 18 ba-c2 f4 b8 d5 a5 fb d9 dd  ..#..D..........
000001e0`fe6a2a30  e4 06 2c c5 dd 73 96 61-86 57 dc b9 27 3e 67 0f  ..,..s.a.W..'>g.
000001e0`fe6a2a40  df 6d b8 aa 17 50 16 e2-4d e6 1c ea 37 0c 16 c7  .m...P..M...7...
000001e0`fe6a2a50  8d 7c 7d 19 3d f3 9f 7f-f5 d2 54 b4 00 a0 72 4c  .|}.=.....T...rL
000001e0`fe6a2a60  e1 2c 8d d1 d8 1b c0 41-5a a5 4f 1e a4 e0 31 8e  .,.....AZ.O...1.
000001e0`fe6a2a70  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe6a2a80  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe6a2a90  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
```

No surprises here - it just points to that enigmatic structure with YKSM tag. As I've already done for 3lss, I tried to look at some of the pointers we have here at offsets 0x18, 0x28, 0x38. 
But before doing that I first examined the log.txt from our openssl server to understand what values we are searching. 
We are now at the first invokation of `SslExpandTrafficKeys`, so we are dealing with handshake traffic secrets. The relevant parts of the keylog are as follows:
```
SERVER_HANDSHAKE_TRAFFIC_SECRET d382<SNIP>0d41 3d07<SNIP>eafe
CLIENT_HANDSHAKE_TRAFFIC_SECRET d382<SNIP>0d41 3b2a<SNIP>ced6
```
Now let's examine those pointers that the `YKSM` structure contains:
```
0:009> dp 000001e0`fe6a29a0+0x18 L1
000001e0`fe6a29b8  000001e0`ff54a5a0
0:009> db 000001e0`ff54a5a0 L50
000001e0`ff54a5a0  3b 2a 9a e9 c5 b7 fc 54-52 9c c0 dc ae b6 3a 30  ;*.....TR.....:0
000001e0`ff54a5b0  62 bf 30 23 c3 f8 7c 85-7e 61 68 85 bf 33 71 f5  b.0#..|.~ah..3q.
000001e0`ff54a5c0  21 ab ea cf c8 55 9a 26-70 9c 66 e7 51 88 ce d6  !....U.&p.f.Q...
000001e0`ff54a5d0  b0 a1 00 00 e0 01 00 00-40 fd 0c ff e0 01 00 00  ........@.......
000001e0`ff54a5e0  14 00 00 00 00 00 00 00-c0 9d 54 ff e0 01 00 00  ..........T.....
0:009> dp 000001e0`fe6a29a0+0x28 L1
000001e0`fe6a29c8  000001e0`fe4c09e0
0:009> db 000001e0`fe4c09e0 L50
000001e0`fe4c09e0  14 00 00 00 4c 41 53 4d-07 00 06 00 80 02 00 00  ....LASM........
000001e0`fe4c09f0  00 00 00 00 00 00 00 00-ff ff ff ff 00 00 0c 00  ................
000001e0`fe4c0a00  01 00 00 80 00 10 00 00-00 00 00 00 00 00 00 00  ................
000001e0`fe4c0a10  00 00 00 00 e0 01 00 00-00 00 00 00 00 00 0c 00  ................
000001e0`fe4c0a20  61 7a 37 30 30 36 33 32-2e 76 6f 2e 6d 73 65 63  az700632.vo.msec
0:009> dp 000001e0`fe6a29a0+0x38 L1
000001e0`fe6a29d8  000001e0`fe6fa080
0:009> db 000001e0`fe6fa080 L50
000001e0`fe6fa080  53 00 48 00 41 00 33 00-38 00 34 00 00 00 02 00  S.H.A.3.8.4.....
000001e0`fe6fa090  1d 00 17 00 18 00 00 00-00 00 5f fe e0 01 06 00  .........._.....
000001e0`fe6fa0a0  53 00 48 00 41 00 33 00-38 00 34 00 00 00 02 00  S.H.A.3.8.4.....
000001e0`fe6fa0b0  53 00 48 00 41 00 33 00-38 00 34 00 00 00 02 00  S.H.A.3.8.4.....
000001e0`fe6fa0c0  53 00 48 00 41 00 33 00-38 00 34 00 00 00 02 00  S.H.A.3.8.4.....
```

Pointers at 0x28 and 0x38 did not get us any results (though the LASM/MSAL tag probably also corresponds to some interesting structure), but at offset 0x18 we have successfully found the CLIENT_HANDSHAKE_TRAFFIC_SECRET (`3b 2a ... ce d6`)! 

The frida snippet to do the same pointer-following as we did is as follows:

```javascript
var get_secret_from_BDDD = function(struct_BDDD){
	var struct_3lss = struct_BDDD.add(0x10).readPointer();
	var struct_RUUU = struct_3lss.add(0x20).readPointer();
	var struct_YKSM = struct_RUUU.add(0x10).readPointer();
	var secret_ptr = struct_YKSM.add(0x18).readPointer();
	return secret_ptr.readByteArray(48);
}
```

Hooray, we now have a way to extract the secrets for TLS1.3! The only thing that is left is to tie them to a session via a client random.

Let's remember [section 5.6](#sect5.6) where we've dealt with session hashes for TLS1.2. While in TLS1.2 calculating the session hash was an optional extension, in TLS1.3 it is actually embedded in the protocol, see page 90 of [\[34\]](#ref34):
```
Derive-Secret(Secret, Label, Messages) =
  HKDF-Expand-Label(Secret, Label,
    Transcript-Hash(Messages), Hash.length)
```

This `Derive-Secret` is the function that is used to get the traffic secrets, among others. This all means that by the time our `ncrypt!SslExpandTrafficKeys` is called, the session hash was already calculated! Testing shows that the same `SslHashHandshake` from [section 5.6](#sect5.6)  is used, so we can reuse our approach of parsing ClientHello passed to it as an argument.

All that is left is to take into account that we have two succeeding calls to `SslExpandTrafficKeys`, first for handshake keys and the second - for application keys. The final part of the hook for TLS1.3 is as follows:
```javascript

var stages = {};
Interceptor.attach(Module.getExportByName('ncrypt.dll', 'SslExpandTrafficKeys'), {
    onEnter: function (args) {
		this.retkey1 = ptr(args[3]);
		this.retkey2 = ptr(args[4]);
		this.client_random = client_randoms[this.threadId] || "???";
		if(stages[this.threadId]){ // We are at the second call
			stages[this.threadId] = null;			
			this.suffix = "TRAFFIC_SECRET_0";
		}else{ // We are at the first call
			stages[this.threadId] = "handshake";
			this.suffix = "HANDSHAKE_TRAFFIC_SECRET";
		}
	},
	onLeave: function (retval) {
		var key1 = get_secret_from_BDDD(this.retkey1.readPointer());
		var key2 = get_secret_from_BDDD(this.retkey2.readPointer());
		keylog("CLIENT_" + this.suffix + " " + this.client_random + " " + buf2hex(key1));
		keylog("SERVER_" + this.suffix + " " + this.client_random + " " + buf2hex(key2));
    }
});

```

## <a href="#sect7" id="sect7">7</a> Putting it all together 

We will use the frida.exe tool that is installed as a part of frida python package - you first install Python3, then go to python home and use `.\Scripts\pip.exe install frida-tools frida` to install it. After that the frida.exe will be inside .\Scripts dir, in my case - C:\Python3\Scripts\frida.exe.

The ready-to-use frida js script is located in [win-frida-scripts repository](https://github.com/ngo/win-frida-scripts/blob/master/lsasslkeylog-easy/keylog.js), it can be ran as follows (from an admin prompt):

```
PS > frida.exe --no-pause lsass.exe -l \path\to\keylog.js
```

The script will dump keys to `C:\keylog.log`. In order to make Wireshark use this keylog file, we'll need to set the `(Pre)-Master-Secret log filename` in `Edit->Preferences->Protocols->TLS`. Wireshark will be able to decrypt new sessions right on the go, reading the keys as they are printed to the keylog file.

As a recap, for TLS1.2 the script hooks three `ncrypt.dll` functions - `SslGenerateMasterKey` and `SslImportMasterKey` to get the key itself and `SslHashHandshake` to get the client random from the hahshake hashing process if extended master secret extension is in use. To correlate `SslHashHandshake` calls to `Ssl{Generate,Import}MasterKey` it uses the thread Id, assuming that between `SslHashHandshake`  and `Ssl{Generate,Import}MasterKey` for a given tls connection  in a certain thread no other connection will be processed (which is a reasonable assumption, given that all this processing is done in an single ALPC message handler).

For TLS1.3 the script additionally hooks `SslExpandTrafficKeys` (and `SslExpandExporterMasterKey`, for that matter. I'm not sure if it is currently used in any way by wireshark, but openssl's keylog function does print it to a keylog, and so did I).

The script is tested on Win10 1909 and 2004, but should also work on other x64 Windows verions. 

## <a href="#sect8" id="sect8">8</a> References

<a id="ref1">[1]</a> Jacob M. Kambic. Cunning With CNG: Soliciting Secrets from Schannel - [Whitepaper from DEFCON 24](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Jkambic-Cunning-With-Cng-Soliciting-Secrets-From-Schannel-WP.pdf), [Slides from BlackHat USA 2016](https://www.blackhat.com/docs/us-16/materials/us-16-Kambic-Cunning-With-CNG-Soliciting-Secrets-From-SChannel.pdf), ["Extracting CNG TLS/SSL artifacts from LSASS memory" by Jacob M. Kambic](https://docs.lib.purdue.edu/open_access_theses/782/) 

<a id="ref2">[2]</a>  MDN: [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)

<a id="ref3">[3]</a> OpenSSL man page: [SSL_CTX_set_keylog_callback](https://www.openssl.org/docs/man1.1.1/man3/SSL_CTX_set_keylog_callback.html)

<a id="ref4">[4]</a> Wireshark source code: [SSLKEYLOG parsing, wireshark/packet-tls-utils.c](https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-tls-utils.c#L5355) 

<a id="ref5">[5]</a> Microsoft Docs: [Key Storage and Retrieval](https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval) 

<a id="ref6">[6]</a> Microsoft Docs: [Cryptography API: Next Generation](https://docs.microsoft.com/en-us/windows/win32/seccng/cng-portal)

<a id="ref7">[7]</a> StackExchange: [Decryping TLS packets between Windows 8 apps and Azure](https://reverseengineering.stackexchange.com/a/213) 

<a id="ref8">[8]</a> StackExchange: [Is it possible to decrypt an SSL connection (short of bruteforcing)?](https://reverseengineering.stackexchange.com/a/2695) 

<a id="ref9">[9]</a> Choi, H., & Lee, H. (2016) [Extraction of TLS master secret key in windows. 2016 International Conference on Information and Communication Technology Convergence (ICTC)](https://ieeexplore.ieee.org/document/7763558). The paper is available on sci-hub if you search for its DOI.

<a id="ref10">[10]</a> Microsoft TechNet Forums: [Obtaining SSLKEYLOGFILE-like data from Edge et al (Schannel clients)](https://social.technet.microsoft.com/Forums/en-US/4041d78a-21bb-44fd-9a96-6579ea8129d1/obtaining-sslkeylogfilelike-data-from-edge-et-al-schannel-clients) 

<a id="ref11">[11]</a> GitHub - NytroRST/NetRipper: [Smart traffic sniffing for penetration testers](https://github.com/NytroRST/NetRipper)

<a id="ref12">[12]</a> Filippo Valsorda: [We need to talk about Session Tickets](https://blog.filippo.io/we-need-to-talk-about-session-tickets/) 

<a id="ref13">[13]</a> Microsoft Docs: [SslGenerateMasterKey function (Sslprovider.h)](https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratemasterkey)

<a id="ref14">[14]</a> Microsoft Docs: [Header Annotations](https://docs.microsoft.com/en-us/windows/win32/winprog/header-annotations)

<a id="ref15">[15]</a> GitHub - droe/sslsplit: [Transparent SSL/TLS interception](https://github.com/droe/sslsplit)

<a id="ref16">[16]</a> Microsoft Docs: [x64 software conventions](https://docs.microsoft.com/en-us/cpp/build/x64-software-conventions)

<a id="ref17">[17]</a> MS .NET Reference Source: [NCryptBuffer structure](https://referencesource.microsoft.com/#system.core/System/Security/Cryptography/NCryptNative.cs,258b810a8a142eb5,references)

<a id="ref18">[18]</a> Windows SDK: [NCRYPTBUFFER_SSL_* constans in ncrypt.h](http://www.gaclib.net/CodeIndexDemo/Gaclib/ncrypt.h.html)

<a id="ref19">[19]</a> The blog of a gypsy engineer: [How does TLS 1.3 protect against downgrade attacks?](https://blog.gypsyengineer.com/en/security/how-does-tls-1-3-protect-against-downgrade-attacks.html) 

<a id="ref20">[20]</a> RFC 5246: [The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246.html) 

<a id="ref21">[21]</a> Frida: [A world-class dynamic instrumentation framework](https://frida.re/)

<a id="ref22">[22]</a> Microsoft Docs: [x64 stack usage](https://docs.microsoft.com/en-us/cpp/build/stack-usage?view=vs-2019) 

<a id="ref23">[23]</a> Microsoft Docs: [Secure Channel](https://docs.microsoft.com/en-us/windows/win32/secauthn/secure-channel)

<a id="ref24">[24]</a> Microsoft Docs: [SSP Packages Provided by Microsoft](https://docs.microsoft.com/en-us/windows/win32/secauthn/ssp-packages-provided-by-microsoft)

<a id="ref25">[25]</a> Wikipedia: [Forward Secrecy](https://en.wikipedia.org/wiki/Forward_secrecy)

<a id="ref26">[26]</a> Microsoft Docs: [SslImportMasterKey function (Sslprovider.h)](https://docs.microsoft.com/en-us/windows/win32/seccng/sslimportmasterkey)

<a id="ref27">[27]</a> RFC 7627: [Transport Layer Security (TLS) Session Hash and Extended Master Secret Extension](https://tools.ietf.org/html/rfc7627)

<a id="ref28">[28]</a> Microsoft Docs: [SslHashHandshake function (Sslprovider.h)](https://docs.microsoft.com/en-us/windows/win32/seccng/sslhashhandshake)

<a id="ref30">[30]</a> Microsoft: [News on TLS1.3 experimental support in Windows 10](https://docs.microsoft.com/en-us/windows/whats-new/whats-new-windows-10-version-1909#transport-layer-security-tls)

<a id="ref31">[31]</a> GitHub - microsoft/msquic: [Testing instructions](https://github.com/microsoft/msquic/blob/master/docs/TEST.md) 

<a id="ref32">[32]</a> IETF draft: [Using TLS to Secure QUIC](https://tools.ietf.org/html/draft-ietf-quic-tls) 

<a id="ref33">[33]</a> GitHub - microsoft/msquic: [SCHANNEL TLS Implementation for QUIC](https://github.com/microsoft/msquic/blob/master/src/platform/tls_schannel.c)

<a id="ref34">[34]</a> RFC 8446: [The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446) 

<a id="ref35">[35]</a> GitHub - dotnet/runtime: [TLS1.3 does not work on Windows · Issue #1720](https://github.com/dotnet/runtime/issues/1720) 

<a id="ref36">[36]</a> Naughter blog: [SSLWrappers + TLS v1.3 support](https://naughter.wordpress.com/2019/05/23/tls-v1-3-support-finally-on-windows/)

<a id="ref37">[37]</a> Microsoft Docs: [InitializeSecurityContextW function (sspi.h)](https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-initializesecuritycontextw)

<a id="ref38">[38]</a> Windows SDK: [SEC_TRAFFIC_SECRETS definition in ntifs.h](https://www.codemachine.com/downloads/win10.1903/ntifs.h)

<a id="ref39">[39]</a> Windows SDK: [SECBUFFER_TRAFFIC_SECRETS definition in sspi.h](https://github.com/susahom/YC/blob/d00467cf2682143e216acf29d4e7b1c350c319ec/Windows%20Kits/10/Include/10.0.18362.0/shared/sspi.h#L375)

<a id="ref40">[40]</a> RFC 5705: [Keying Material Exporters for Transport Layer Security (TLS)](https://tools.ietf.org/html/rfc5705) 

<a id="ref41">[41]</a> Peter Wu: [sslkeylog.c for keylogging apps that use OpenSSL](https://git.lekensteyn.nl/peter/wireshark-notes/tree/src)

<a id="ref42">[42]</a> GitHub - gentilkiwi/mimikatz: [kuhl_m_crypto_extractor.c - a TODO line which mentions MSKY magic tag](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/crypto/kuhl_m_crypto_extractor.c#L419)) 

