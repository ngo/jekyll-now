---
layout: post
title: SSLKEYLOGFILE-like functionality for schannel secrets
---

For some protocol reversing I've lately been needing a way to extract TLS secrets for traffic decryption. For openssl-based software there exists a `SSLKEYLOGFILE` env var as well as a way to `LD_PRELOAD` a special wrapper. For schannel - no such luck.

I've thrown together a frida script that is able to generate `SSLKEYLOG`-compatible file for wireshark for some of TLS connections that use SChannel.

## Preparation

1. You'll need admin privilege in order to utilize this method.
2. Make sure that the memory of lsass.exe is accessible to th admin user. The easiest way is to open Task Manager, find lsass.exe in details and try to make a dump of the process. If this is successful, you can proceed.
3. Although it is possible to run this from a single machine, it is more convenient to utilize two: one with frida-server, the other - with frida itself (acts as a client).
4. [On windows machine] Download and unpack frida-server executable from [Frida releases](https://github.com/frida/frida/releases)
5. [On windows machine] Run `frida-server.exe -l 0.0.0.0`
6. [On the frida machine] Install python3, get  [win-frida-scripts](https://github.com/ngo/win-frida-scripts/), install [prerequisites](https://github.com/ngo/win-frida-scripts/tree/master/lsass-sslkeylog#requirements).
7. [On the frida machine] [Run lsasslkeylog](https://github.com/ngo/win-frida-scripts/tree/master/lsass-sslkeylog#running)


## Decrypting traffic

1. Launch wireshark
2. Go to `Edit->Preferences->Protocols->TLS`
3. Set `(Pre)-Master-Secret log filename` to `C:\keylog.log` 
4. Make sure that frida is still running
5. Enable traffic capture
6. Enjoy some traffic decryption


## Tested OS versions

1. Win 10 Pro (`10.0.18363`)
2. Windows Server 2012 R2 Standard (`6.3.9600`)
3. Windows Server 2008 R2 Enterprise (`6.1.7601`)

## Tested use-cases

1. RDP client traffic (`mstsc.exe`)
2. Powershell's `Invoke-WebRequest`
3. MS Edge and IE

## Known problems

1. 64-bit windows only
2. Resumed TLS sessions will not be decrypted, if the initial full handshake wasn't captured. This is because we hook key creation, and on resumptions keys are not created again.
3. Tested to work with TLS1.2, will not work for anything above or below (yet).
4. will crash your lsass if you supply wrong pdb or wrong schannel.dll.

## Feedback

* `webpentest` on twitter and on gmail.
