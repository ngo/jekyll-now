---
layout: post
title: SSLKEYLOGFILE-like functionality for schannel secrets
---

For some protocol reversing I've lately been needing a way to extract TLS secrets for traffic decryption. For openssl-based software there exists a `SSLKEYLOGFILE` env var as well as a way to `LD_PRELOAD` a special wrapper. For schannel - no such luck.

I've thrown together a frida script that is able to generate `SSLKEYLOG`-compatible file for wireshark for some of TLS connections that use SChannel.

## Preparation

1. You'll need admin privilege in order to utilize this method.
2. Make sure that the memory of lsass.exe is accessible to th admin user. The easiest way is to open Task Manager, find lsass.exe in details and try to make a dump of the process. If this is successful, you can proceed.
3. Download and install python3 for windows. The python install direcroty will be referred to as `PYTHONDIR`.
4. Open powershell as admin, cd to `PYTHONDIR/Scripts`
5. run `.\pip.exe install frida-tools`
6. Copy `lsass-sslkeylog.js` from [win-frida-scripts](https://github.com/ngo/win-frida-scripts/) to a file somewhere, for example `C:\tools\lsass-sslkeylog.js`.


## Running frida

1. Open powershell as administrator, go to `PYTHONDIR/Scripts`
2. run `.\frida.exe lsass.exe --no-pause -l C:\path\to\lsass-sslkeylog.js`
3. The keylog file will be created as `C:\keylog.log`


## Decrypting traffic

1. Launch wireshark
2. Go to `Edit->Preferences->Protocols->TLS`
3. Set `(Pre)-Master-Secret log filename` to `C:\keylog.log`
4. Make sure that frida is still running
5. Enable traffic capture
6. Enjoy some traffic decryption


## Cases known to work 

NB: all tests were performed on Win10 1909. Everything else is yet untested. 

1. RDP client traffic (`mstsc.exe`)
2. Powershell's `Invoke-WebRequest`
3. In some cases - traffic from MS Edge.

## Known problems

1. Resumed TLS sessions will not be decrypted, especially if the initial full handshake wasn't captured.
2. The frida script gets the master secret and the client random from different calls and the tries to match them based on thread ID. This works poorly when there are lots of concurrent SSL connections happening.
3. The code that searches for client random values is quite fragile and won't work in all cases, the getting of master keys - less so. For cases where the script cannot get the client random, it'll output `CLIENT_RANDOM ??? <master-key>` to the logfile. You can then try to manually enter the client random (they can be found in traffic in ClientHello messages).
4. Tested to work with TLS1.2, will not work for anything above or below (yet).

## Feedback

* `webpentest` on twitter and on gmail.
