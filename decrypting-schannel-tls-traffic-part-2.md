---
layout: page
title: Decrypting Schannel TLS traffic. Part 2. Session resumption
permalink: /decrypting-schannel-tls-part-2/
---

## TL;DR

This is the second part of my schannel research. I recommend at least skimming through [part 1](/decrypting-schannel-tls-part-1/) before reading this one, because it contains a lot of important context that is omitted in part 2.

This part is about dealing with session resumption. I've also redone some of the experiments from Jacob Cambic's research [\[3\]](#ref3) to discover if something has changed from the time it was written.

The key takeaways are as follows:

 - For TLS1.2 schannel does session resumption both with session IDs and tickets;
 - Resumption for TLS1.2 is only performed when extended master secret extension is in use;
 - Methods and results from Jacob Cambic's research still largely apply, but some of the offsets have since changed;
 - Researching resumption helped identify an easier target for hooking the works both for resumed and non-resumed TLS1.2 sessions and does not have problems with session hashing, namely `SslGenerateSessionKeys`; 
 - The [tool for exporting the keys ](https://github.com/sldlb/win-frida-scripts/tree/master/lsasslkeylog-easy) was update with this new extraction method;
 - My experiments show that for TLS1.3 session resumption is **not** currently supported by Schannel. I would love to be proven wrong, though.

As previously, this work is part of my R&D activities at [SolidLab LLC](https://solidlab.ru) and was fully funded by the company. I'm grateful to be able to do reseach as part of my job. We do offensive security, web application analysis and SDL consunting. We also develop [a WAF](https://solidwall.io/).

## Table of contents

* TOC
{:toc}

## 1. TLS1.2 Session resumption

### 1.1 Testbed for session resumption

In order to test if the client implementation will cache tls session either via saving session IDs or with session tickets, I used a sample RFC5077 server [\[1\]](#ref1). After compilation, running the server creates 4 endpoints with different settings:

```command
% ./rfc5077-server 1443 2443 3443 4443
[✔] Check arguments.
[✔] Initialize OpenSSL.
[✔] Setup libev.
[✔] Setup server listening on 1443 without cache and without tickets.
[✔] Setup server listening on 2443 with cache and without tickets.
[✔] Setup server listening on 3443 with cache and with tickets.
[✔] Setup server listening on 4443 without cache and with tickets.
```

I can then open Wireshark, issue a couple of requests and examine the ClientHello message.

On successful session ID resumption the ClientHello will contain non-empty Session Id:

```
Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 191
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 187
            Version: TLS 1.2 (0x0303)
            Random: 5ef20d2c434688f2df6703763c7b8cf066e2ce62f0b0ea20…
            Session ID Length: 32 // <--- non-zero session id
            Session ID: 58f138f0948fdf4ccd16451940f5b53315e0afe5ceee36e2…
 ...
```
On successful session ticket resumption, the ClientHello will contain session_ticket extension with non-zero length:

```
Frame 2930: 378 bytes on wire (3024 bits), 378 bytes captured (3024 bits) on interface wlan0, id 0
Ethernet II, Src: PcsCompu_f2:86:82 (08:00:27:f2:86:82), Dst: IntelCor_98:b0:66 (3c:6a:a7:98:b0:66)
Internet Protocol Version 4, Src: 192.168.88.166, Dst: 192.168.88.186
Transmission Control Protocol, Src Port: 52666, Dst Port: 3443, Seq: 1, Ack: 1, Len: 324
Transport Layer Security
    TLSv1.2 Record Layer: Handshake Protocol: Client Hello
        Content Type: Handshake (22)
        Version: TLS 1.2 (0x0303)
        Length: 319
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 315
            Version: TLS 1.2 (0x0303)
            Random: 5ef20d33043e581bc1b47fbf443a1eb8d8ebece565b74197…
            Session ID Length: 0
            Cipher Suites Length: 52
            Cipher Suites (26 suites)
            Compression Methods Length: 1
            Compression Methods (1 method)
            Extensions Length: 222
            <SNIP>
            Extension: session_ticket (len=160)
                Type: session_ticket (35)
                Length: 160                         // <--- non-zero here
                Data (160 bytes)                    // <--- non-empty here
```

### 1.2 Schannel, session resumption and Extended Master Secret TLS extension

While testing my Win10 for session resumption, I was very surprised to find that the sessions were never resumed! I even had a hypothesis that MS broke session resumption in W10 2004. But then I tried it on another machine and saw that the sessions were resumed there, even after I updated it to 2004. Diffing schannel settings in the registry revealed that on the non-resuming machine I had `DisableClientExtendedMasterSecret` setting set to 0x1. This setting disables the Extended Master Secret TLS extension which we've already discussed in [section 5.6 of part 1](/decrypting-schannel-tls-part-1/#56-dealing-with-tls-session-hashes) of the article. 

So as it turned out, starting from October 2019, MS requires EMS extension to be used for any resumed session ([\[2\]](#ref2)) because of the  CVE-2019-1318 vulnerability.  After deleting the key and rebooting I've got session resumption to work.

### 1.3 Rechecking the CSessionCacheItem-based approach

Testing our keylogging script from Part 1 shows that for resumed sessions neither `SslGenerateMasterKey` nor `SslImportMasterKey` (the two functions we hooked to extract the master key) are called. Fortunately, if the original session was performed while the script was already running, the original master secret was already keylogged, and Wireshark is smart enough to detect session resumption by both Session ID and session tickets automatically will use the older key already present in the keylog. We would also like, though, to get the keys even if we didn't capture the original non-resumed handshake.

The keys for the resumed sessions are persisted in the special cache, which is the basis for methods used by Jacob Cambic ([\[3\]](#ref3)). The rest of the section is a recheck of the methods to get the keys from the cache presented in [\[3\]](#ref3) on pages 77-80. If you are not interested in details, you can jump straight to [TL;DR](#14-csessioncacheitem-based-approach-tldr).

Let's start with searching for NCryptSslkey objects by BDDD tags and resolving pointers to keys at offset 0x10 (script taken from page 78 of [\[3\]](#ref3)). The windbg script reformatted for clarity is as follows:
```
.foreach(
    nKey {
      s -[1w]a 0 L?800000000000 BDDD
    }
){
  db poi(${nKey}-4+10) L10;
}
```
Result:
```
0:012> .foreach(nKey {s -[1w]a 0 L?800000000000 BDDD}){db poi(${nKey}-4+10) L10;}
00000285`433b5510  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`433b4f70  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`4339bc30  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`432eabe0  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`432ea960  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`432ea8c0  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`432eab90  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`432eaa50  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........
00000285`4339bd70  50 00 00 00 35 6c 73 73-03 03 00 00 00 00 00 00  P...5lss........

```

So far so good, we can see many keys present in memory. Let's move on to the next step. The paper [\[3\]](#ref3) says:
```
Values heuristically matching the session ID pattern were spotted
reliable at 0x70 bytes below one pointer to every NcryptSslKey 
that pointed to a master key.
```

The authors propose the following script, the if-check relates to the peculiarity that exists in session ids generated by schannel:
```
 .foreach(
    sslSess {
        .foreach (
            BDDDPoi {
              .foreach(
                  ssl5Key {
                      s -[1w]d 0x0 L?800000000000 'ssl5'
                  }
              ){
                s-[1]q 0x0 L?800000000000 ${ssl5Key}-4;
              }
            }
        ){
          s -[1]q 0x0 L?80000000000 ${BDDDPoi}-10
        }
    }
){
  .if (dwo(${sslSess}+78) < 0x00010000 & dwo(${sslSess}+78) >= 0x00000101){
      db ${sslSess}+78 L20;.echo ***
  }
}
```

This tripple-foreach have proved to be really time-consuming (as it turned out later, this was because of the \[1\] search modifier instead of \[1w\]), and, after waiting 30 minutes, I decided to perform a manual check for a couple of keys.

I got the following ssl5Key pointer as an example: `000002854339bd70`. Did a search for pointers that point to it with `s -[1]q 0x0 L?800000000000 000002854339bd70`, but this also was really long to finish, so I decided to do a search in writable memory only (`-[1w] instead `-[1]` - not sure why original authors chose to use full scan here, perhaps a typo?):
```
0:012> s -[1w]q 0x0 L?800000000000 000002854339bd70;
0x00000285`432d5ff0
```
This reveals a BDDD structure, as expected:
```
0:012> db 0x00000285`432d5ff0-10 L20
00000285`432d5fe0  20 00 00 00 42 44 44 44-00 00 00 00 01 00 00 00   ...BDDD........
00000285`432d5ff0  70 bd 39 43 85 02 00 00-e0 66 cb 42 85 02 00 00  p.9C.....f.B....
```

Now we search for the pointers to this structure:
```
0:012> s -[1w]q 0x0 L?800000000000 00000285`432d5ff0-10
0x00000285`433a8dd0
```

and now we try offset 0x70 below the pointer (which is 0x78, including the size of the pointer itself), as recommended by the paper:
```
0:012> db 0x00000285`433a8dd0+78 L20
00000285`433a8e48  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000285`433a8e58  00 00 00 00 00 00 00 00-20 ee 2a 43 85 02 00 00  ........ .*C....
```

This does not look like a session ID at all. When trying the orignal WinDBG script, but in all cases searching only the writable mem and without that condition in the end that checks for session ids, none of the results  looks anything like a session id:
```
0:012> .foreach(sslSess {.foreach (BDDDPoi {.foreach(ssl5Key {s -[1w]d 0x0 L?800000000000 'ssl5'}){s -[1w]q 0x0 L?800000000000 ${ssl5Key}-4;}}){s -[1w]q 0x0 L?80000000000 ${BDDDPoi}-10}}){db ${sslSess}+78 L20;.echo ***}
00000149`fc2f9428  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fc2f9438  00 00 00 00 00 00 00 00-40 51 2a fc 49 01 00 00  ........@Q*.I...
***
00000149`fc2f9788  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fc2f9798  00 00 00 00 00 00 00 00-b0 b4 29 fc 49 01 00 00  ..........).I...
***
00000149`fbca82a8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fbca82b8  00 00 00 00 00 00 00 00-f0 fc cf fb 49 01 00 00  ............I...
***
00000149`fc2f9c98  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fc2f9ca8  00 00 00 00 00 00 00 00-40 4e 2a fc 49 01 00 00  ........@N*.I...
<...>
```


Looking around these pointers a little bit more revealed the following:
1. The assumption the author used here for filtering out the session ids (namely, `two sets of zeros in the third and fourth position`) is only suitable when the **server-side** of the connection is windows-based. That's because, at least for sessions that are resumed by session IDs, the **server** is in control of the session that later gets reused. So, when a windows client connects to e.g. openssl-based server, the session id won't have these zeroes. This is not that significant, though, because later, when describing the volatility and rekall plugins made, the author is not using this assumption to filter out session ids.
2. For my version of windows 10, the correct offset from the pointer to the pointer to BDDD was not 0x70 but 0xc8

Repeating the memory search with new offsets yields the following:
```
0:007> .foreach(sslSess {.foreach (BDDDPoi {.foreach(ssl5Key {s -[1w]d 0x0 L?800000000000 'ssl5'}){s -[1w]q 0x0 L?800000000000 ${ssl5Key}-4;}}){s -[1w]q 0x0 L?80000000000 ${BDDDPoi}-10}}){db ${sslSess}+0xc8 L20;.echo ***}
00000149`fc2f97d8  9f 1a 00 00 f5 d4 76 39-96 cb c8 ab 9d 43 bc 1f  ......v9.....C..
00000149`fc2f97e8  96 22 00 9d 31 6a d5 64-fd 7e 56 92 1c 56 15 b6  ."..1j.d.~V..V..
***
00000149`fc2f9628  41 1b 00 00 6a bf 72 32-5e 47 0c 75 1d 2d dc 0b  A...j.r2^G.u.-..
00000149`fc2f9638  b4 be 4d 9e 43 1c ca 8c-4f 06 75 3d 4e 27 78 6f  ..M.C...O.u=N'xo
***
00000149`fc20ace8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fc20acf8  00 00 00 00 00 00 00 00-a0 b8 20 fc 49 01 00 00  .......... .I...
***
00000149`fc2f92c8  d1 1d 00 00 10 df 8b 6a-c4 cd 37 f6 eb 58 19 b9  .......j..7..X..
00000149`fc2f92d8  11 0e e7 c5 53 cb b0 a4-3b b3 d0 84 79 19 24 77  ....S...;...y.$w
***
00000149`fbcd44d0  d0 44 cd fb 49 01 00 00-d0 44 cd fb 49 01 00 00  .D..I....D..I...
00000149`fbcd44e0  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
***
00000149`fc3b91f8  4d 01 00 00 54 d4 69 97-0f fc 58 b3 10 a3 00 b7  M...T.i...X.....
00000149`fc3b9208  1c 75 5e 67 59 5e 3c 46-66 cf 78 c1 a8 27 c6 64  .u^gY^<Ff.x..'.d
***
00000149`fc212640  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fc212650  00 00 00 00 0a 00 00 00-00 00 00 00 00 00 00 00  ................
***
00000149`fc2139d8  00 00 00 00 00 00 00 00-c8 39 21 fc 49 01 00 00  .........9!.I...
00000149`fc2139e8  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
***
00000149`fc3b93a8  97 ed 90 d3 fb 52 e3 1b-f4 33 17 92 47 1c 90 62  .....R...3..G..b
00000149`fc3b93b8  de d8 5b 2e 67 9b 0b e4-bd 10 f0 52 b3 e3 ba 4e  ..[.g......R...N
***
00000149`fc3b8628  d4 3c 00 00 f7 3b 58 13-76 42 86 9e d5 5c 4e 01  .<...;X.vB...\N.
00000149`fc3b8638  c1 6d 19 9c 8a 3f 7b 01-bd 7a 2c e9 98 31 00 dd  .m...?{..z,..1..
***
00000149`fc3b9a68  87 26 00 00 96 6d a2 16-24 a5 d8 c4 7a 3c 67 ec  .&...m..$...z<g.
00000149`fc3b9a78  09 f3 23 d0 a9 f2 45 d9-8d 4f d2 87 e9 1d c7 44  ..#...E..O.....D
***
```

Out of the memory above, first two seem like schannel-generated session ids, the 4th,6th,9-11th seem like openssl session ids, and the rest are false positives. I could also find session ID of my test connection among them.

Moving on,  the authors also propose scanning for references to `CSessionCache{Server,Client}Item::'vftable'` to get all of the session cache items and then just dereference a pointer to get the key. Let's also check this approach. The windbg script authors propose is as follows (reformatted for brevity, note that awkward syntax around vftable - backtick in front, single quote in the end):

```
.foreach(
  cacheSess {
    s -[w1]q 0x0 L?800000000000 schannel!CSessionCacheServerItem::`vftable'
  }
){
  .echo **SERVER*********;
  .echo **SessID**;
  db ${cacheSess}+88 L20;
  .echo **MasterKey**;
  db poi(poi(${cacheSess}+10)+10)+1C L30
};
.foreach(
  cacheSess {
    s -[w1]q 0x0 L?800000000000 schannel!CSessionCacheClientItem::`vftable'
  }
){
  .echo **CLIENT*********;
  .echo **SessID**;
  db ${cacheSess}+88 L20;
  .echo **MasterKey**;
  db poi(poi(${cacheSess}+10)+10)+1C L30
}
```

We need to fix the 88 offset (0x88 =  0x10 + 0x08 + 0x70 = offset to pointer to BDDD + pointer size + offset between pointer to BDDD and pointer to session ID). In our case 0x88 transforms to 0xd8:
```
0:013> .foreach(cacheSess {s -[w1]q 0x0 L?800000000000 schannel!CSessionCacheServerItem::`vftable'}){.echo **SERVER*********;.echo **SessID**;db ${cacheSess}+d8 L20;.echo **MasterKey**;db poi(poi(${cacheSess}+10)+10)+1C L30};.foreach(cacheSess {s -[w1]q 0x0 L?800000000000 schannel!CSessionCacheClientItem::`vftable'}){.echo **CLIENT*********;.echo **SessID**;db ${cacheSess}+d8 L20;.echo **MasterKey**;db poi(poi(${cacheSess}+10)+10)+1C L30}

**CLIENT*********
**SessID**
00000149`fc3b8e98  72 47 00 00 a2 67 05 2d-9e 5c 4c 9c 7f cf d5 d1  rG...g.-.\L.....
00000149`fc3b8ea8  e8 05 ad 18 0e 56 80 b1-81 69 c0 ef d8 a5 de 14  .....V...i......
**MasterKey**
00000149`fc3fe64c  1d b2 2a 0a 0a 98 ed ac-66 f1 b1 8a f2 3a 43 e1  ..*.....f....:C.
00000149`fc3fe65c  85 a4 d6 28 14 32 e6 f7-aa 65 f3 54 cb cf 84 cb  ...(.2...e.T....
00000149`fc3fe66c  1f 0d b9 90 fe 80 fb 39-44 c1 82 08 e4 71 97 9e  .......9D....q..
<...>
```

This also works an yield similar results.

When testing sessions resumed with with session tickets I, like the authors of the paper, found that the session ID is all zeroes:

```
**CLIENT*********
**SessID**
00000149`fc3b9048  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
00000149`fc3b9058  00 00 00 00 00 00 00 00-00 00 00 00 00 00 00 00  ................
**MasterKey**
00000149`fc31426c  c4 65 a3 98 c8 7d 69 6b-1f a0 2f 09 ef 49 32 37  .e...}ik../..I27
00000149`fc31427c  ad 6a fb 90 f8 36 79 d1-33 4c df 4a 0d 2b 74 2a  .j...6y.3L.J.+t*
00000149`fc31428c  b7 c1 fc c7 e9 d9 fa 3c-eb f7 e5 ad a7 57 2d af  .......<.....W-.
```

The authors didn't provide a way to correlate a master key to a client random in this case, which makes perfect sense, because it is unlikely that the client random is preserved in the cache, given that it is generated anew on succeeding resumed sessions. The session tickets, evidently, are no longer to be found at the offset 0x128 mentioned in the paper, and I decided to not search for the new offset - as mentioned in part 1, I already have a way to extract client random from a session hash and in schannel computing a session hash is guaranteed to always happen on session resumption.

### 1.4 CSessionCacheItem-based approach: TL;DR

All in all, the experiments yield the following observations:
1. The proposed approach works, though the offsets in `CSslCache{Client,Server}Item` structures have changed since 2016;
2. For TLS sessions with session id = 0 the approach is capable of getting the key, but not linking it to something ingestable by Wireshark, requiring manual work.

### 1.5 Dumping keys for resumed sessions by hooking (+ an easier way for non-resumed sessions)

Let's do some reversing to find where and how these cache items are used during a session resumption.

Looking through CSessionCacheClientItem methods, we can find an interesting method called IsSameTargetName. Breakpointing it reveals that it is called once for a resumed session, with the following backtrace (showing only SpInitLsaModeContext and above)

```
0:019> bm schannel!CSessionCacheClientItem::IsSameTargetName
  1: 00007ff8`f7c95ba0 @!"schannel!CSessionCacheClientItem::IsSameTargetName"
0:019> g
Breakpoint 1 hit
schannel!CSessionCacheClientItem::IsSameTargetName:
00007ff8`f7c95ba0 488b8158010000  mov     rax,qword ptr [rcx+158h] ds:0000029f`a53afa08=0000029fa53ba5e0
0:004> k
 # Child-SP          RetAddr           Call Site
00 000000ba`14f7e2d8 00007ff8`f7c95b6a schannel!CSessionCacheClientItem::IsSameTargetName
01 000000ba`14f7e2e0 00007ff8`f7c86e14 schannel!CSessionCacheClientItem::IsEntryAMatch+0x3a
02 000000ba`14f7e310 00007ff8`f7c8921c schannel!CSessionCacheTable::LookupCacheByName+0x108
03 000000ba`14f7e3a0 00007ff8`f7c8abc3 schannel!CSslContextManager::InstantiateClientContext+0x60
04 000000ba`14f7e400 00007ff8`f8818864 schannel!SpInitLsaModeContext+0x543
05 000000ba`14f7e570 00007ff8`f8815c9d lsasrv!WLsaInitContext+0x4a4
<SNIP>
```

Looking at the decompiled source for CSslContextManager::InstantiateClientContext we can find that it takes care of session caching both for TLS1.2 and 1.3. It is called for each new session to be established and calls `CSessionCacheManager::ComputeClientCacheIndex` followed by `CSessionCacheTable::LookupCacheByName` to find if there is a cache item associated with this session. The session cache table is stored in a global SessionCacheManager (CSessionCacheManager::m_pSessionCacheManager).

Debugging show that the return value of `CSessionCacheManager::ComputeClientCacheIndex` depends only on the server name (or ip), which is passed as the second parameter (the first parameter holds `this`):
```
0:006> db RDX L20
0000029f`a52c05e0  31 00 39 00 32 00 2e 00-31 00 36 00 38 00 2e 00  1.9.2...1.6.8...
0000029f`a52c05f0  38 00 38 00 2e 00 31 00-38 00 36 00 00 00 00 00  8.8...1.8.6.....p RCr
```

The `CSessionCacheTable::LookupCacheByName` has the following prototype:
```
int __thiscall
LookupCacheByName(CSessionCacheTable *this,ulong cache_index,WCHAR *server_name,
                 CCredentialGroup *credential_group,CSessionCacheItem **result)
```
The `cache_index` is the value returned by `ComputeClientCacheIndex` modulo the size of the cache, the `server_name` is a wchar string containing server name, `credential_group` is a pointer to a `CCredentialGroup` structure, and the resulting cache item will be written into `result`.
The `credential_group`  is different for different applications, but if called multiple times within the same app, can be the same. More testing shows that it corresponds to the first parameter of schannel's `InitializeSecurityContext` ([\[4\]](#ref4)), which is documented as follows:
```
phCredential [in, optional]

    A handle to the credentials returned by AcquireCredentialsHandle (Schannel). 
    This handle is used to build the security context.
    The InitializeSecurityContext (Schannel) function requires
    at least OUTBOUND credentials.
```

All this is very good, but hooking these method in schannel will require PDB, because they are not exported. Let's try to find something exported from ncrypt.dll, that is called during a resumed handshake. After a bit of digging and debugging we get to the following call trace:

```
 # Child-SP          RetAddr           Call Site
00 000000b7`9757db58 00007fff`f92f4f9e ncrypt!SslGenerateSessionKeys
01 000000b7`9757db60 00007fff`f92f4b7f schannel!CSslContext::MakeSessionKeys+0xee
02 000000b7`9757dc30 00007fff`f92f09e0 schannel!CSsl3TlsClientContext::ProcessRecord+0x1cf
03 000000b7`9757dc80 00007fff`f92eff43 schannel!CSsl3TlsContext::TlsProtocolHandlerWorker+0xa20
04 000000b7`9757dd60 00007fff`f92eaa35 schannel!CSsl3TlsContext::SslProtocolHandler+0x1c3
05 000000b7`9757dda0 00007fff`f9ed8864 schannel!SpInitLsaModeContext+0x3b5
06 000000b7`9757df10 00007fff`f9ed5c9d lsasrv!WLsaInitContext+0x4a4
<SNIP>
```

Looking at the docs [\[5\]](#ref5) for `SslGenerateSessionKeys` we can see that it receives the master key as a parameter:

```
SECURITY_STATUS WINAPI SslGenerateSessionKeys(
  _In_  NCRYPT_PROV_HANDLE hSslProvider,
  _In_  NCRYPT_KEY_HANDLE  hMasterKey,
  _Out_ NCRYPT_KEY_HANDLE  *phReadKey,
  _Out_ NCRYPT_KEY_HANDLE  *phWriteKey,
  _In_  PNCryptBufferDesc  pParameterList,
  _In_  DWORD              dwFlags
);
```

 `SslGenerateSessionKeys` is a perfect target for hooking, because it is called both for new and for resumed sessions. 
 What's even better is that, contrary to the `SslGenerateMasterKey` function, the calls to  `SslGenerateSessionKeys` will always have client random inside `pParameterList` (see [section 5.6 of Part 1](/decrypting-schannel-tls-part-1/#56-dealing-with-tls-session-hashes)). This is because the session hash TLS1.2 extension  only replaces client and server randoms with a hash during the calculation of a master secret. While calculating write keys, the client and server random are still needed (see section 6.3 of [\[6\]](#ref6)) and will be thus passed inside `pParameterList`. 
 
This means that we now have a generic way to dump TLS1.2 keys + their corresponding client randoms in all situations by just hooking one call.

### 1.6 TLS 1.2 session resumption: lessons learned

1. As described by Jake Cambic in [\[1\]](#ref1), the keys are cached inside `CSslCache{Client,Server}Item` structures.
2. Surprisingly, the master key is cached even if the server does not support any kind of resumption. I.e. if the server neither sends non-zero session ID nor sends the session tickt, the client will still cache the key.
3. As we've learned in the introduction, disabling EMS extension via `DisableClientExtendedMasterSecret` reg key, disables session resumption as well. In this case the keys are not persisted inside the `CSslCacheClientItem` structures. NB: enabling and disabling this key does not require reboot.
4. The session IDs and tickets are bound to the server address, not the port. I.e. if the client has received a session id or ticket when connecting to server:443, it will send that id/ticket when connecting to server:1443.
5. The session keys for resumption are bound to the calling process, which means that ProcessA will only reuse session ids or tickets that came from connections of ProcessA. Even more specifically, for session keys to be reused in succeeding calls to `InitializeSecurityContext` [\[4\]](#ref4) the client should reuse the first parameter (i.e. the credentials handle).
6. We've found a generic way to dump keys for both resumed and non-resumed TLS1.2 sessions.

## 2. Schannel and TLS 1.3 session resumption

Contrary to TLS1.2, TLS1.3 only supports session tickets for session resumption, see sections 2.2 and 4.6.1 of [\[7\]](#ref7). Session resumption in TLS 1.3 is a special case of a PSK, in the sense that it is indeed pre-shared by client and server before the connection. As outlined on page 93 of [\[7\]](#ref7), the resumed session will still generate new set of handshake and traffic secrets, using key material from PSK for two things:
1. Early secrets (most notably, the client_early_traffic_secret). This secret is used to generate a corresponding key, that is only used in a 0-RTT handshake for the first application data sent from the client in the first ClientHello (see page 18 of [\[7\]](#ref7)).
2. As a salt when generating handshake secrets based on DH exchange.

This means that our procedure for getting the handshake and application secrets from Part 1 should probably still work. The only thing we should additionally consider is the early traffic secrets, most importantly the CLIENT_EARLY_TRAFFIC_SECRET, but also the corresponding EARLY_EXPORTER_SECRET.

Though, as stated in MsQuic readme [\[9\]](#ref9), schannel currently lacks 0-RTT support, which means that realistically speaking, there will be no traffic encrypted by CLIENT_EARLY_TRAFFIC_SECRET.

Like in part 1, I tried to use the SSLWrappers project [\[8\]](#ref8). I had to patch the SSLWrapperDemo.cpp to perform two connections in a row that share sslCredentials, so that session resumption would work. However, even though that enabled the tool to resume  TLS1.2 sessions (both with session ids and tickets), I wasn't able to make it resume TLS1.3 sessions. I even upgraded from using the older SCHANNEL_CRED  structure [\[10\]](#ref10) to a new SCH_CREDENTIALS [\[11\]](#ref11), as implemented in [\[12\]](#ref12). The current status of resumption code in msquic for schannel tls provider implicitly supports my guess that resumption is currently not supported whatsoever, see [\[13\]](#ref13). I will be looking forward for any new information regarding support for TLS1.3 session resumption in Schannel.

## 3. References

<a id="ref1">[1]</a> GitHub - vincentbernat/rfc5077: [Various tools for testing RFC 5077](https://github.com/vincentbernat/rfc5077)

<a id="ref2">[2]</a> Microsoft Support: [A note on EMS and session resumption](https://support.microsoft.com/en-us/help/4528489/transport-layer-security-tls-connections-might-fail-or-timeout-when-co)

<a id="ref3">[3]</a> Jacob M. Kambic. Cunning With CNG: Soliciting Secrets from Schannel - [Whitepaper from DEFCON 24](https://media.defcon.org/DEF%20CON%2024/DEF%20CON%2024%20presentations/DEF%20CON%2024%20-%20Jkambic-Cunning-With-Cng-Soliciting-Secrets-From-Schannel-WP.pdf), [Slides from BlackHat USA 2016](https://www.blackhat.com/docs/us-16/materials/us-16-Kambic-Cunning-With-CNG-Soliciting-Secrets-From-SChannel.pdf), ["Extracting CNG TLS/SSL artifacts from LSASS memory" by Jacob M. Kambic](https://docs.lib.purdue.edu/open_access_theses/782/) 

<a id="ref4">[4]</a> Microsoft Docs: [InitializeSecurityContext (Schannel) function](https://docs.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel)

<a id="ref5">[5]</a> Microsoft Docs: [SslGenerateSessionKeys function (Sslprovider.h)](https://docs.microsoft.com/en-us/windows/win32/seccng/sslgeneratesessionkeys)

<a id="ref6">[6]</a> RFC 5246: [The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246.html) 

<a id="ref7">[7]</a> RFC 8446: [The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)

<a id="ref8">[8]</a> PJ Naughter blog:  [SSLWrappers + TLS v1.3 support](https://naughter.wordpress.com/2019/05/23/tls-v1-3-support-finally-on-windows/)

<a id="ref9">[9]</a> GitHub - microsoft/msquic: [Readme regarding schannel's 0-RTT support](https://github.com/microsoft/msquic#windows-10) 

<a id="ref10">[10]</a> Microsoft Docs: [SCHANNEL_CRED structure](https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-schannel_cred)

<a id="ref11">[11]</a> Microsoft Docs: [SCH_CREDENTIALS structure](https://docs.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-sch_credentials)

<a id="ref12">[12]</a> GitHub - microsoft/msquic: [Use SCH_CREDENTIALS instead of SCHANNEL_CREDS by anrossi · Pull Request #111](https://github.com/microsoft/msquic/pull/111) 

<a id="ref13">[13]</a> GitHub - microsoft/msquic: [msquic/tls_schannel.c at master](https://github.com/microsoft/msquic/blob/master/src/platform/tls_schannel.c#L1368)
