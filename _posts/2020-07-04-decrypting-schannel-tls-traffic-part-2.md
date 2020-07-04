---
layout: post
title: Decrypting Schannel TLS traffic. Part 2. Session resumption
excerpt_separator: <!--more-->
---
The second part of my schannel research **[is out](/decrypting-schannel-tls-part-2/)**.  I recommend at least skimming through [part 1](/decrypting-schannel-tls-part-1/) before reading this one, because it contains a lot of important context that is omitted in part 2.

This part is about dealing with session resumption. I've also redone some of the experiments from a related research to discover if something has changed from the time it was written.
<!--more-->
The key takeaways are as follows:

 - For TLS1.2 schannel does session resumption both with session IDs and tickets;
 - Resumption for TLS1.2 is only performed when extended master secret extension is in use;
 - Methods and results from Jacob Cambic's research still largely apply, but some of the offsets have since changed;
 - Researching resumption helped identify an easier target for hooking the works both for resumed and non-resumed TLS1.2 sessions and does not have problems with session hashing, namely `SslGenerateSessionKeys`; 
 - The [tool for exporting the keys ](https://github.com/sldlb/win-frida-scripts/tree/master/lsasslkeylog-easy) was update with this new extraction method;
 - My experiments show that for TLS1.3 session resumption is **not** currently supported by Schannel. I would love to be proven wrong, though.

As previously, this work is part of my R&D activities at [SolidLab LLC](https://solidlab.ru) and was fully funded by the company. I'm grateful to be able to do reseach as part of my job. We do offensive security, web application analysis and SDL consunting. We also develop [a WAF](https://solidwall.io/).

**[Read part 2](/decrypting-schannel-tls-part-2/)**.

