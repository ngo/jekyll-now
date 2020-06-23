---
layout: post
title: Decrypting Schannel TLS traffic. Part 1. Getting secrets from lsass
excerpt_separator: <!--more-->
---
Recently I've spent about a month doing research about extracting schannel TLS secrets. The journey and the results are summarized in **[the article](/decrypting-schannel-tls-part-1/)**.

The TL;DR is as follows:

 - The article is about ways to **decrypt TLS traffic of windows apps** that use schannel. This includes **IIS, RDP, IE and older Edge, Outlook, Powershell** and many others, but **excludes everything that uses OpenSSL or NSS** (most notably, all browsers except for Edge and IE). 
 - This is **not an exploit**. Applying this method **requires admin privilege** on the host and also **being able to debug lsass.exe** (i.e. bypassing protections such as Protected Process and Virtualization-based security is out of scope). 
 - There are ways to do similar things without admin privilege. Some of them are briefly mentioned in [related work](#2.-Related-work), and there also will be follow-up parts of the article about this.
 - The **tool** for exporting the keys **is available** at [win-frida-scripts repository](https://github.com/sldlb/win-frida-scripts/tree/master/lsasslkeylog-easy), along with a short howto.

This work is part of my R&D activities at [SolidLab LLC](https://solidlab.ru) and was fully funded by the company. I'm grateful to be able to do reseach as part of my job. 
<!--more-->
