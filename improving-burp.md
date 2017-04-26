---
layout: page
title: Better Burp Repeater
permalink: /improving-burp/
---

* TOC
{:toc}

__NB: this document currently more of a braindump. Please leave comments, so that the picture is more complete!__

## Goals ##

This document aims to describe, what improvements Burp needs in order to make manual web penetration testing an efficient and pleasing process.

## An overview of what's wrong ##

### Feature requests ###

1. Repeater
 * [Repeater organization](https://support.portswigger.net/customer/portal/questions/16767283-repeater-organization)
 * [Repeater UI - Fixed Placement of Tabs](https://support.portswigger.net/customer/portal/questions/11886952-repeater-ui-fixed-placement-of-tabs)
 * [Orchestrate Repeater Requests](https://support.portswigger.net/customer/portal/questions/16272678-orchestrate-repeater-requests)
 * [Add "Close All Tabs" button](https://support.portswigger.net/customer/portal/questions/12936757-add-close-all-tabs-button-to-the-repeaster)
 * [manage JSON Web Token auth](https://support.portswigger.net/customer/portal/questions/12941042-how-do-i-manage-json-web-token-auth-in-burp-)
2. Session management, macros, cookie jars
 * [Multithreaded scans vs single cookie jar](https://support.portswigger.net/customer/portal/questions/14319714-session-management)
 * [Multithreaded scans, single cookie jar, thread sync](https://support.portswigger.net/customer/portal/questions/14386607-burp-session-handling-in-multiple-scanner-threads)
 * [Session per request](https://support.portswigger.net/customer/portal/questions/16834096-generate-cookie-session-per-request-intruder)
 * [Multiple cookie jars](https://support.portswigger.net/customer/portal/questions/16318844-multiple-cookie-jars)

### Other points ###

1. Repeater
 * Some repeater tabs are kept as proofs that certain actions or outcomes are possible (i.e. specific error in response or successful attack).
In this case it usually happens that this tab is mistakenly reused to perform other requests. After that it is very hard to find that "POC I've done three days ago" or "that error I've seen but didn't investigate", the only way is to use search.
 * The only place where a repeater tab can be commented is its header, which leaves not enough room for a sufficiently large comment.
 * There is no indication as to which 'action' (in terms of webapp logic) is performed by the request and by which actor. There is no way to mark special circumstances (i.e. requests that are sent via 3G sometimes have special powers in terms of authentication)
 * There is no way to filter tabs that are displayed, which is super useful when pentesting multiple interconnected apps (i.e. oauth provider + oauth client, or merchant site + separate MPI + ACS)

2. Other unsorted
 * Cyrillic text in responses - sometimes improperly displayed, and copying to clipboard results in garbage.
 * Copying from request in repeater appends unnecessary newlines (might be linux-specific)
 * Memory usage and loading times, inability to quicly switch between projects
 * Not-so-usable hex editor (TODO specify).
 * "Export macro as a bash script" =)


{% include disqus.html %}
