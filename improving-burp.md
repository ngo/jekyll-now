---
layout: page
title: Better Burp Repeater
permalink: /improving-burp/
---

* TOC
{:toc}

__NB: this is currently more of a braindump__

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
