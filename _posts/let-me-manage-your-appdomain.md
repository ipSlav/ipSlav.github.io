---
layout: post
title: Let Me Manage Your AppDomain
subtitle: Abuse the CLR memory un(safety)
tags: [red teaming, security research]
---

## Introduction
As EDR are becoming more and more sophisticated and difficult to bypass the opportunity to blend-in within legitimate application behavior appear to be an interesting vector to remain undetected.
This research started a couple of years back during my initial days of trying to bypass EDRs (without really understanding how and why things were working in a certain way) while stumbling upon a [@MrUn1k0d3r](https://twitter.com/MrUn1k0d3r) episode, on which he explained a really cool .NET appdomain trick.
By leveraging some other previous research and PoCs and standing on the shoulder of giants I've come up with an extra cool fashion way to backdoor and abuse .NET Framework applications.

### App Domain Manager Injection
The starting point to backdoor .NET Framwework applications is to abuse the very well-known App Domain Manager Injection technique.
For who doesn't know this technique, initially discovered by Casey Smith (aka subTee) in 2017, it allows to inject a custom ApplicationDomain that will execute arbitrary code inside the target application process.
At the time subTee published also GhostLoader, unfortunately the repo has been deleted but you can still check it thanks to a fork published by [TheWover)](https://github.com/TheWover/GhostLoader).
Without having to dive too much into the details (plese go check out [NetbiosX](https://pentestlaboratories.com/2020/05/26/appdomainmanager-injection-and-detection/) and [Rapid7](https://www.rapid7.com/blog/post/2023/05/05/appdomain-manager-injection-new-techniques-for-red-teams/) blogposts), what we are interested here is that we can trigger any .NET Framework application to load an arbirary managed DLL.

To do so two main trigger methods exists:

- .config XLM file
- Enviromental varibles
