---
title: "ParagOWNED - how CVE-2025-43200 likely abused Apple Intelligence to take control of an iPhone"
date: 2025-12-03T6:59:55+02:00
category: "analysis"
tags: ["vulnerability", "analysis"]
summary: "How the paragon iMessage exploit worked."
image: "/images/paragowned/Paragon-Website_White.png"
---

> **Note:** This analysis is based on patch diffing and reverse engineering. Some conclusions about the Apple Intelligence component are speculative based on the evidence available. The isFromMe bug vector is confirmed through patch analysis.

{{< figure src="/images/paragowned/Paragon-Website_White.png" width="60%" align="center" caption="Figure 1: Paragon's logo" >}}

# Who are Paragon?
Paragon Solutions is a cyberweapons company,
that sells spyware tools to foreign government agencies.
This is a buisness model that was pioneered and proven successful
first by NSO Group, then was emulated by others:

* [QuaDream](https://www.surveillancewatch.io/entities/quadream)
* [Candiru](https://www.surveillancewatch.io/entities/candiru)
* [Cytrox/Intellexa](https://www.surveillancewatch.io/entities/intellexa-consortium)
* [Toka group](https://www.surveillancewatch.io/entities/toka)
* [BlueOcean](https://www.surveillancewatch.io/entities/blue-ocean)
* [Dataflow](https://www.surveillancewatch.io/entities/dataflow-security)

Paragon differentiates itself from NSO Group by emphasizing that it sells its tools exclusively to what it refers to as “[Democratic Governments](https://he.wikipedia.org/wiki/%D7%A4%D7%90%D7%A8%D7%90%D7%92%D7%95%D7%9F_%D7%A4%D7%AA%D7%A8%D7%95%D7%A0%D7%95%D7%AA).” NSO Group, meanwhile, became the focus of extensive international media coverage following reports about how its technology had been used by various clients. In the period after that global scrutiny, oversight and export controls surrounding offensive cyber tools were tightened, which in turn narrowed the pool of eligible customers across the industry.

Paragon has ties in the US Government and have the US governments' trust since they do not have a complicated
past like NSO Group.
They leverage this clean record to offer basically the same service as NSO Group without the "[Stigma](https://www.bis.gov/press-release/commerce-adds-nso-group-other-foreign-companies-entity-list-malicious-cyber-activities)"
that comes along with using NSO Group products.


# What Was The exploit?
## iMessage - The one stop shop for Remote Code Execution
Apple's iMessage has been for a long time, THE vector for remote code execution.
Every time an iPhone receives an iMessage, there are a bunch of complex compontents that
parse and process the message recieved automatically.
Anywhere were parsing happens, we have the potential for bugs.

## What we do know about CVE-2025-43200
### From the media/investigative journalism
We only have very limited information about the techincal aspects of this CVE.
Bill marczak of citizen lab discovered the Graphite implant, and apple patched a cve that is part of the 0-Click chain used by Graphite (Paragon's equivalent to Pegasus).
The full chain is obviously not available, but its assumed that what apple described in their patchnotes is the entrance vector onto the device.
### From Apple
{{< figure src="/images/paragowned/apple-advisory1.png" width="100%" align="center" >}}
{{< figure src="/images/paragowned/apple-advisory2.png" width="100%" align="center" >}}

Apple's advisory gives us the surface details, but the real story is in the patch itself.

## Where one BlastDoor Closes, Another Door Opens
Seeing that this fix was released as part of a minor patch, I was optimistic in possibly being able to PatchDiff to find this vulnerability.
Luckily for us, there is a repo that details the diffs of every single iOS version against its previous release.
[Link to the great work by blacktop](https://github.com/blacktop/ipsw-diffs/tree/main/18_3_22D63__vs_18_3_1_22D72)
{{< figure src="/images/paragowned/diff.png" width="100%" align="center" >}}

Here we find an interesting change in the iMessage side of things, a new string has been added!:
{{< figure src="/images/paragowned/interesting-string.png" width="100%" align="center" >}}

Bingo! thats a massive hint! thanks apple!

lets diff this bad boy in IDA PRO, using [Diaphora++, my custom fork of diaphora](https://github.com/gracecondition/diaphoraplusplus)

{{< figure src="/images/paragowned/partial-matches.png" width="100%" align="center" >}}

We find that literally just one function has changed:

``_reAttemptMessageDeliveryForGUID``
Diffing it, i find:

{{< figure src="/images/paragowned/screenshot2.png" width="100%" align="center" >}}

In the first diff I found a new check, an ObjectiveC invocation of "isFromMe".
This is checking if the is_from_me bit is set in ``sms.db`` , where the message is stored.


{{< figure src="/images/paragowned/screenshot4.png" width="100%" align="center" >}}


And theres our

``Being requested to re-send a message that wasn't sent by me``

That we found in the patchdiffs.

### The Core Vulnerability: Missing isFromMe Check
This is it. The smoking gun. Apple added a check to verify message ownership before processing resend requests - a check that was completely missing before.
What does this mean? Attackers could force victims to "resend" messages they never actually sent. When this happens, iOS marks those malicious messages
as originating from the victim (`isFromMe = 1`), granting them elevated trust. This single missing check bypasses BlastDoor's sandbox protections,
allowing malicious link previews to be processed by Apple Intelligence with the security model completely inverted.

#### Stage 1  - Confirmed
Stage one goes as follows (Probably):

Attacker sends a maliciously crafted iMessage containing a link, and then another malicious iMessage asking the target
to resend that message ("being asked to resend a message that wasnt sent by me"), a missing isFromMe check is not performed.
this marks the message as being sent from the target, thus altering the behaviour of how the data is stored, and treated security wise by the operating system.

This message contains an iCloud link to a maliciously crafted photo or video (per Apple's advisory). When the isFromMe bug flips the message ownership to is_from_me = 1, the victim's iPhone treats this as their own content. The malicious media gets processed outside the BlastDoor sandbox because it's treated as "user-initiated" content. 

## Apple Intelligence gets PWN'D
I kept thinking about this one patch in the diff. The second most significant patch in the diff.
And I just couldnt make sense of it.

{{< figure src="/images/paragowned/diff3.png" width="100%" align="center" >}}
{{< figure src="/images/paragowned/diff2.png" width="100%" align="center" >}}

It looks like a bunch of AI (Apple Intelligence) code had been patched.
Yet, this was supposed to be an image parsing vulnerability, according to apple.

And then,

It hit me.
{{< figure src="/images/paragowned/umactually.png" width="100%" align="center" >}}

The "processing logic issue" is in Apple Intelligence!!!

### PatchDiffing WritingToolsUIService
This library appears to be code for applying Language Models on data.
This library recieves data as a string, injects json into it, and then parses it.

Heres what I did:
* PatchDiff'd the binary to create a list of removed functions.
* cross referenced the strings that were removed to the removed functions
* confirmed that the strings crossreferenced exist in the functions that were removed.

This gave me the following results, a few functions that were completely removed from ``WritingToolsUIService``:

{{< figure src="/images/paragowned/json-bug1.png" width="100%" align="center" >}}

The interesting behaviour is the appending of arbitrary strings on line 27, and line 34.

Lines 27 and 34 append attacker‑controlled data directly into a JSON literal. There is no escaping/sanitization;
only a final JSON validity check. A skilled attacker can and probably did craft an input that passes this check and injects additional code.

### Refinements - AI instructions
There is an array that is added into json, ``refinements``.
From what I can gather refinements are like "visual enhacements" in the form of markdown to how the plain text spit out
of the language model look, in the form of markdown. And thus require a markdown parser.
This array should not be writeable to by the attacker, hence when its added, its added like a closed empty array (See line 34 of PatchDiffing WritingToolsUIService)
However, due to the loose checks, an attacker could still still populate it.


{{< figure src="/images/paragowned/markdown-bug1.png" width="100%" align="center" >}}

Now that I have confirmed that multiple bugs were present in the way AppleIntelligence handles Untrusted input,
stuff like weak checks on JSON (just making sure its a valid json, not checking if the schema/format of the json has changed)
Theres a high probability that there was a bug in apple intelligence.
### More Evidence - ProactiveSummarizaton

{{< figure src="/images/paragowned/summerization.png" width="100%" align="center" >}}

It would appear there are now a bunch of checks in the way AI summaries are generated, likely to prevent
malicious media and messages from being processed by Apple Intelligence.

**This is the smoking gun for summarization being part of the chain.** Apple didn't just patch WritingToolsUIService - they added comprehensive input filtering to prevent malicious content from ever reaching the summarization pipeline in the first place. These deny lists are emergency mitigations that confirm:
1. Content from notifications (which includes iMessages) was being automatically fed into notification summarization
2. The summarization pipeline had weak input validation
3. Certain apps/content types were exploitable through this path

Specifically, the new defensive checks include:
```objc
CStrings:
+ "Could not load summarization bundleIds deny list plist: %@; proceeding with empty set"
+ "Could not load summarization categories plist: %@; proceeding with empty set"
+ "Notification not eligible for summarization (bundleId not allowed); bundle: %{public}s"
+ "Notification not eligible for summarization (iTunes category not allowed); bundle: %{public}s iTunes category: %{public}ld"
+ "Notification not eligible for summarization (no bundle): %{public}s"
+ "Notification stack has no app bundleId"
+ "Notification stack not eligible for summarization (bundleId not allowed); bundle: %{public}s"
+ "Notification stack not eligible for summarization (iTunes category not allowed); bundle: %{public}s iTunes category: %{public}ld"
+ "Notification stack not eligible for summarization (no bundle): %{public}s"
+ "Notification stack's bundleId is not allowed: "
+ "Notification stack's iTunes category is not allowed: "
+ "SummarizationBundleIdsDenyList"
+ "SummarizationCategoriesDenyList"
+ "The summarization bundleIds deny list plist exists but is missing a DeniedBundleIds key"
+ "The summarization categories plist exists but is missing a DeniedCategories key"
+ "summarizationFilter_notificationStack_ineligibleBundleId"
+ "summarizationFilter_notificationStack_ineligibleItunesCategory"
+ "summarizationFilter_notificationStack_missingBundleId"
+ "summarizationFilter_notification_ineligibleBundleId"
+ "summarizationFilter_notification_ineligibleItunesCategory"
+ "summarizationFilter_notification_missingBundleId"
```

*"Due to a significant amount of code redaction and error checking done in the AppleIntelligence codebase in the patch, I strongly believe an AppleIntelligence parsing bug is the second stage of the atttack."* - My conclusion


The following screenshot also backs up our hypothesis, and also suggests that this particular exploit was only used for a short while:
{{< figure src="/images/paragowned/auto-enable.png" width="100%" align="center" >}}


#### Stage 2 - Apple Intelligence parsing bug
Now that we have received a message with an iCloud link from an attacker, and the iPhone has begun to treat the message from the attacker as if it were from us
(isFromMe flipped to 1),
the security model changes. The iCloud link points to a maliciously crafted photo or video (per Apple's advisory). Since the message appears to be user-originated, the media is processed outside the BlastDoor sandbox with elevated trust.
Apple Intelligence then processes this malicious media for summarization, and a parsing bug is probably encountered somewhere
in the WritingToolsUIService/ProactiveSummarization part of the AppleIntelligence stack. The malicious photo/video or its metadata
likely injects content into the AI's JSON processing pipeline.

#### Diffing IMSharedUtils
I tried diffing IMSharedUtils and found that its unchanged. This is significant - it further strengthens the arugment that this isn't a classic image parsing vulnerability like JBIG2. Instead, the maliciously crafted photo or video (shared via iCloud link) likely exploits bugs in how Apple Intelligence **processes media content**, not in low-level image parsers.

# Hypothetical Exploit flow:

{{< mermaid >}}
flowchart TD
    subgraph P1["PHASE 1 - Initial Message Injection"]
        A1[Attacker sends malicious<br/>iMessage with iCloud link]
        A2[imagent daemon receives]
        A3[BlastDoor validates<br/>inactive payload]
        A4[Stored in sms.db<br/>is_from_me = 0]
        A1 --> A2 --> A3 --> A4
    end

    subgraph P2["PHASE 2 - isFromMe Bug"]
        B1[Attacker sends<br/>resend request]
        B2[imagent calls<br/>_reAttemptMessageDeliveryForGUID]
        B3[❌ MISSING isFromMe CHECK]
        B4[IMDPersistenceAgent<br/>updates database<br/>is_from_me = 1]
        B1 --> B2 --> B3 --> B4
    end

    subgraph P3["PHASE 3 - Sandbox Bypass"]
        C1[Message now trusted<br/>as user-initiated]
        C2[Malicious photo/video<br/>processed OUTSIDE BlastDoor]
        C3[iCloud media link<br/>Content with crafted metadata]
        C1 --> C2 --> C3
    end

    subgraph P4["PHASE 4 - AI Summarization"]
        D1[Media sent to<br/>Notification Summarization]
        D2[❌ NO DENY LISTS<br/>Weak input validation]
        D3[Media processed as<br/>notification content]
        D1 --> D2 --> D3
    end

    subgraph P5["PHASE 5 - JSON Injection"]
        E1[Data routed to<br/>WritingToolsUIService]
        E2[❌ Lines 27 & 34 bug<br/>Attacker strings appended<br/>without sanitization]
        E3[Malformed JSON created]
        E1 --> E2 --> E3
    end

    subgraph P6["PHASE 6 - Exploitation (Speculative)"]
        F1[LLM processes<br/>malformed JSON]
        F2[Markdown/Schema/<br/>Directive bugs triggered]
        F3[Code execution achieved<br/>in Apple Intelligence context]
        F1 --> F2 --> F3
    end

    subgraph P7["PHASE 7 - Post-Exploitation (speculative)"]
        G1[Graphite implant installed]
        G2[Access: messages, notifications,<br/>other user data ]
        G3[Graphite maintains persistence via launchd & privesc exploit]
        G1 --> G2 --> G3
    end

    P1 --> P2
    P2 --> P3
    P3 --> P4
    P4 --> P5
    P5 --> P6
    P6 --> P7

    style B3 fill:#ff6b6b,stroke:#f03e3e,stroke-width:3px,color:#fff
    style B4 fill:#f97316,stroke:#ea580c,stroke-width:2px,color:#fff
    style D2 fill:#ff8787,stroke:#f03e3e,stroke-width:2px,color:#fff
    style E2 fill:#ff6b6b,stroke:#f03e3e,stroke-width:3px,color:#fff
    style F3 fill:#a855f7,stroke:#9333ea,stroke-width:2px,color:#fff
    style G2 fill:#3b82f6,stroke:#2563eb,stroke-width:2px,color:#fff
{{< /mermaid >}}

## Daemon-Level Exploit Chain
Based on the patch analysis, here's how the exploit likely flows through iOS at the daemon level:

### Phase 1: Initial Message Injection
1. **Attacker → imagent (iMessage daemon)**
   - Attacker sends malicious iMessage containing an iCloud link to a malicious photo or video
   - Message passes through BlastDoor sandbox (inactive payload - no immediate trigger)
   - BlastDoor validates basic iMessage structure but doesn't detect dormant exploit
   - Message stored in `sms.db` with `is_from_me = 0` and assigned a GUID

### Phase 2: The isFromMe Bug Exploitation
2. **Attacker → imagent → IMDPersistenceAgent**
   - Attacker sends a second control message: a resend request for the victim's message GUID
   - `imagent` calls `_reAttemptMessageDeliveryForGUID:...` without verifying ownership
   - **Missing check:** No `if (![message isFromMe]) { return; }` validation
   - `IMDPersistenceAgent` updates the message in `sms.db`: `is_from_me` changes from `0` to `1`
   - Message now appears to originate from the victim

### Phase 3: Sandbox Bypass via Trust Inversion
3. **Message processing with inverted trust model**
   - Message marked as `is_from_me = 1` changes security context
   - iOS treats this as a "user-initiated" message
   - The message contains an iCloud link to a maliciously crafted photo or video
   - Since the message appears to be from the user, the media bypasses BlastDoor sandbox and is processed with elevated trust
   - The malicious media includes:
     - Crafted photo/video with malicious metadata
     - Content designed to exploit AI processing bugs
     - Not a classic image parsing vulnerability (IMSharedUtils unchanged)

### Phase 4: Apple Intelligence Summarization Processing
4. **Media Content → Notification Summarization Pipeline**
   - The malicious photo/video from the iCloud link is forwarded to Apple Intelligence for automatic summarization
   - iMessage media can trigger notification summarization
   - The exact daemon/framework name is private, but patch analysis reveals extensive changes to summarization logic
   - **Evidence from patches:** Apple added comprehensive filtering checks (see "More Evidence - AI summarization" section):
     - `SummarizationBundleIdsDenyList` - Probably blocks specific apps from being summarized
     - `SummarizationCategoriesDenyList` - Probably blocks apps by their iTunes category metadata (the App Store category like "Social Networking", "Games", etc.)
     - Notification eligibility checks for bundleId, categories, and missing bundle validation

    These NEW defensive checks confirm summarization was exploited - Apple is now filtering what content can enter the summarization pipeline

   - Media content that gets processed includes:
     - Photo/video data from iCloud link
     - Metadata from the malicious media
     - All of this fed into the AI summarization system that previously had weak input validation

### Phase 5: JSON Injection in WritingToolsUIService
5. **Summarization Pipeline → WritingToolsUIService**
   - The summarization system (whatever Apple calls it internally) processes the malicious media
   - Since the message appears to be from the user (isFromMe bug), and passes any pre-existing bundleId checks (before the patch added deny lists), the media gets processed
   - Data routed to `WritingToolsUIService` for LLM-based text processing
   - **Bug location:** Lines 27 and 34 of removed function (from patch analysis)
   - Attacker-controlled strings from the media/metadata appended directly into JSON literal without sanitization
   - Only final JSON validity check (no schema validation)
   - Malicious payload in media metadata crafted to:
     - Pass basic JSON syntax validation
     - Inject additional fields into the JSON structure
     - Potentially inject markdown in "refinements" array
   - **Why summarization had to be involved:** The tight coupling between the summarization checks (deny lists) and the WritingToolsUIService bugs (JSON injection) in the same patch strongly suggests summarization was the entry point that fed malicious data to WritingToolsUIService

### Phase 6: Exploitation (Speculative)
6. **WritingToolsUIService → Language Model Processing**
   - Malformed JSON with injected content processed by LLM pipeline
   - Possible exploitation paths:
     - **Path A:** Markdown injection in "refinements" triggers markdown parser bug
     - **Path B:** JSON schema confusion causes type confusion vulnerability
     - **Path C:** Injected JSON directives alter LLM processing behavior
     - **Path D:** Malicious "instructions" embedded in refinements executed by AI system
   - Exploitation leads to code execution in Apple Intelligence context
   - Apple Intelligence runs with elevated privileges (access to user data, notifications, messages)

### Phase 7: Post-Exploitation
7. **Code Execution → Persistence**
   - Exploit gains execution within Apple Intelligence daemon
   - Potential capabilities:
     - Standard Implant data collection: Gallery, messages, contacts, etc.
     - Potentially escalate to kernel via additional exploits
     - Install persistent implant (Graphite payload)
   - Attacker maintains access to device

## Attack Surface Summary
**Daemons Involved (Confirmed by Patch Analysis):**
- `WritingToolsUIService` - LLM text processing service with JSON injection bugs (Stage 5-6)
- `ProactiveSummarization` - Apple Intelligence notification/message summarization framework (Stage 4-5)

**Daemons Likely Involved (Inferred but not directly patched):**
- `imagent` - iMessage handling daemon with isFromMe bug (Stage 1-2)
- `IMDPersistenceAgent` - Message database management daemon (Stage 2)
- `intelligenceplatformd` - Apple Intelligence knowledge graph daemon, may route data between components (Stage 4)
- iCloud media processing components - The malicious photo/video from iCloud link is processed with elevated trust once isFromMe=1

**Security Boundaries Crossed:**
1. BlastDoor sandbox (bypassed via isFromMe bug - malicious iCloud media processed outside sandbox)
2. User/attacker message trust boundary (inverted by resend bug)
3. Apple Intelligence input validation (JSON injection in WritingToolsUIService)

# The story, most likely & Conclusions
## Exploitation & Discovery timeline
* This particular bugchain was made widely exploitable with the autoenabling of AppleIntelligence on 18.3.0, Januray 27th 2025
* This particular bugchain was patched with 18.3.1, Feburary 10, 2025 (14 days of exploitation)
* The Graphite implant is discovered on the iPhone, April 29th 2025 thanks to apple notification.

## Organizational methodoligies
Organizations like Paragon operate with the following principals:
* Any bug that can be exploited, should be exploited.
* Even if the bug is probably applicable to an obscure amount of iPhones, its still worth trying.
* If we dont exploit it, someone else will.

Aswell as

* Vulnerability research teams constantly work around the clock to create a sufficient backlog of exploits that can be swapped in and out so that the product remains operational even when a bug get patched.
* Vulnerability research teams have to update their existing exploit chains to work, when a part of the chain gets patched.

Also,

* Its almost confirmed that the ``isFromMe`` bug is the main vector of exploitation.
* Due to AppleIntelligence not being enabled on every phone, its likely that other chains were used in conjunction with the ``isFromMe`` bug, in cases
where apple intelligence was not exploitable.


## Lessons learned from history
More facts from history:
* Most times, security researchers that research these bugs cannot find the full chain.
* Finding the full chain requires a significant amount of effort
* Recreating the entire exploit, in working condition, requires even more effort
* Thus, its its more economical, practical, and more immediate to patch the intial access vector,alongside some of the chain (as much as possible), instead of reverse engineering the whole chain and patching accordingly.

## What happened post patching
It is highly likely that Paragon has a double digit backlog of exploits for iOS and android.
That backlog of exploits can be used to create chains that allow remote code execution.
The bugs in the current used RCE chain were swapped out for other bugs, and the RCE chain presists.
* The ``isFromMe`` iMessage entry vector was closed, and likely replaced with another bug.
* The AppleIntelligence parsing bug was replaced with another bug for code execution


# Credits and closing remarks
## Closing remarks
All of the information in this post is hypothetical security research from the very little made available to the public.

I do not have a personal stance on this industry, and am not an "activist". I simply find the technology fascinating.

If you are reading this and work for an organization like this, The only thing I would think is that on a **purely technological level**, what  you work on is insanely cool, thats about it.

Everything in this blog was written to the best of my knowledge, if you want to submit corrections or know something that I dont
please dont hesitate to reach out!


## Credits

[Jaybird1291](https://jaybird1291.github.io/blog-cyber/en/posts/graphite-caught/), who also independantly replicated some of the exploit chain research, aswell as creating heuristics for how one might forensically detect this exploit.

[A Brief History of
iMessage Exploitation
Samuel Groß (@5aelo), Ian Beer (@i41nbeer)](https://saelo.github.io/presentations/bluehat_il_22_a_brief_history_of_imessage_exploitation.pdf)
For providing an invaluable amount of knowledge on iMessage exploits of the past.

