# Online Operations Security (OpSec)
Threat models and tools for staying safe, private and informed while Online, used by the average person.

## Introduction
OpSec or Operations Security, originally introduced by the United States Military during the Vietnam War, can be defined (when referring to [Wikipedia](https://en.wikipedia.org/wiki/Operations_security)) as a, "*...process that identifies critical information to determine if friendly actions can be observed by enemy intelligence, determines if information obtained by adversaries could be interpreted to be useful to them, and then executes selected measures that eliminate or reduce adversary exploitation of friendly critical information.*" OpSec is also a paradigm or a mindset, and applicable to any activity within the physical and digital worlds; both increasingly intertwined with and bound to the other.

The core motivation of OpSec is to protect what you value; often information or state, but sometimes tangible (or other intangible) goods too. OpSec is therefore any proactive efforts made to limit an attacker's ability to remove said value from you, for whatever their and/or your purposes. And Online OpSec is protecting what one values in relationship to coexisting with and using the Internet, all of which we explore in detail throughout the sections below.

Online OpSec, in the context of everyday Internet users is quite a serious/pressing topic, one best to be treated responsibly and with care. Thankfully, in a way similar to how large companies successfully deploy DevOps, individuals can apply Online OpSec tools and techniques to reduce their own risks; perhaps even more effectively and immediately, which is important to observe. Ideally Online OpSec becomes integrated into one's lifestyle choices, even your conscious thinking and (more submliminal) dreaming, during the day and/or night.

Therefore the purpose of this document is to organize useful context (in the form of information about threat modeling) and powerful tools (most of which are free and open source software, or FOSS) for staying safe, private and informed while Online. If a resource mentioned inside this document does require one to spend money for access, said tool is assuredly both low-cost and high-return. Above all, please continue doing your own research to validate anything and everything herein.

### Quintessentials
Before diving into the world(s) of Online OpSec, it's important to understand what is at risk; more accurately, it's important to understand what we value. We value specific states that encourage human wellness; those being safety, privacy and access to information. Or being safe, private and informed; again, each quality is reliant on the others for overall, personal success.

The substance of this document can help the individual maintain these conditions Online in conjunction with other states or pursuits or variables. To help explain, below is an overview of what *safe*, *private* and *informed* mean in the setting of this resource.

#### Safe
To be safe (when referencing [Wikipedia](https://en.wikipedia.org/wiki/Safety)) means to be, "*...protected from harm or other non-desirable outcomes. Safety can also refer to the control of recognized hazards in order to achieve an acceptable level of risk.*" We can therefore see that to be safe means to employ a degree of agency over one's immediate environment. So, however relative and subjective, to be safe is (universally) to be gated, aware and responsive; which is best accomplished and sustained through cooperation with an interconnected community of like-minded people and other resources.

#### Private
To have privacy or to be private (according to the [IAPP](https://iapp.org/about/what-is-privacy/)) means to be, "*...let alone, or [to have] freedom from interference or intrusion.*" Something is considered to be private when it relates to or impacts only a select few parties.

Online OPSEC is relevant to the average person (as written by [Stuart Peck](https://www.tripwire.com/state-of-security/security-data-protection/opsec-everyone-not-just-people-something-hide/)) in terms of privacy as, '*There’s a saying that goes, “If you have nothing to hide, you have nothing to fear.” The reality is that everyone has something they want to hide from the general public.*' In other words, it is reliable to assume that most people value privacy to some extent, and therefore must maintain it.

#### Informed
To be informed (as mentioned on [Merriam-Webster.com](https://www.merriam-webster.com/dictionary/well-informed)) means to be especially, "*...knowledgeable in a particular subject[.]*" This is also the state of access to information one has that you are seeking, even more so if it's required for your objective(s) to be met.

To be informed is to be aware of properties and their value(s); ideally within a single dashboard. The essence of remaining informed is the ability to quickly and flexibly scale one's awareness over whatever is of interest. Accomplished on the Internet with powerful Social Media Monitoring tools and simple techniques to enhance their usefulness.

### Adversaries
There are many different potential threats (to what is valued) or adversaries faced by the average person, in terms of their/the Online reality. And these risks are also important to understand before diving into threat modeling and the relevant technologies, the tools. 

An adversary (according to [Merriam-Webster.com](https://www.merriam-webster.com/dictionary/adversary)) is defined as, "*having or involving antagonistic parties or opposing interests[.]*" Along those lines, below we review three types of adversaries; which are social, technological and economic.

#### Social
Social dangers can include being tricked into unknowingly divulging personally identifiable information. Or losing friendships due to gossip.

#### Technological
Technological dangers can include your computer being remotely accessed without your consent. Or one's smart home video surveillance system being illegally monitored.

#### Economic
Economic dangers can include theft of digital currencies or loss of a job.

### Relevancy
The need to be secure (which is at the root or a product of privacy, safety and remaining informed) when using the Internet (in other words, when creating a digital footprint) is relevant to everyone; regardless of who, what, why, how, where and/or when one is. This is a consequence of and opportunity for/from an open Internet. Savvy users must thus be proactive to ensure effective participation, as threats abound.

Moving forward, threat models are covered first, followed by specific tools; extensions in the pursuit of reaching for that meta (yet granular) agency, an ideal asset indeed.

## Threat Models
A threat model is a structured and systematic means by which individuals can identify potential vulnerabilities, understand the implications of each and respond accordingly in order to mitigate any potential damage. The intention behind threat modeling, as mentioned on [Wikipedia](https://en.wikipedia.org/wiki/Threat_model), is to offer an, "*...analysis of what controls or defenses need to be included, given the nature of the system, the probable attacker's profile, the most likely attack vectors, and the assets most desired by an attacker.*" In other words, designing a threat model is the conducting of an organized review of one's current situation and possible or foreseeable future dangers therein.

The objective for deploying a threat model is to determine what can go wrong inside a given set of variables; providing the modeler tactical advantages that might have otherwise been missed from lack of perspective and preparation. The use of threat models is akin to doing one's homework on probable realities. Best done (according to [Martin Fowler](https://martinfowler.com/articles/agile-threat-modelling.html#ThreatModellinglittleAndOften)) a little bit at a time, but frequently.

There is an underlying or common pattern among many threat models, generally consisting of five interrelated steps/phases. The first step is to identify the information/assest(s) that are critical to your operation. The second step or phase is to conduct an analysis of the possible threats to what you're protecting (what you value). The third step is to conduct a review of how you might be vulnerable to the attacks identified in the previous step. The fourth step is to map out how likely your risk is given the information generated so far. And the fifth phase/step includes deploying any appropriate countermeasures.

Below you will find a growing number of specific threat modeling techniques that can be applied to anyone's security situation Online.

### LINDDUN
LINDDUN is an acronym for seven different threat categories; including linkability, identifiability, non-repudiation, detectability, disclosure of information, unawareness and non-compliance. And is carried out over six steps.
1. Model your Data Flow Diagram (DFD)
1. Map privacy threats to DFD elements
1. Identify threat scenarios
1. Prioritize threats
1. Select suitable mitigation strategies
1. Select corresponding Privacy Enhancing Technologies (PETs)

#### Six Steps
The six steps of the LINDDUN method are explored below.

##### Model Your DFD
Understand how your system is organized, using Data Flow Diagrams.

##### Map Privacy Threats
While relying on DFDs, investigate each element for possible threats.

##### Identify Threats
Once a threat is identified, make a note of it.

##### Prioritize Threats
Determine which threats are most pressing.

##### Select Mitigation Strategies
Resolve and overcome each threat by choosing the correct solution(s).

##### Apply PETs
Include the use of privacy enhancing technologies (PETs) in your total approach.

#### Seven Threat Categories
Let's now explore the seven different threat categories addressed by the LINDDUN model, with help from the [LINDDUN](https://www.linddun.org/linddun) organization; as quoted below.

##### Linkability
When an attacker can, "*...link two items of interest without knowing the identity of the data subject(s) involved.*"

##### Identifiability
When an attacker can, "*...identify a data subject... ...through an item of interest.*"

##### Non-Repudiation
When a, "*...data subject is unable to deny a claim[.]*"

##### Detectability
When an attacker can, "*...distinguish whether an item of interest about a data subject exists or not[.]*"

##### Disclosure Of Information
When an attacker can, "*...learn the content of an item of interest about a data subject.*"

##### Unawareness
When a, "*...data subject is unaware of the collection, processing, storage, or sharing activities... ...of the data subject’s personal data.*"

##### Non-Compliance
This is the, "*...processing, storage, or handling of personal data is not compliant with [standards.]*"

#### Conclusion
The LINDDUN threat model is simple and robust. It's also one of my favorite techniques for analyzing personal Online vulnerabilities; primarily because it produces strong and distinct results.

### PASTA
PASTA stands for Process For Attack Simulation And Threat Analysis.

There are seven stages involved in the PASTA model.
1. Define Objectives
1. Define Technical Scope
1. Application Decomposition
1. Threat Analysis
1. Vulnerability And Weaknesses Analysis
1. Attack Modeling 
1. Risk And Impact Analysis

#### Seven Phases
The seven phases of PASTA explained.

##### Define Objectives
Identifying your goals.

##### Define Technical Scope
Define where you're interfacing with the Internet, where you're exposed.

##### Application Decomposition
Box each element of your situation into their basic elements.

##### Threat Analysis
List out your potential threats.

##### Vulnerability And Weaknesses Analysis
Connect where you're exposed to assets (what you value) and possible attackers.

##### Attack Modeling
Create hypothetical situations for how attackers might attempt to remove value from you.

##### Risk And Impact Analysis
Generate an overall understanding of what the consequences and likelihood(s) are for certain attacks.

#### Conclusion
The PASTA model (as mentioned by [Tony UV](https://2017.appsec.eu/presos/CISO/Threat%20Modeling%20with%20PASTA%20-%20Risk%20Centric%20Application%20Threat%20Modeling%20Case%20Studies%20-%20Tony%20UcedaV%C3%A9lez%20-%20OWASP_AppSec-Eu_2017.pdf)) is a, "*...flexible, phased approach for [the] adoption of... ...threat modeling[.]*"

### STRIDE
STRIDE (originally introduced by Microsoft) is an acronym representing six different types of threats, each tied to a desired/alternative state or property:
* Spoofing / Authenticity
* Tampering / Integrity
* Repudiation / Non-Repudiability
* Information Disclosure / Confidentiality
* Denial Of Service / Availability
* Elevation Of Privilege / Authorization

According to [Wikipedia](https://en.wikipedia.org/wiki/STRIDE_(security)), STRIDE is typically applied when attempting to, "*...find threats to a system. It is used in conjunction with a model of the target system that can be constructed in parallel. This includes a full breakdown of processes, data stores, data flows and trust boundaries.*" The STRIDE model is popular because it is effective, but that relevancy (as mentioned by [Kevin Poniatowski](https://blog.securityinnovation.com/stride)) has been waning.

#### Specific Threats

What follows are the six different threats (as outlined above) that the STRIDE model examines in detail.

##### Spoofing
Spoofing (as explained by [Forcepoint](https://www.forcepoint.com/cyber-edu/spoofing)) is the misrepresentation of one's identity when communicating, whether that be of a person or computer.

##### Tampering
Tampering (according to [Merriam-Webster.com](https://www.merriam-webster.com/dictionary/tamper)) refers to, "*...interfere so as to weaken or change for the worse...*"

##### Repudiation
Leaving no trail or details of illegal or unauthroized activity.

##### Information Disclosure
Gaining access to private and/or secure information without proper authority.

##### Denial Of Service
Preventing intended users from having access to a resource.

##### Elevation Of Privilege
Unauthorized expansion of abilities as a user.

#### Conclusion
The STRIDE threat model is especially useful for understanding one's personal Online Operations Security situation.

Now that we have overviewed a few different threat models as examples, let's take a look at the best tools and technologies accesible to the average person for remaining safe, private and informed while Online.

## Tools
The tools organized below are useful for remaining secure while Online. Special attention has been given to the overall usefulness of each utlity for the average person. In other words, most of the resources listed below are picked for their simplicity and overwhleming effectiveness. There are more powerful tools available, but those are considered to be expert level technologies, therefore unnecessary or outside the scope of this document.

### Android Device Apps
Applications for the Android mobile Operating System.

* **[Bouncer](https://play.google.com/store/apps/details?id=com.samruston.permission)** - "*...gives you the ability to grant permissions temporarily. Want to tag a location or take a photo, but don't want that app to be able to use the camera or get your location whenever it wants? Bouncer gives you exactly that.*"
* **[K-9 Mail](https://k9mail.app/)** - "*...is an open source email client focused on making it easy to chew through large volumes of email.*"
* **[Orbot](https://play.google.com/store/apps/details?id=org.torproject.android)** - "*...a free proxy app that empowers other apps to use the internet more securely. Orbot uses Tor to encrypt your Internet traffic and then hides it by bouncing through a series of computers around the world.*"

### Antivirus
Reputable and effective antivirus software for Windows computer. Which can be understood (by referring to [TechTerms](https://techterms.com/definition/antivirus)) as a, "*...type of utility used for scanning and removing viruses from your computer.*"

* **[Bitdefender](https://www.bitdefender.com/)** - "*...is a global cybersecurity leader protecting over 500 million systems in more than 150 countries.*" (Recommended)
* **[Malwarebytes](https://www.malwarebytes.com/)** - "*...not only stops hackers and malware, but it cleans up an infected machine better than traditional antivirus.*"

### Books
Literature for understanding the larger thought-space of personal security; both Online and off.

* **The Art of Invisibility** - written by Kevin Mitnick, published on September 10th of 2019
* **ComSec** - written by Justin Carroll, published on July 13th of 2018
* **Extreme Privacy** - written by Michael Bazzell, published on May 27th of 2020 (Recommended)
* **Going Gray** - written by Matthew Dermody, published on January 22nd of 2020
* **How To Be Your Own Bodyguard** - written by Nick Hughes, published on October 1st of 2011
* **Open Source Intelligence Techniques** - written by Michael Bazzell, published on October 25 on 2019
* **Operator Handbook** - written by Joshua Picolet and published on March 18th of 2020
* **Situational Sense** - written by Matthew Dermody, published on December 10th of 2019
* **Social Engineering** - written by Christopher Handagy, published on July 31st of 2018
* **Surveillance Zone** - written by Ami Toben, published on May 21st of 2017
* **Survive Like a Spy** - written by Jason Hanson, published on September 8th of 2020

### Browser Extensions
Critical security and privacy add-ons for the Firefox Browser.

* **[Clear Browsing Data](https://addons.mozilla.org/en-US/firefox/addon/clear-browsing-data/)** - "*Delete browsing data directly from the browser toolbar. Clear cookies, history and cache with a single click.*" (Recommended)
* **[ClearURLs](https://addons.mozilla.org/en-US/firefox/addon/clearurls/)** - "*...automatically remove tracking elements from URLs to help protect your privacy when browsing through the Internet.*" (Recommended)
* **[Cookie AutoDelete](https://addons.mozilla.org/en-US/firefox/addon/cookie-autodelete/)** - "*When a tab closes, any cookies not being used are automatically deleted. Whitelist the ones you trust while deleting the rest.*" (Recommended)
* **[Decentraleyes](https://addons.mozilla.org/en-US/firefox/addon/decentraleyes/)** - "*...prevents a lot of requests from reaching networks like Google Hosted Libraries, and serves local files to keep sites from breaking.*"
* **[Firefox Multi-Account Containers](https://addons.mozilla.org/en-US/firefox/addon/multi-account-containers/)** - "*...lets you keep parts of your online life separated into color-coded tabs that preserve your privacy.*"
* **[Ghostery](https://addons.mozilla.org/en-US/firefox/addon/ghostery/)** - "*Block ads, stop trackers and speed up websites.*"
* **[Google Search Link Fix](https://addons.mozilla.org/en-US/firefox/addon/google-search-link-fix/)** - "*...prevents Google and Yandex search pages from modifying search result links when you click them.*"
* **[HTTPS Everywhere](https://addons.mozilla.org/en-US/firefox/addon/https-everywhere/)** - "*...a Firefox extension to protect your communications by enabling HTTPS encryption automatically on sites that are known to support it, even when you type URLs or follow links that omit the https: prefix.*" (Recommended)
* **[NoScript Security Suite](https://addons.mozilla.org/en-US/firefox/addon/noscript/)** - "*Allow potentially malicious web content to run only from sites you trust. Protect yourself against XSS other web security exploits.*" (Recommended)
* **[Privacy Badger](https://addons.mozilla.org/en-US/firefox/addon/privacy-badger17/)** - "*Automatically learns to block invisible trackers.*" (Recommended)
* **[uBlock Origin](https://addons.mozilla.org/en-US/firefox/addon/ublock-origin/)** - "*...an efficient wide-spectrum content blocker. Easy on CPU and memory.*" (Recommended)
* **[uMatrix](https://addons.mozilla.org/en-US/firefox/addon/umatrix/)** - "*...forbid/allow any class of requests made by your browser. Use it to block scripts, iframes, ads, facebook, etc.*"

### Browsers
The average Web Browser (according to [Mozilla.org](https://www.mozilla.org/en-US/firefox/browsers/what-is-a-browser/)) enables users to go, "*...anywhere on the internet, letting you see text, images and video from anywhere in the world.*" The modern Browsers of today's Web are able to do much more than view text, images and videos; including text-to-voice translation, secure Online shopping and the inclusion of extensions/add-ons.

* **[Brave](https://brave.com/)** - "*Secure, fast and private Web browser with Adblocker[.]*" - [Source](https://en.wikipedia.org/wiki/Firefox)
* **[Firefox](https://www.mozilla.org/en-US/firefox/)** - "*...is a free and open-source web browser developed by the Mozilla Foundation and its subsidiary, the Mozilla Corporation. Firefox uses the Gecko layout engine to render web pages, which implements current and anticipated web standards.*" - [Source](https://en.wikipedia.org/wiki/Firefox) (Recommended)
* **[GNU IceCat](https://www.gnu.org/software/gnuzilla/)** - "*GNUzilla is the GNU version of the Mozilla suite, and GNU IceCat is the GNU version of the Firefox browser. Its main advantage is an ethical one: it is entirely free software.*"
* **[Tor](https://www.torproject.org/)** - "*Defend yourself against tracking and surveillance. Circumvent censorship.*"

### Browser Testing
These are tools that Internet users can use to verify how secure or insecure an Web experience is. Or, how much information your digital footprint, inside a given moment, contains or expresses.

* **[AmIUnique](https://amiunique.org/)** - "*Learn how identifiable you are on the Internet[.]*"
* **[BrowserLeaks](https://browserleaks.com/)** - "*...is all about browsing privacy and web browser fingerprinting. Here you will find a gallery of web technologies security testing tools that will show you what kind of personal identity data can be leaked, and how to protect yourself from this.*" (Recommended)
* **[Cover Your Tracks](https://coveryourtracks.eff.org/)** - "*Test your browser to see how well you are protected from tracking and fingerprinting.*"
* **[IPLeak.net](https://ipleak.net/)** - "*This is the kind of information that all the sites you visit, as well as their advertisers and any embedded widget, can see and collect about you.*" (Recommended)


### Data Erasure
Tools for permanently deleting data on your computer.

* **[BleachBit](https://www.bleachbit.org/)** - "*...you can free cache, delete cookies, clear Internet history, shred temporary files, delete logs, and discard junk you didn't know was there.*" (Recommended)

### Disc Encryption
A disc is one's hard drive, whether that's a standard Hard Disc Drive or a more modern Solid State Drive. And encryption (according to [Wikipedia](https://en.wikipedia.org/wiki/Encryption)) is the, "*...process of encoding information. This process converts the original representation of the information, known as plaintext, into an alternative form known as ciphertext. Ideally, only authorized parties can decipher a ciphertext back to plaintext and access the original information.*" So, disc encryption is therefore the process of encoding of information stored therein.

* **[GPG](https://gnupg.org/)** - "*...is a complete and free implementation of the OpenPGP standard as defined by RFC4880 (also known as PGP). GnuPG allows you to encrypt and sign your data and communications; it features a versatile key management system, along with access modules for all kinds of public key directories.*"
* **[VeraCrypt](https://www.veracrypt.fr/en/Home.html)** - "*...is a free open source disk encryption software for Windows, Mac OSX and Linux.*"

### Email Providers
* **[AnonAddy](https://anonaddy.com/)** - "*...simply make up a new alias and enter that instead of your real email address.*"
* **[Guerilla Mail](https://www.guerrillamail.com/)** - "*...gives you a disposable email address. There is no need to register, simply visit Guerrilla Mail and a random address will be given.*"
* **[Mailfence](https://mailfence.com/)** - "*We believe that online privacy is a fundamental human right which can no longer be taken for granted so we decided that it was time to offer a service which is fully dedicated to email privacy.*"
* **[ProtonMail](https://protonmail.com/)** - "*...an easy to use secure email service with built-in end-to-end encryption and state of the art security features. Our goal is to build an internet that respects privacy and is secure against cyberattacks.*" (Recommended)
* **[SimpleLogin](https://simplelogin.io/)** - "*...is an open-source email alias solution to protect your email address.*"
* **[Tutanota](https://tutanota.com/)** - "*...the world's most secure email service, easy to use and private by design.*"

### Email Clients
* **[Roundcube](https://roundcube.net/)** - "*...is a browser-based multilingual IMAP client with an application-like user interface. It provides full functionality you expect from an email client, including MIME support, address book, folder manipulation, message searching and spell checking.*"
* **[Thunderbird](https://www.thunderbird.net/)** - "*...is a free email application that’s easy to set up and customize - and it’s loaded with great features!*"

### Encrypted Cloud Storage
* **[pCloud](https://www.pcloud.com/)** - "*...we're providing the world with a comprehensive easy-to-use cloud storage solution for individuals and businesses alike.*"
* **[Sync](https://www.sync.com/)** - "*...protects your privacy with end-to-end encryption — ensuring that your data in the cloud is safe, secure and 100% private.*"
* **[Tresorit](https://tresorit.com/)** - "*...is the ultra-secure place in the cloud to store, sync, and share files within your organization and with external partners.*"

### Firewalls
A firewall (according to [Indiana University](https://kb.iu.edu/d/aoru)) is a, "*...system designed to prevent unauthorized access to or from a private network. ... Firewalls prevent unauthorized internet users from accessing private networks connected to the internet, especially intranets.*" The purpose and useuflness of a firewall doesn't change, whether you're securing a business or a home network.

* **[pfSense](https://www.pfsense.org/)** - "*...is a free network firewall distribution, based on the FreeBSD operating system with a custom kernel and including third party free software packages for additional functionality. pfSense software, with the help of the package system, is able to provide the same functionality or more of common commercial firewalls, without any of the artificial limitations.*" (Recommended)

### Messaging
* **[Signal](https://signal.org/)** - "*...a cross-platform encrypted messaging service developed by the Signal Foundation and Signal Messenger LLC. It uses the Internet to send one-to-one and group messages, which can include files, voice notes, images and videos.*" - [Source](https://en.wikipedia.org/wiki/Signal_(software))
* **[Silence](https://silence.im/)** - "*Encrypt your SMS and MMS messages with Silence. Improve your privacy, think freely.*"

### Mobile Device Operating Systems
* **[GrapheneOS](https://grapheneos.org/)** - "*...is an open source privacy and security focused mobile OS with Android app compatibility.*"

### Operating Systems
An Operating System (sometimes abbreviated simply as "OS", when referencing [GCFGlobal](https://edu.gcfglobal.org/en/computerbasics/understanding-operating-systems/1/)) is the, "*...most important software that runs on a computer. It manages the computer's memory and processes, as well as all of its software and hardware. It also allows you to communicate with the computer without knowing how to speak the computer's language.*" All of the Operating Systems explored below are Linux distributions.

* **[Arch Linux](https://www.archlinux.org/)** - "*...a Linux distribution for computers with x86-64 processors. Arch Linux adheres to five principles: simplicity, modernity, pragmatism, user centrality, and versatility.*" - [Source](https://en.wikipedia.org/wiki/Arch_Linux)
* **[Debian](https://www.debian.org/)** - "*...a Linux distribution composed of free and open-source software, developed by the community-supported Debian Project, which was established by Ian Murdock on August 16, 1993.*" - [Source](https://en.wikipedia.org/wiki/Debian)
* **[Fedora](https://getfedora.org/)** - "*...an innovative, free, and open source platform for hardware, clouds, and containers that enables software developers and community members to build tailored solutions for their users.*"
* **[Qubes OS](https://www.qubes-os.org/)** - "*...a free and open-source, security-oriented operating system for single-user desktop computing. Qubes OS leverages Xen-based virtualization to allow for the creation and management of isolated compartments called qubes.*"
* **[Tails](https://tails.boum.org/)** - "*...is a portable operating system that protects against surveillance and censorship.*"
* **[Ubuntu](https://ubuntu.com/)** - "*...a Linux distribution based on Debian and mostly composed of free and open-source software.*" - [Source](https://en.wikipedia.org/wiki/Ubuntu) (Recommended)
* **[Whonix](https://www.whonix.org/)** - "*...can anonymize everything you do online[.]*"

### Password Storage
Password storage is accomplished with password manager software, which (referencing [WeLiveSecurity](https://www.welivesecurity.com/2020/06/26/what-is-password-manager-why-is-it-useful/)) is a type of, "*application specifically designed to store your login details in an encrypted vault and to generate complex passwords for you[.]*"

* **[Bitwarden](https://bitwarden.com/)** - "*...easiest and safest way for individuals and businesses to store, share, and secure sensitive data on any device[.]*"
* **[KeePassX](https://www.keepassx.org/)** - "*...an application for people with extremly high demands on secure personal data management. It has a light interface, is cross platform and published under the terms of the GNU General Public License.*" (Recommended)
* **[KeePassXC](https://keepassxc.org/)** - "*Securely store passwords using industry standard encryption, quickly auto-type them into desktop applications, and use our browser extension to log into websites.*"
* **[Pass](https://www.passwordstore.org/)** - "*The standard unix password manager[.]*"

### Prepaid Wireless Providers
* **[Tracfone](https://www.tracfone.com/)** - "*...is an American prepaid, no-contract mobile phone provider.*" - [Source](https://en.wikipedia.org/wiki/TracFone_Wireless)

### Search Engines
A search engine (according to [Computer Hope](https://www.computerhope.com/jargon/s/searengi.htm)) is, "*...software accessed on the Internet that searches a database of information according to the user's query. The engine provides a list of results that best match what the user is trying to find*" These tools are useful for finding lots of relevant information quickly; or, scaling the Internet with ease.

* **[CheckUsernames](https://checkusernames.com/)** - "*Check the use of your brand or username on 160 Social Networks[.]*"
* **[DuckDuckGo](https://duckduckgo.com/)** - "*...an international community of extraordinary individuals, coming together on a mission to set a new standard of trust online.*" (Recommended)
* **[Qwant](https://lite.qwant.com/)** - "*...is the first search engine which protects its users freedoms and ensures that the digital ecosystem remains healthy.*"
* **[Searx](https://searx.me/)** - "*Privacy-respecting metasearch engine[.]*"
* **[Startpage](https://www.startpage.com/)** - "*The world's most private search engine[.]*"
* **[UserSearch.org](https://usersearch.org/index.php)** - "*Find anyone online[.]*"

### Social Media And Trend Monitoring
The use of these tools, as well as the search engine listed above, is the conducting of open-source intelligence (OSINT) gathering. OSINT is (referring now to [Wikipedia](https://en.wikipedia.org/wiki/Open-source_intelligence)) a, "*...methodology for collecting, analyzing and making decisions about data accessible in publicly available sources to be used in an intelligence context.*" Which can be applicable to a personal context as well, simply by intending for it to.

Below you will find various Social Media and trend monitoring tools, organized by platform/type.

#### Facebook
* **[Lookup-ID.com](https://lookup-id.com/)** - "*...helps you to find the Facebook ID for your profile or a Group.*"

#### Forums
* **[Boardreader](https://boardreader.com/)** - "*Forum search engine[.]*"

#### General Purpose
* **[Hootsuite](https://hootsuite.com/)** - "*...manage all your social media and get results with Hootsuite.*"
* **[Social Mention](http://socialmention.com/)** - "*...a real time search platform[.]*"

#### Google
* **[Google Alerts](https://www.google.com/alerts)** - "*Monitor the web for interesting new content[.]*"
* **[Google Trends](https://trends.google.com/trends/)** - "*Explore what the world is searching[.]*"

#### Reddit
* **[Metrics For Reddit](https://frontpagemetrics.com/)** - "*...a tool for tracking statistics of 2,535,250 subreddits... ...and discovering the fastest growing communities on reddit.*"
* **[Reddit Insights](https://www.redditinsight.com/)** - "*...an analytics suite for Reddit.com using their public API, combined with real-time data analysis and graphic visualizations of historical data.*"
* **[Reddit Investigator](https://www.redditinvestigator.com/)** - "*...a new way to discover many things about redditors. It works just by collecting the data that reddit makes available and elaborates it to obtain some new useful infos.*"
* **[RedditMetis](https://redditmetis.com/)** - "*...a project inspired by u/orionmelt's site SnoopSnoo. Since May 2019, the site no longer updated user info due to an API error.*"
* **[Subreddit Stats](https://subredditstats.com/)** - "*...a bunch of different subreddit ranking lists. You can click a subreddit name to see stats (graphs, etc.) for that subreddit.*"

#### Twitter
* **[Followerwonk](https://followerwonk.com/)** - "*...for Twitter Analytics, Bio Search and more[.]*"
* **[OmniSci Tweetmap](https://www.omnisci.com/demos/tweetmap)** - "*Interactively explore millions of geo-located tweets.*" (Recommended)
* **[SocialBearing](https://socialbearing.com/)** - "*Find, filter and sort tweets or people by engagement, influence, location, sentiment and more[.]*" (Recommended)
* **[Trendsmap](https://www.trendsmap.com/)** - "*...the latest Twitter trending hashtags and topics from anywhere in the world. Click on a word, zoom into your area of interest, and explore.*" (Recommended)
* **[TweetDeck](https://tweetdeck.twitter.com/)** - "*...for real-time tracking, organizing, and engagement. Reach your audiences and discover the best of Twitter.*"
* **[TweeterID](https://tweeterid.com/)** - "*...allows you to easily look up any username (@handle) on Twitter and find out what their corresponding ID is.*"
* **[Twiangulate](http://twiangulate.com/search/)** - "*...analyzing the connections between friends...*"

#### YouTube
* **[Watch Frame By Frame](http://www.watchframebyframe.com/)** - "*Watch YouTube and Vimeo videos frame by frame and in slow motion[.]*"
* **[YouTube DataViewer](https://citizenevidence.amnestyusa.org/)** - "*Extract meta data[.]*"

### VPNs
A VPN or Virtual Private Network (according to [Wikipedia](https://en.wikipedia.org/wiki/Virtual_private_network)) allows a user to safely, "*...send and receive data across shared or public networks as if their computing devices were directly connected to the private network.*" All of which is accomplished with strong encryption.

* **[AirVPN](https://airvpn.org/)** - "*...based on OpenVPN and operated by activists and hacktivists in defence of net neutrality, privacy and against censorship.*" (Recommended)
* **[Mullvad VPN](https://mullvad.net/)** - "*Privacy is a universasl right[.]*"
* **[Private Internet Access](https://www.privateinternetaccess.com/)** - "*...is the leading VPN Service provider specializing in secure, encrypted VPN tunnels which create several layers of privacy and security providing you safety on the internet.*"
* **[ProtonVPN](https://protonvpn.com/)** - "*...is designed with security as the main focus, drawing upon the lessons we have learned from working with journalists and activists in the field.*"

### Web Services Account Deletion
Resources for helping Internet users permanently delete their accounts with various Web Service(s) providers, such as Google or Netflix.

* **[JustDeleteMe](https://justdeleteme.xyz/)** - "*A directory of direct links to delete your account from web services.*"

## Hybridization
Understanding what threat models are, or how to use certain tools is fine. But let's now look at the fusion of these two assets (threat models and digital technologies) into one approach, intended to create a hybrid model for practicing effective personal Internet security by the average person.

When first learning what threat models are or how to use different tools, it's important to step back and look at the bigger picture; as not only do these philosophies and technologies work, but they work better together.

## Conclusion
There are a healthy number of reliable techniques and dozens of powerful tools available to the averge person for staying safe, private and informed while Online. This document brings the best of them to you; the "tools most fit for the average person".

Over the coming months, the information and resources found herein will continue to grow; ideally becoming a first class resource for those interested in the serious topic of personal Online OpSec. Many thanks to those who have already suggested improvements to this project.
