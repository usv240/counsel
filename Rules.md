https://findevil.devpost.com/?ref_content=featured&ref_feature=challenge&ref_medium=portfolio&_gl=1*ki9bbn*_gcl_au*MTA4MDA5NjM4Mi4xNzc0MDI2MzM1*_ga*MTU4MjI1MDgwOC4xNzc0MDI2MzM2*_ga_0YHJK3Y10M*czE3ODAzNTIwMjgkbzE0MCRnMSR0MTc4MDM1MjAzNiRqNTIkbDAkaDA. 

Devpost
Join a hackathon 
Host a hackathon 
Resources 
 
ujwalsv
Notifications
Loading...

FIND EVIL!
Overview
My projects
Participants (3858)
Resources
Rules
Project gallery
Updates
Discussions
FIND EVIL!
AI threats strike in minutes. Build the defender that responds in seconds.
Start project
Find teammates
Import from portfolio
Who can participate
Above legal age of majority in country of residence
All countries/territories, excluding standard exceptions 
View full rules
14 more days to deadline
View schedule

Deadline

Jun 15, 2026 @ 11:45pm EDT 
Online
Public
$22,000 in cash	3858 participants
sans
Cybersecurity Machine Learning/AI Beginner Friendly

The Speed Problem

An AI-powered adversary can go from initial access to full domain control in under 8 minutes. CrowdStrike's fastest observed breakout time: 7 minutes. Horizon3's autonomous agent: 60 seconds to full privilege escalation. MIT's 2024 research: AI-driven attack workflows running 47 times faster than human operators.

Meanwhile, a human incident responder is still pulling up their toolkit.

That gap is the most dangerous problem in cybersecurity. Find Evil! challenges you to close it.

The Mission

You'll build autonomous AI agents on the SANS SIFT Workstation --- 200+ incident response tools on a single platform, 18 years of community development, 60K+ annual downloads. Protocol SIFT, the proof-of-concept framework that connects AI agents to those tools through Model Context Protocol (MCP).

Protocol SIFT works. It also hallucinates more than we'd like. (That's exactly why this hackathon exists.) Unlike offensive teams that operate with three or four people in secret, we're putting the entire practitioner community on this problem simultaneously. Your job: teach an AI agent to think like a senior analyst --- how to sequence its approach, recognize when something doesn't add up, and self-correct when it gets it wrong.

Who Should Join

You don't need to be an incident response expert. The SIFT Workstation handles the domain tooling. You need curiosity and building skills.

IR/Security professionals: You've been finding evil manually for years. Build the AI partner you wish you had at 3 AM during an active incident.
AI/ML engineers: Apply your skills to a domain where speed determines whether attackers win. Real case data, real tools, no toy datasets.
Students and early-career builders: No IR background required. The SIFT Workstation is your on-ramp to the most in-demand intersection in tech.
Open-source contributors: Every submission lives on as a community tool. Build something thousands of responders will use.
Four supported architectural approaches: Direct Agent Extension (Claude Code or OpenClaw), Custom MCP Server, Multi-Agent Frameworks (AutoGen, CrewAI, LangGraph), or Alternative Agentic IDEs (Cursor, Cline, Aider). Teams up to 5. Solo permitted. April 15 -- June 15, 2026. $22,000+ in prizes.

About the Challenge

Why this exists

In November 2025, Anthropic's security team published findings on GTG-1002 --- a Chinese state-sponsored operation where attackers used Claude Code to run autonomous reconnaissance, exploitation, and lateral movement at 80-90% autonomy. The AI handled everything at request rates Anthropic described as "physically impossible" for human operators.

That was the offensive side. The SIFT Workstation is the defensive platform. Protocol SIFT demonstrated what's possible when you connect AI agents to that platform through MCP. This hackathon is how the community makes it real.

The DFIR community built the SIFT Workstation 18 years ago to give every practitioner access to professional-grade tools. Find Evil! extends that mission: give every responder an AI co-pilot that can triage incidents at the speed adversaries now operate.

The gap we're closing

Manual command-line incident response cannot compete with autonomous agents executing thousands of requests. Adversaries move at machine speed. Defenders still look up command-line flags during active incidents. Your goal: build AI systems on the SIFT Workstation that match that velocity --- triaging, correlating, and reporting at the pace the threat demands.

This hackathon is how.

Get Started

Register on Devpost (you're here)
Join the Protocol SIFT Slack  --- this is where questions get answered, teams form, and mentors hang out - 
Download the SIFT Workstation from sans.org/tools/sift-workstation
Install Protocol SIFT Package to demonstrate automated analysis, To install Protocol SIFT, after you download SIFT OVA, and login, run this command from your terminal:: $ curl -fsSL https://raw.githubusercontent.com/teamdfir/protocol-sift/main/install.sh | bash
Review the starter resources: sample case data (hard drives, memory images), example submission.
Pick a problem and start building. See "What to Build" for project ideas and supported architectural approaches to get past the blank-screen problem.
Requirements
What to Build

One goal: Make Protocol SIFT a fully autonomous incident response agent.

Your submission must improve how Protocol SIFT processes case data --- any case data. Disk images, memory captures, remote endpoints via MCP, log files, network captures. The data type doesn't define the track. The quality of autonomous execution does.

Teach the agent how a senior analyst thinks. How they sequence their approach. How they recognize when something doesn't add up. How they adjust.

Supported Architectural Approaches

You can build on any of these patterns. The platform matters less than how your architecture enforces evidence integrity and enables genuine self-correction.

1. Direct Agent Extension (Claude Code / OpenClaw) --- Extend Protocol SIFT's existing agent loop. Better prompt engineering, smarter tool sequencing, self-correction routines, accuracy validation. This is the on-ramp for most participants and the fastest path to a working submission. OpenClaw's extensible architecture also makes it a natural fit for building custom MCP tool wrappers directly into the tool chain.

2. Custom MCP Server --- Build a purpose-built MCP server that exposes structured functions instead of generic shell commands. Instead of giving the AI execute_shell_cmd, expose typed functions like get_amcache(), extract_mft_timeline(), analyze_prefetch(). The agent physically cannot run destructive commands because the server doesn't have those tools. The MCP server handles raw tool output natively and can parse it before returning to the LLM, preventing context window overload from massive text dumps. (This is the most sound architecture in the evaluation. It's also the most work.)

3. Multi-Agent Frameworks (AutoGen, CrewAI, LangGraph) --- Decompose the analysis into specialized, communicating agents. One agent reviews memory artifacts, another parses disk timelines, a third synthesizes findings. No single model holds all raw data in its context window, which prevents context degradation on complex cases. Agent-to-agent communication is logged programmatically with timestamps and token usage, creating structured execution records. Warning: agent loops can get stuck in infinite conversational spirals without careful termination conditions. Build in max-iteration caps and graceful degradation.

4. Alternative Agentic IDEs (Cursor, Cline, Aider) --- AI-native development environments with their own rule systems. Excellent UI/UX and built-in diff viewing, but designed for software development, not incident response. These tools rely on prompt adherence for evidence protection, not architectural enforcement. If your submission uses an alternative IDE, your accuracy report must document what happens when the model ignores read-only rules.

(If another agentic framework can do the job, we won't disqualify it. But Claude Code, OpenClaw, and the four approaches above are the primary targets. Build for those.)

Starter Ideas (Not Prescriptions)

Two months is enough time to build something real, but the hardest part is always the first hour. These are starting points. The best submissions will go beyond these in directions we haven't considered.

1. The Self-Correcting Triage Agent --- Build an agent that runs initial triage on a disk image, evaluates its own output for logical consistency, identifies gaps in its analysis, and autonomously re-runs with adjusted parameters. Success metric: fewer hallucinated findings than Protocol SIFT's current baseline.

2.  Multi-Source Correlation Engine --- Given a disk image and a memory capture from the same system, build an agent that cross-references findings between the two sources and flags discrepancies. If the disk timeline says one thing and memory says another, the agent should catch it.

3. MCP-Connected Live Triage --- Build an MCP server that connects Protocol SIFT to a remote endpoint or SIEM, then create an agent workflow that pulls live data, analyzes it against SIFT's tool library, and produces a real-time triage report.

4.  The Analyst Training Loop --- Build an agent that not only analyzes case data but explains its reasoning at each step --- which tool it chose, why, what it expected to find, and what it actually found. Designed to train junior analysts by making the agent's decision-making process transparent.

5.  Accuracy Benchmarking Framework --- Create a test harness that runs Protocol SIFT against known-good data with documented ground truth, then scores accuracy, false positive rates, and hallucination frequency. The community needs this benchmark to measure progress.

6.   The Purpose-Built MCP Server --- Wrap SIFT's 200+ tools as structured, type-safe functions exposed through a custom MCP server. The agent physically cannot run destructive commands because the server doesn't expose them. Success metric: zero evidence spoliation risk, with the same or better analytical output as the baseline Protocol SIFT agent. (This is the architecture that would make a practitioner comfortable standing behind the results.)

7. The Persistent Learning Loop --- Build a self-correcting execution loop that iterates on a task until verifiable success criteria are met. The agent logs failures to a progress file, learns from its own execution traces across iterations, and course-corrects without human intervention. Must include a hard --max-iterations cap to prevent runaway execution. Success metric: demonstrable improvement in accuracy between first iteration and final iteration on the same data, with full execution traces preserved.

(These are meant to get past the blank-screen problem. The winning submission will almost certainly be something none of us predicted.)

What to Submit

All eight components required. Missing any one means elimination.

1.  Code Repository --- GitHub (public). Open-source license (MIT or Apache 2.0).

2.  Demo Video (5 min max) --- Screencast of live terminal execution with audio narration. Show the agent working against real case data, including at least one self-correction sequence.

3.  Architecture Diagram --- How components connect: the agent, SIFT tools, MCP servers, data sources, output pipeline. Your diagram must identify which architectural pattern you're using and document where security boundaries are enforced. Prompt-based guardrails and architectural guardrails must be clearly distinguished. Judges need to understand your system and its trust boundaries at a glance.

4.  Written Project Description --- Devpost project story format: What it does, How you built it, Challenges, What you learned, What's next. Be specific about design decisions, tradeoffs, and which qualities of autonomous execution your submission addresses.

5.  Dataset Documentation --- What the agent was tested against, source of data, and what it found. Reproducibility starts here.

6.  Accuracy Report --- Self-assessment of findings accuracy. False positives, missed artifacts, hallucinated claims. Include a section documenting your evidence integrity approach: how does your architecture prevent original data from being modified? If you're using prompt-based restrictions rather than architectural enforcement, document what happens when the model ignores the restriction. Did you test for spoliation? (If you found failure modes, document them. That's signal, not weakness.)

7.  Try-It-Out Instructions --- Live deployment URL or step-by-step instructions for judges to run your agent locally on the downloadable SIFT workstation. If local setup requires specific tools or dependencies, document them clearly in the README.

8.  Agent Execution Logs --- Structured logs showing the full agent communication and tool execution sequence. For multi-agent submissions: agent-to-agent message logs with timestamps. For single-agent submissions: tool execution logs with timestamps and token usage. For persistent loop submissions: iteration-over-iteration traces showing how the agent's approach changed. Judges must be able to trace any finding back to the specific tool execution that produced it.

Prizes
$22,000 in prizes
1st Place - SLAYED EVIL
$10,000 in cash
1 winner
SANS Summit pass + hotel (each member) + SANS OnDemand course (each member)

Presentation on SANS Webcast/Livestream broadcast to the SANS Community

2nd Place - HUNTED EVIL
$7,500 in cash
1 winner
SANS Summit pass + hotel (each member) + SANS OnDemand course (each member)

Presentation on SANS Webcast/Livestream broadcast to the SANS Community

3rd Place - FOUND EVIL
$4,500 in cash
1 winner
SANS OnDemand course (each member)

Devpost Achievements
Submitting to this hackathon could earn you:


X Hackathons
 level 5

Hackathon Winner
 level 2
Judges
Rob T. Lee
Rob T. Lee
CAIO, SANS INSTITUTE

Ahmed AbuGharbia
Ahmed AbuGharbia
Founder, cyberdojo.ai

Brad Edwards
Brad Edwards
Domain Consultant SecOps, Palo Alto Networks

Teri Green
Teri Green
VP of Technology, Elevate

Yevhen Pervushyn
Yevhen Pervushyn
Founder & Adversarial AI Security Researcher, Red Asgard

Harish Vundavalli
Harish Vundavalli
Sr. Technical Architect, Strategic Education INC

Nimitt Jhaveri
Nimitt Jhaveri
CEO, BitScore Cybertech LLP

Narrayanan MKL
Narrayanan MKL
VP Cyber Defence, Standard Chartered Bank

Roshan Varghese
Roshan Varghese
Sr. Information Security Manager, Incident Response

Jens Ernstberger
Jens Ernstberger
Security Researcher, Kontext Security

Jeroen Hoof
Jeroen Hoof
Freelance Lead Analyst, SANS Instructor

Sneha Parmar
Sneha Parmar
Director EDR, Deutsche Bank

Nodirjon Umurkulov
Nodirjon Umurkulov
Security Researcher/Engineer

Pedro Jimenez Argente del Castillo
Pedro Jimenez Argente del Castillo
SOC Chapter Lead, ING Hubs Spain

Michael Barclay
Michael Barclay
Principal Security Researcher, Origin Security

Ovie Carroll
Ovie Carroll
Director DOJ Cybercrime Lab

Joshua McCray
Joshua McCray
Sr. Lead Cyber Security Analyst, Hilton

Cheri Carr
Cheri Carr
Principal Consultant & Owner, Aspen Forensics

Kellep Charles
Kellep Charles
Cybersecurity Chair, Capitol Technology University

Dorian Oliver Collier
Dorian Oliver Collier
National CSIRT Lead & DFIR Specialist

Brett Cumming
Brett Cumming
CISO, Skechers

Yotam Perkal
Yotam Perkal
Director Security Research, Pluto Security

Marc Brawner
Marc Brawner
Managing Partner, Auxiris

Adam Nasreldin
Adam Nasreldin
Senior IR Consultant, Google Mandiant

Georgios Kapoglis
Georgios Kapoglis
Staff Detection & Response Engineer, Roblox

Steve Cobb
Steve Cobb
CISO, SecurityScorecard

Maximilian Gutowski
Maximilian Gutowski
Head of Threat Detection & Response, Deutsche Telekom Security

John Wilson
John Wilson
CISO & President of Forensics, HaystackID

Jason Garman
Jason Garman
Principal Security Specialist, AWS

Richard Nathan Smith
Richard Nathan Smith
Enterprise Architect

Saurabh Naik
Saurabh Naik
Head of Red Team, Lockheed Martin

Dr. Stephen Coston
Dr. Stephen Coston
Lead Security Architect AI and Cybersecurity

Mathieu Alcaina
Mathieu Alcaina
SOC L3 / DFIR Analyst, Onepoint

Monish Alur Gowdru
Monish Alur Gowdru
Technical Security Lead, UltraViolet Cyber

Jon Stewart
Jon Stewart
Managing Director, LevelBlue

Sumit Ranjan
Sumit Ranjan
AI Security Advisor & Ex CTO

Amanda Rankhorn
Amanda Rankhorn
FBI Special Agent/Senior Forensics Examiner (Retired)

Khushi Gupta, Ph.D.
Khushi Gupta, Ph.D.
Asst. Professor of Cybersecurity, University of North Georgia

Preston Fitzgerald
Preston Fitzgerald
Cybersecurity SME, SANS Institute

Muhammad Shera
Muhammad Shera
DFIR Consultant

Sandeep Bachhas
Sandeep Bachhas
Sr. Manager, Cyber Threat Hunting

Judging Criteria
1. Autonomous Execution Quality (tiebreaker)
Does the agent reason about next steps, handle failures, and self-correct in real time?
2. IR Accuracy
Are findings correct? Hallucinations caught and flagged? Confirmed findings distinguished from inferences?
3. Breadth and Depth of Analysis
How much case data can the agent handle? Depth on fewer types beats shallow coverage of many.
4. Constraint Implementation
Are guardrails architectural or prompt-based? Judges evaluate where security boundaries are enforced and whether they were tested for bypass.
5. Audit Trail Quality
Can judges trace any finding back to the specific tool execution that produced it?
6. Usability and Documentation
Can another practitioner deploy and build on this?
To-dos
 Join the Slack

 Dismiss

Download SIFT Workstation

 Dismiss

Download Example Compromised System Data

 Dismiss

Review NotebookLM for Questions and on How to Begin your Build

 Dismiss

You're registered for this hackathon.

Unregister  Edit registration questions 
Questions? Email the hackathon manager

Hackathon sponsors
SANS Institute
This site is protected by reCAPTCHA and the Google Privacy Policy and Terms of Service apply.

Devpost
About
Careers
Contact
Help
Hackathons
Browse hackathons
Explore projects
Host a hackathon
Hackathon guides
Portfolio
Your projects
Your hackathons
Settings
Connect
 Twitter
 Discord
 Facebook
 LinkedIn
© 2026 Devpost, Inc. All rights reserved.
Community guidelines
Security
CA notice
Privacy policy
Terms of service


----------------------------------------------------------

https://findevil.devpost.com/rules 

Devpost
Join a hackathon 
Host a hackathon 
Resources 
 
ujwalsv
Notifications
Loading...

FIND EVIL!
Overview
My projects
Participants (3858)
Resources
Rules
Project gallery
Updates
Discussions
FIND EVIL! (the “Hackathon”) Official Rules
NO PURCHASE OR PAYMENT NECESSARY TO ENTER OR WIN. A PURCHASE OR PAYMENT WILL NOT INCREASE YOUR CHANCES OF WINNING. 

SUBMISSION OF ANY ENTRY CONSTITUTES AGREEMENT TO THESE OFFICIAL RULES AS A CONTRACT BETWEEN ENTRANT (AND EACH INDIVIDUAL MEMBER OF ENTRANT), THE HACKATHON SPONSOR, AND DEVPOST.

1. Dates and Timing
Submission Period: Apr 15, 2026 12:00 PM EDT  – Jun 15, 2026 11:45 PM EDT (“Submission Period”).

Judging Period:  Jun 19, 2026 12:00 AM EDT  –  Jul 3, 2026 12:00 AM EDT(“Judging Period”).

Winners Announced: On or around Jul 8, 2026 12:00 PM EDT.

2. Sponsor and Administrator
Sponsor and Administrator: SANS Institute 495 Lowell St, Lexington, MA 02420

3. Eligibility
The Hackathon IS open to: 

Individuals who are at least the age of majority where they reside as of the time of entry (“Eligible Individuals”);
Teams of up to 5 Eligible Individuals (“Teams”); and
Organizations (including corporations, not-for-profit corporations and other nonprofit organizations, limited liability companies, partnerships, and other legal entities) that exist and have been organized or incorporated at the time of entry.
(the above are collectively, “Entrants”)
An Eligible Individual may join more than one Team or Organization and an Eligible Individual who is part of a Team or Organization may also enter the Hackathon on an individual basis. If a Team or Organization is entering the Hackathon, they must appoint and authorize one individual (the “Representative”) to represent, act, and enter a Submission, on their behalf. By entering a Submission on behalf of a Team or Organization you represent and warrant that you are the Representative authorized to act on behalf of your Team or Organization.

The Hackathon IS NOT open to: 

Individuals who are residents of, or Organizations domiciled in, a country, state, province or territory where the laws of the United States or local law prohibits participating or receiving a prize in the Hackathon (including, but not limited to, Brazil, Quebec, Russia, Crimea, Cuba, Iran, and North Korea and any other country designated by the United States Treasury's Office of Foreign Assets Control) 
Organizations involved with the design, production, paid promotion, execution, or distribution of the Hackathon, including the Sponsor, and Administrator (“Promotion Entities”).
Employees, representatives and agents** of such Promotion Entities, and all members of their immediate family or household*
Any other individual involved with the design, production, promotion, execution, or distribution of the Hackathon, and each member of their immediate family or household*
Any Judge (defined below), or company or individual that employs a Judge
Any parent company, subsidiary, or other affiliate*** of any organization described above
Any other individual or organization whose participation in the Hackathon would create, in the sole discretion of the Sponsor and/or Administrator, a real or apparent conflict of interest 
*The members of an individual’s immediate family include the individual’s spouse, children and stepchildren, parents and stepparents, and siblings and stepsiblings. The members of an individual’s household include any other person that shares the same residence as the individual for at least three (3) months out of the year. 

**Agents include individuals or organizations that in creating a Submission to the Hackathon, are acting on behalf of, and at the direction of, a Promotion Entity through a contractual or similar relationship.

***An affiliate is: (a) an organization that is under common control, sharing a common majority or controlling owner, or common management; or (b) an organization that has a substantial ownership in, or is substantially owned by the other organization.

4. How To Enter 
Entrants may enter by visiting findevil.devpost.com (“Hackathon Website”) and following the below steps:

Register for the Hackathon on the Hackathon Website by clicking the “Join Hackathon” button. To complete registration, sign up to create a free Devpost account, or log in with an existing Devpost account. This will enable you to receive important updates and to create your Submission.
Entrants will obtain access to the required developer tools/platform and complete a Project described below in Project Requirements. Use of the developer tools will be subject to the license agreement related thereto. Entry in the Hackathon constitutes consent for the Sponsor and Devpost to collect and maintain an entrant’s personal information for the purpose of operating and publicizing the Hackathon.
The SANS SIFT Workstation is available at https://github.com/sans-dfir/sift. Starter evidence datasets, a practice MCP server endpoint, and sample code will be provided on the Protocol SIFT Slack server at launch.
Complete and enter all of the required fields on the “Enter a Submission” page of the Hackathon Website (each a “Submission”) during the Submission Period and follow the requirements below.
Project Requirements

What to Create: Entrants must submit a working software application ("Project") that extends Protocol SIFT's autonomous incident response capability using an agentic framework as the primary execution engine. Claude Code and OpenClaw are the preferred frameworks, though comparable agentic architectures are permitted. Projects may operate on any supported case data type, including disk images, memory captures, log files, network captures, and remote endpoints via MCP.
Each Project must demonstrate all of the following:
Self-correction — the agent detects and resolves errors or inconsistencies in its own output without human intervention.
Accuracy validation — all findings are traceable to specific artifacts, files, offsets, or log entries.
Analytical reasoning — output is presented as a structured investigative narrative, not a raw execution log.
Functionality: The Project must be capable of being successfully installed and running consistently on the platform for which it is intended and must function as depicted in the video and/or expressed in the text description.
Platforms: Projects must be built on Linux terminal / SIFT Workstation environment. Projects must run on or integrate with the SANS SIFT Workstation using Claude Code or OpenClaw as the agentic framework. 
New & Existing: Projects must be substantially new work created during the hackathon period (April 15 -- June 15, 2026). Teams may use pre-existing open-source libraries, frameworks, and the existing SIFT codebase as a foundation. The novel contribution must be clearly documented.
Third Party Integrations: If a Project integrates any third-party SDK, APIs and/or data, Entrant must be authorized to use them in accordance with any terms and conditions or licensing requirements of the tool.
Submission Requirements 

Submissions to the Hackathon must meet the following requirements:

Include a Project built with the required developer tools and meets the above Project Requirements.
Provide a URL to your code repository for judging and testing. The repository must contain all necessary source code, assets, and instructions required for the project to be functional. 
The repository must be public and open source by including an MIT or Apache 2.0 open source license file. This license should be detectable and visible at the top of the repository page (in the About section).  
The repository must contain a README with setup instructions.
Include either a live deployment URL or step-by-step instructions that let judges run your agent locally against provided evidence. If local setup requires specific tools or dependencies, document them clearly in the README.
Include a text description that should explain the features and functionality of your Project.
Include a demonstration video of your Project. The video portion of the Submission:
should be less than five (5) minutes. Judges are not required to watch beyond ten minutes 
should include a screencast of live terminal execution with audio narration. Not slides. Not marketing videos. Show the agent working against real evidence, including at least one self-correction sequence.
must be uploaded to and made publicly visible on YouTube, Vimeo, or Youku, and a link to the video must be provided on the submission form on the Hackathon Website; and
must not include third party trademarks, or copyrighted music or other material unless the Entrant has permission to use such material.
Include an Architecture Diagram -- A clear visual showing how components connect -- the agent, SIFT tools, MCP servers, evidence sources, output pipeline.
Include Evidence Dataset Documentation -- What the agent was tested against, source of the data, and what the agent found.
Include an Accuracy Report -- Self-assessment of findings accuracy. False positives, missed artifacts, hallucinated claims identified during testing. Honesty valued over perfection.
Include Agent Execution Logs – Structured logs showing the full agent communication and tool execution sequence. For multi-agent submissions: agent-to-agent message logs with timestamps. For single-agent submissions: tool execution logs with timestamps and token usage. For persistent loop submissions: iteration-over-iteration traces showing how the agent's approach changed. Judges must be able to trace any finding back to the specific tool execution that produced it.
Multiple Submissions 

An Entrant may submit more than one Submission, however, each Submission must be unique and substantially different from each of the Entrant’s other Submissions, as determined by the Sponsor and Devpost in their sole discretion.

Submission ownership

Be the original work of the Entrant, be solely owned by the Entrant, and not violate the IP rights of any other person or entity.

Testing 

Access must be provided to an Entrant’s working Project for judging and testing by providing a link to a website, functioning demo, or a test build. If Entrant’s website is private, Entrant must include login credentials in its testing instructions. The Entrant must make the Project available free of charge and without any restriction, for testing, evaluation and use by the Sponsor, Administrator and Judges until the Judging Period ends. Judges are not required to test the Project and may choose to judge based solely on the text description, images, and video provided in the Submission.

If the Project includes software that runs on proprietary or third party hardware that is not widely available to the public, including software running on devices or wearable technology other than smartphones, tablets, or desktop computers, the Sponsor and/or Administrator reserve the right, at their sole discretion, to require the Entrant to provide physical access to the Project hardware upon request.  

Language Requirements

All Submission materials must be in English or, if not in English, the Entrant must provide an English translation of the demonstration video, text description, and testing instructions as well as all other materials submitted. 

Team Representation

If a team or organization is entering the Hackathon, they must appoint and authorize one individual (the “Representative”) to represent, act, and enter a Submission, on their behalf. The Representative must meet the eligibility requirements above. By entering a Submission on the Hackathon Website on behalf of a team or organization you represent and warrant that you are the Representative authorized to act on behalf of your team or organization.

Intellectual Property 

Your Submission must: (a) be your (or your Team, or Organization’s) original work product; (b) be solely owned by you, your Team, your Organization with no other person or entity having any right or interest in it; and (c) not violate the intellectual property rights or other rights including but not limited to copyright, trademark, patent, contract, and/or privacy rights, of any other person or entity. An Entrant may contract with a third party for technical assistance to create the Submission provided the Submission components are solely the Entrant’s work product and the result of the Entrant’s ideas and creativity, and the Entrant owns all rights to them. An Entrant may submit a Submission that includes the use of open source software or hardware, provided the Entrant complies with applicable open source licenses and, as part of the Submission, creates software that enhances and builds upon the features and functionality included in the underlying open source product. By entering the Hackathon, you represent, warrant, and agree that your Submission meets these requirements.

Financial or Preferential Support 

A Project must not have been developed, or derived from a Project developed, with financial or preferential support from the Sponsor or Administrator. Such Projects include, but are not limited to, those that received funding or investment for their development, were developed under contract, or received a commercial license, from the Sponsor or Administrator any time prior to the end of Hackathon Submission Period. The Sponsor, at their sole discretion, may disqualify a Project, if awarding a prize to the Project would create a real or apparent conflict of interest.

5. Submission Modifications
Draft Submissions 

Prior to the end of the Submission Period, you may save draft versions of your submission on Devpost to your portfolio before submitting the Submission materials to the Hackathon for evaluation. Once the Submission Period has ended, you may not make any changes or alterations to your Submission, but you may continue to update the Project in your Devpost portfolio.

Modifications After the Submission Period

The Sponsor and Devpost may permit you to modify part of your Submission after the Submission Period for the purpose of adding, removing or replacing material that potentially infringes a third party mark or right, discloses personally identifiable information, or is otherwise inappropriate. The modified Submission must remain substantively the same as the original Submission with the only modification being what the Sponsor and Devpost permits. 

6. Judges & Criteria
Eligible submissions will be evaluated by a panel of judges selected by the Sponsor (the “Judges”). Judges may be employees of the sponsor or third parties, may or may not be listed individually on the Hackathon Website, and may change before or during the Judging Period. Judging may take place in one or more rounds with one or more panels of Judges, at the discretion of the sponsor. 

Stage One) The first stage will determine via pass/fail whether the ideas meet a baseline level of viability, in that the Project reasonably fits the theme and reasonably applies the required APIs/SDKs featured in the Hackathon.

Stage Two) All Submissions that pass Stage One will be evaluated in Stage Two based on the following equally weighted criteria (the “Judging Criteria”):

Entries will be judged on the following equally weighted criteria, and according to the sole and absolute discretion of the judges:

Autonomous Execution Quality
Does the agent reason about next steps, handle failures, and self-correct in real time?
IR Accuracy
Are findings correct? Hallucinations caught and flagged? Confirmed findings distinguished from inferences?
Breadth and Depth of Analysis
How much case data can the agent handle? Depth on fewer types beats shallow coverage of many.
Constraint Implementation
Are guardrails architectural or prompt-based? Judges evaluate where security boundaries are enforced and whether they were tested for bypass.
Audit Trail Quality
Can judges trace any finding back to the specific tool execution that produced it?
Usability and Documentation
Can another practitioner deploy and build on this?
The scores from the Judges will determine the potential winners of the applicable prizes. The Entrant(s) that are eligible for a Prize, and whose Submissions earn the highest overall scores based on the applicable Judging Criteria, will become potential winners of that Prize.

Tie Breaking 

For each Prize listed below, if two or more Submissions are tied, the tied Submission with the highest score in the first applicable criterion listed above will be considered the higher scoring Submission. In the event any ties remain, this process will be repeated, as needed, by comparing the tied Submissions’ scores on the next applicable criterion. If two or more Submissions are tied on all applicable criteria, the panel of Judges will vote on the tied Submissions.

7. Intellectual Property Rights
All Submissions remain the intellectual property of the individuals or organizations that developed them. By submitting an entry, entrants agree that the Sponsor will have a non-exclusive license to use such entry for judging the entry. Entrants agree that the sponsor and Devpost shall have the right to promote the Submission and use the name, likeness, voice and image of all individuals contributing to a Submission, in any materials promoting or publicizing the Hackathon and its results, during the Hackathon Period and for three years thereafter.  Some Submission components may be displayed to the public. Other Submission materials may be viewed by the sponsor, Devpost, and judges for screening and evaluation. By submitting an entry or accepting any prize, entrants represent and warrant that (a) submitted content is not copyrighted, protected by trade secret or otherwise subject to third party intellectual property rights or other proprietary rights, including privacy and publicity rights, unless entrant is the owner of such rights or has permission from their rightful owner to post the content; and (b) the content submitted does not contain any viruses, Trojan horses, worms, spyware or other disabling devices or harmful or malicious code.


8. Prizes

Winner

Prize

Qty

Eligible Submissions 

Judging Criteria

1st Place - SLAYED EVIL

$10,000 cash

SANS Summit pass + hotel covered for each team member at any upcoming SANS Summit in the next 12 months.

One SANS OnDemand course per team member (to be used within 12 months)

Presentation on SANS Webcast/Livestream broadcast to the SANS Community

1

All eligible submissions

All judging criteria

2nd Place - HUNTED EVIL

$7,500 cash

SANS Summit pass + hotel covered for each team member at any upcoming SANS Summit in the next 12 months.

One SANS OnDemand course per team member (to be used within 12 months)

Presentation on SANS Webcast/Livestream broadcast to the SANS Community

1

All eligible submissions

All judging criteria

3rd Place - FOUND EVIL

$4,500 cash

One SANS OnDemand course per team member (to be used within 12 months)

1

All eligible submissions

All judging criteria

IMPORTANT NOTES ON MULTIPLE PRIZE ELIGIBILITY:

Each Project is eligible to receive a maximum of one (1) prize.

Substitutions & Changes: Prizes are non-transferable by the winner. Sponsor in its sole discretion has the right to make a prize substitution of equivalent or greater value. Sponsor will not award a prize if there are no eligible Submissions entered in the Hackathon, or if there are no eligible Entrants or Submissions for a specific prize.
Verification Requirement: THE AWARD OF A PRIZE TO A POTENTIAL WINNER IS SUBJECT TO VERIFICATION OF THE IDENTITY, QUALIFICATIONS AND ROLE OF THE POTENTIAL WINNER IN THE CREATION OF THE SUBMISSION. No Submission or Entrant shall be deemed a winning Submission or winner until their post-competition prize affidavits have been completed and verified, even if prospective winners have been announced verbally or on the competition website. The final decision to designate a winner shall be made by the Sponsor and/or Administrator. 
Prize Delivery: Prizes will be payable to the Entrant, if an individual; to the Entrant’s Representative, if a Team; or to the Organization, if the Entrant is an Organization. It will be the responsibility of the winning Entrant’s Representative to allocate the Prize among their Team or Organization’s participating members, as the Representative deems appropriate. A monetary Prize will be mailed to the winning Entrant’s address (if an individual) or the Representative’s address (if a Team or Organization), or sent electronically to the Entrant, Entrant’s Representative, or Organization’s bank account, only after receipt of the completed winner affidavit and other required forms (collectively the “Required Forms”), if applicable. The deadline for returning the Required Forms to the Administrator is ten (10) business days after the Required Forms are sent. Failure to provide correct information on the Required Forms, or other correct information required for the delivery of a Prize, may result in delayed Prize delivery, disqualification of the Entrant, or forfeiture of a Prize. Prizes will be delivered within 60 days of the Sponsor or Devpost’s receipt of the completed Required Forms.
Fees & Taxes: Winners (and in the case of Team or Organization, all participating members) are responsible for any fees associated with receiving or using a prize, including but not limited to, wiring fees or currency exchange fees. Winners (and in the case of Team or Organization, all participating members) are responsible for reporting and paying all applicable taxes in their jurisdiction of residence (federal, state/provincial/territorial and local). Winners may be required to provide certain information to facilitate receipt of the award, including completing and submitting any tax or other forms necessary for compliance with applicable withholding and reporting requirements. United States residents may be required to provide a completed form W-9 and residents of other countries may be required to provide a completed W-8BEN form. Winners are also responsible for complying with foreign exchange and banking regulations in their respective jurisdictions and reporting the receipt of the Prize to relevant government departments/agencies, if necessary. The Sponsor, Devpost, and/or Prize provider reserves the right to withhold a portion of the prize amount to comply with the tax laws of the United States or other Sponsor jurisdiction, or those of a winner’s jurisdiction.
9. Entry Conditions and Release
A.  By entering the Hackathon, you (and, if you are entering on behalf of a Team, Organization each participating members) agree(s) to the following:

The relationship between you, the Entrant, and the Sponsor and Administrator, is not a confidential, fiduciary, or other special relationship.
You will be bound by and comply with these Official Rules and the decisions of the Sponsor, Administrator, and/or the Hackathon Judges which are binding and final in all matters relating to the Hackathon.
You release, indemnify, defend and hold harmless the Promotion Entities, and their respective parent, subsidiary, and affiliated companies, the Prize suppliers and any other organizations responsible for sponsoring, fulfilling, administering, advertising or promoting the Hackathon, and all of their respective past and present officers, directors, employees, agents and representatives (hereafter the “Released Parties”) from and against any and all claims, expenses, and liabilities (including reasonable attorneys’ fees), including but not limited to negligence and damages of any kind to persons and property, defamation, slander, libel, violation of right of publicity, infringement of trademark, copyright or other intellectual property rights, property damage, or death or personal injury arising out of or relating to a Entrant’s entry, creation of Submission or entry of a Submission, participation in the Hackathon, acceptance or use or misuse of the Prize (including any travel or activity related thereto) and/or the broadcast, transmission, performance, exploitation or use of the Submission as authorized or licensed by these Official Rules. 
B.  Without limiting the foregoing, the Released Parties shall have no liability in connection with: 

Any incorrect or inaccurate information, whether caused by the Sponsor or Administrator’s electronic or printing error, or by any of the equipment or programming associated with or utilized in the Hackathon; 
Technical failures of any kind, including, but not limited to malfunctions, interruptions, or disconnections in phone lines, internet connectivity or electronic transmission errors, or network hardware or software or failure of the Hackathon Website;
Unauthorized human intervention in any part of the entry process or the Hackathon; 
Technical or human error which may occur in the administration of the Hackathon or the processing of Submissions; or 
Any injury or damage to persons or property which may be caused, directly or indirectly, in whole or in part, from the Entrant’s participation in the Hackathon or receipt or use or misuse of any Prize.
The Released Parties are not responsible for incomplete, late, misdirected, damaged, lost, illegible, or incomprehensible Submissions or for address or email address changes of the Entrants. Proof of sending or submitting the aforementioned will not be deemed to be proof of receipt by the Sponsor or Administrator. If for any reason any Entrant’s Submission is determined to have not been received or been erroneously deleted, lost, or otherwise destroyed or corrupted, the Entrant’s sole remedy is to request the opportunity to resubmit its Submission. Such a request must be made promptly after the Entrant knows or should have known there was a problem and will be determined at the sole discretion of the Sponsor.

10. Publicity
By participating in the Hackathon, Entrant consents to the promotion and display of the Entrant’s Submission, and to the use of personal information about themselves for promotional purposes, by the Sponsor, Administrator, and third parties acting on their behalf. Such personal information includes, but is not limited to, your name, likeness, photograph, voice, opinions, comments and hometown and country of residence. It may be used in any existing or newly created media, worldwide without further payment or consideration or right of review, unless prohibited by law. Authorized use includes but is not limited to advertising and promotional purposes. 

11. General Conditions 
Sponsor and Administrator reserve the right, in their sole discretion, to cancel, suspend and/or modify the Hackathon, or any part of it, in the event of a technical failure, fraud, or any other factor or event that was not anticipated or is not within their control.
Sponsor and Administrator reserve the right in their sole discretion to disqualify any individual or Entrant if it finds to be actually or presenting the appearance of tampering with the entry process or the operation of the Hackathon or to be acting in violation of these Official Rules or in a manner that is inappropriate, unsportsmanlike, not in the best interests of this Hackathon, or a violation of any applicable law or regulation.
Any attempt by any person to undermine the proper conduct of the Hackathon may be a violation of criminal and civil law. Should the Sponsor or Administrator suspect that such an attempt has been made or is threatened, they reserve the right to take appropriate action including but not limited to requiring an Entrant to cooperate with an investigation and referral to criminal and civil law enforcement authorities.
If there is any discrepancy or inconsistency between the terms and conditions of the Official Rules and disclosures or other statements contained in any Hackathon materials, including but not limited to the Hackathon Submission form, Hackathon Website, or advertising, the terms and conditions of the Official Rules shall prevail.
The terms and conditions of the Official Rules are subject to change at any time, including the rights or obligations of the Entrant, the Sponsor and Administrator. The Sponsor and Administrator will post the terms and conditions of the amended Official Rules on the Hackathon Website. To the fullest extent permitted by law, any amendment will become effective at the time specified in the posting of the amended Official Rules or, if no time is specified, the time of posting.
If at any time prior to the deadline, an Entrant or prospective Entrant believes that any term in the Official Rules is or may be ambiguous, they must submit a written request for clarification. 
The Sponsor or Administrator’s failure to enforce any term of these Official Rules shall not constitute a waiver of that provision. Should any provision of these Official Rules be or become illegal or unenforceable in any jurisdiction whose laws or regulations may apply to an Entrant, such illegality or unenforceability shall leave the remainder of these Official Rules, including the Rule affected, to the fullest extent permitted by law, unaffected and valid. The illegal or unenforceable provision shall be replaced by a valid and enforceable provision that comes closest and best reflects the Sponsor’s intention in a legal and enforceable manner with respect to the invalid or unenforceable provision.
Excluding Submissions, all intellectual property related to this Hackathon, including but not limited to copyrighted material, trademarks, trade-names, logos, designs, promotional materials, web pages, source codes, drawings, illustrations, slogans and representations are owned or used under license by the Sponsor and/or Administrator. All rights are reserved. Unauthorized copying or use of any copyrighted material or intellectual property without the express written consent of its owners is strictly prohibited. Any use in a Submission of Sponsor or Administrator’s intellectual property shall be solely to the extent provided for in these Official Rules.
12. Limitations of Liability
By entering, all Entrants (including, in the case of a Team or Organization, all participating members) agree to release the Released Parties from any and all liability in connection with the Prizes or Entrant’s participation in the Hackathon. Provided, however, that any liability limitation regarding gross negligence or intentional acts, or events of death or body injury shall not be applicable in jurisdictions where such limitation is not legal.

13. Disputes
A.  Except where prohibited by law, as a condition of participating in this Hackathon, Entrant agrees that:

Any and all disputes and causes of action arising out of or connected with this Hackathon, or any Prizes awarded, shall be resolved individually, without resort to any form of class action lawsuit, and exclusively by final and binding arbitration under the rules of the American Arbitration Association and held at the AAA regional office nearest the contestant;
The Federal Arbitration Act shall govern the interpretation, enforcement and all proceedings at such arbitration; and
Judgment upon such arbitration award may be entered in any court having jurisdiction.
B.  Under no circumstances will Entrant be permitted to obtain awards for, and Entrant hereby waives all rights to claim, punitive, incidental or consequential damages, or any other damages, including attorneys’ fees, other than contestant’s actual out-of-pocket expenses (i.e., costs associated with entering this Hackathon), and Entrant further waives all rights to have damages multiplied or increased.

C.  All issues and questions concerning the construction, validity, interpretation and enforceability of these Official Rules, or the rights and obligations of the Entrant and Sponsor in connection with this Hackathon, shall be governed by, and construed in accordance with, the substantive laws of the State of New York, USA without regard to New York choice of law rules.

SOME JURISDICTIONS DO NOT ALLOW THE LIMITATIONS OR EXCLUSION OF LIABILITY FOR INCIDENTAL OR CONSEQUENTIAL DAMAGES, SO THE ABOVE LIMITATIONS OF LIABILITY MAY NOT APPLY TO YOU.

14. Additional Terms
Please review the Devpost Terms of Service at https://info.devpost.com/terms for additional rules that apply to your participation in the Hackathon and more generally your use of the Hackathon Website. Such Terms of Service are incorporated by reference into these Official Rules, including that the term "Poster" in the Terms of Service shall mean the same as "Sponsor" in these Official Rules." If there is a conflict between the Terms of Service and these Official Rules, these Official Rules shall control with respect to this Hackathon only.

15. Entrant’s Personal Information
Information collected from Entrants is subject to Devpost’s Privacy Policy, which is available at https://info.devpost.com/privacy.

For questions, send an email to support@devpost.com.

 

 

Devpost
About
Careers
Contact
Help
Hackathons
Browse hackathons
Explore projects
Host a hackathon
Hackathon guides
Portfolio
Your projects
Your hackathons
Settings
Connect
 Twitter
 Discord
 Facebook
 LinkedIn
© 2026 Devpost, Inc. All rights reserved.
Community guidelines
Security
CA notice
Privacy policy
Terms of service

