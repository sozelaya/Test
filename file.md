**McAfee Endpoint Security 10.x**

**Technical Support Document**

For Internal Use Only

Version Number: 0.04

|    |                  |                                                                                                                                                                                                                                                                                                                                           |
| -- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| \! | ***IMPORTANT:*** | *The information contained in this document is confidential and must not be supplied to anyone external to the Intel organization without prior consent from the entire McAfee engineering team. **Unauthorized distribution of this document in whole or in part will result in disciplinary action, up to and including termination.*** |

**Document Information**

| Date:                       | 2015-08-17        |
| --------------------------- | ----------------- |
| Current Version:            | .01               |
| Author(s):                  |                   |
| Engineering Manager(s)      | Steve Aughinbaugh |
| Director of Engineering     | Srinivas Kalburgi |
| Sr. Director of Engineering | Kris Bugbee       |

**Document Revision History**

| Date:      | Version: | Author:        | Details:                                                                               |
| ---------- | -------- | -------------- | -------------------------------------------------------------------------------------- |
| 2015-08-17 | .01      | Rob Stalnaker  | Update from 10.0 release                                                               |
| 2017-08-24 | .02      | Jason Larson   | Updated to include information regarding activity logging in desired language feature. |
| 2018-04-24 | .03      | Yuji Nagi      | Updated to include information for McAfee Protection Global Exclusions feature.        |
| 2019-02-21 | .04      | Josh Eisenberg | Added pointer to case sensitivity support doc in the supported platforms section       |
| 2019-03-24 | .05      | Martin Boretto | Added ODS Scan Logging option into the Client UI Logger Settings section.              |
| 2019-09-20 | .06      | Alina Zelaya   | Updated logging structure format                                                       |

Table of Contents

[1 About This Document 7](#about-this-document)

[2 Acronyms, Abbreviations and Definitions
8](#acronyms-abbreviations-and-definitions)

[3 Supported Platforms 9](#supported-platforms)

[3.1 Workstation Operating Systems 9](#workstation-operating-systems)

[3.2 Server Operating Systems 9](#server-operating-systems)

[3.3 Windows case sensitivity 9](#windows-case-sensitivity)

[4 Overview of Major Components 10](#overview-of-major-components)

[4.1 Summary 10](#summary)

[4.2 High-level Component Diagram 10](#high-level-component-diagram)

[4.3 Component Details 11](#component-details)

[4.3.1 BL Framework 11](#bl-framework)

[4.3.2 Client UI Framework 13](#client-ui-framework)

[4.3.3 IMDPP Framework 29](#imdpp-framework)

[4.3.4 Extensions 30](#extensions)

[4.3.5 External Components 38](#external-components)

[5 Major Features 40](#major-features)

[5.1 Overview of features 40](#overview-of-features)

[5.2 License Management 40](#license-management)

[5.2.1 Overview 40](#overview)

[5.2.2 License Types 41](#license-types)

[5.2.3 Files and Registry 42](#files-and-registry)

[5.2.4 Module Behavior on license expiry
43](#module-behavior-on-license-expiry)

[5.2.5 License Overutilization 43](#license-overutilization)

[5.2.6 Troubleshooting 43](#troubleshooting)

[5.2.7 Event Management 45](#event-management)

[5.2.8 Overview 45](#overview-1)

[5.2.9 Event Database 45](#event-database)

[5.2.10 Event database change notification
45](#event-database-change-notification)

[5.2.11 Event Sinks 47](#event-sinks)

[5.2.12 Event Severity 47](#event-severity)

[5.2.13 Event Purge 47](#event-purge)

[5.2.14 Troubleshooting 47](#troubleshooting-1)

[5.2.15 Policy Settings 49](#policy-settings)

[5.3 Password Protection 49](#password-protection)

[5.3.1 Overview 49](#overview-2)

[5.3.2 Password Types 50](#password-types)

[5.3.3 Password Mode 50](#password-mode)

[5.3.4 Registry 50](#registry)

[5.3.5 Troubleshooting 51](#troubleshooting-2)

[5.4 Task Scheduler 52](#task-scheduler)

[5.4.1 Overview 52](#overview-3)

[5.4.2 Templates 52](#templates)

[5.4.3 Features 52](#features)

[5.4.4 Troubleshooting 53](#troubleshooting-3)

[5.5 Logger 54](#logger)

[5.5.1 Overview 54](#overview-4)

[5.5.2 Configuration File (Logcfg.ini)
55](#configuration-file-logcfg.ini)

[5.5.3 Client UI Logger Settings 57](#client-ui-logger-settings)

[5.5.4 Log Sinks and Log structure. 57](#log-sinks-and-log-structure.)

[5.5.5 Debugger Logger Logs 58](#debugger-logger-logs)

[5.5.6 Troubleshooting 59](#troubleshooting-4)

[5.5.7 Policy Settings 60](#policy-settings-1)

[5.6 System Information 61](#system-information)

[5.6.1 Overview 61](#overview-5)

[5.6.2 Default values: 61](#default-values)

[5.6.3 Systeminfo Notifications 61](#systeminfo-notifications)

[5.6.4 Windows Notifications 62](#windows-notifications)

[5.6.5 Troubleshooting 62](#troubleshooting-5)

[5.7 Common Package Manager 63](#common-package-manager)

[5.7.1 Overview 63](#overview-6)

[5.7.2 High-Level Component Diagram / Data Flows
64](#high-level-component-diagram-data-flows)

[5.7.3 Components 65](#components)

[5.7.4 The Update Process 66](#the-update-process)

[5.7.5 Policy Settings 67](#policy-settings-2)

[5.7.6 Files 67](#files)

[5.7.7 Registry 67](#registry-1)

[5.7.8 Logging and Errors 68](#logging-and-errors)

[5.7.9 Troubleshooting 69](#troubleshooting-6)

[5.7.10 Potential Call Generators 69](#potential-call-generators)

[5.7.11 Mirror Tasks 69](#mirror-tasks)

[5.7.12 SiteList Import/Export 69](#sitelist-importexport)

[5.8 Self-Protection 70](#self-protection)

[5.8.1 McAfee Protection Global Exclusions
70](#mcafee-protection-global-exclusions)

[5.9 Threat Reputation (GTI) 73](#threat-reputation-gti)

[5.9.1 Overview 73](#overview-7)

[5.9.2 Proxy Configuration 74](#proxy-configuration)

[5.9.3 Troubleshooting 74](#troubleshooting-7)

[5.10 DLL Injection Management 75](#dll-injection-management)

[5.10.1 Overview 75](#overview-8)

[5.10.2 Workflow 75](#workflow)

[5.10.3 Debug 79](#debug)

[5.11 Management Mode 79](#management-mode)

[5.11.1 Overview 79](#overview-9)

[5.11.2 ePO Managed Systems 79](#epo-managed-systems)

[5.11.3 Security Center Managed Systems
80](#security-center-managed-systems)

[5.11.4 Troubleshooting 80](#troubleshooting-8)

[5.12 Localization Framework 81](#localization-framework)

[5.12.1 Business Objects 81](#business-objects-1)

[5.12.2 Client UX 81](#client-ux)

[5.13 About Box 82](#about-box)

[6 Major external dependencies 83](#major-external-dependencies)

[6.1 Trusted Source (SDK) 83](#trusted-source-sdk)

[6.2 Encryption (RSA SDK) 83](#encryption-rsa-sdk)

[6.3 MPT 83](#mpt)

[6.4 McAfee Agent 83](#mcafee-agent-1)

[6.5 AMCore 83](#amcore)

[7 Policy Settings 84](#policy-settings-3)

[7.1 Client Settings 84](#client-settings)

[7.2 Server Settings 87](#server-settings)

[8 Client Installation and Uninstallation
89](#client-installation-and-uninstallation)

[8.1 List of install packages: 89](#list-of-install-packages)

[8.2 List of files for different types of packages:
89](#list-of-files-for-different-types-of-packages)

[8.3 ENS Binaries, Location and Services
90](#ens-binaries-location-and-services)

[8.4 SETUP command-line options 91](#setup-command-line-options)

[8.5 Product Upgrade 93](#product-upgrade)

[8.6 Install logs 93](#install-logs)

[8.7 Error Codes 95](#error-codes)

[8.8 Common installation messages and their causes and solutions
97](#common-installation-messages-and-their-causes-and-solutions)

[8.9 Clean Uninstaller tool 98](#clean-uninstaller-tool)

[8.10 Issues and resolution – 98](#issues-and-resolution)

[8.11 Hotfixes – 98](#hotfixes)

[9 Extension Installation and Uninstallation
99](#extension-installation-and-uninstallation)

[9.1 Cloud 99](#cloud)

[9.1.1 Installation 99](#installation)

[9.1.2 Upgrades 99](#upgrades)

[9.1.3 Uninstallation 99](#uninstallation)

[9.2 On-premise 99](#on-premise)

[9.2.1 Installation 99](#installation-1)

[9.2.2 Upgrades 99](#upgrades-1)

[9.2.3 Uninstallation 99](#uninstallation-1)

[10 Localization / Internationalization
100](#localization-internationalization)

[11 Files and Folders Overview 101](#files-and-folders-overview)

[11.1 Default File disposition on a 32 bit system
101](#default-file-disposition-on-a-32-bit-system)

[11.2 Default File disposition on a 64 bit system
103](#default-file-disposition-on-a-64-bit-system)

[12 Registry Overview 106](#registry-overview)

[12.1 Business Object Registry Structure
106](#business-object-registry-structure)

[12.2 Endpoint Security Platform Registry
107](#endpoint-security-platform-registry)

[13 Log Files 110](#log-files)

[14 Appendix C: Tools 111](#appendix-c-tools)

[14.1 Support Tool 111](#support-tool)

[14.1.1 License Conversion Tool 111](#license-conversion-tool)

[14.1.2 License Extension Tool 112](#license-extension-tool)

[14.1.3 Password Tool 113](#password-tool)

[14.1.4 Service Management Tool 114](#service-management-tool)

[14.2 Policy Import/Export Tool 116](#policy-importexport-tool)

[14.2.1 Usage: 116](#usage-4)

[14.2.2 Troubleshooting 116](#troubleshooting-13)

[14.2.3 Files 117](#files-5)

[15 Appendix D: Known Issues 118](#appendix-d-known-issues)

# About This Document

This is a technical document designed to be distributed to the support
engineers who are working directly with this product. The document may
also be beneficial to any member of the company that is directly or
indirectly involved in the software life-cycle of the product. The
document provides an overview of the functionality of the software and
includes the following:

1.  Files, Folders, Registry Keys, System Variables specific to the
    product

2.  Data structures, major components and data flow

3.  Logging and reporting information and configuration

4.  Troubleshooting tips, tools and methodologies

5.  Architectural and design diagrams

# Acronyms, Abbreviations and Definitions

| Module Name  | Module Id                                                                                                                   |
| ------------ | --------------------------------------------------------------------------------------------------------------------------- |
| BL Framework | Business Logic Framework – Meant for implementing business logic for different features.                                    |
| BO/BObj      | Business Object – Implements business logic for a feature                                                                   |
| MA           | McAfee Agent                                                                                                                |
| ePO          | ePolicy Orchestrator                                                                                                        |
| TPS          | Total Protection System – Existing McAfee product meant for SMB customers                                                   |
| SaaS         | Security-as-a-service                                                                                                       |
| SMB          | Small Medium Business                                                                                                       |
| GTI          | Global Threat Intelligence                                                                                                  |
| TS SDK       | Trusted Source SDK                                                                                                          |
| LPC          | Local Procedure Call – Mechanism provided by MA to invoke local procedures during policy enforcement, task invocation, etc. |
| Client UI/UX | (Graphical) **U**ser **I**nterface (**U**ser **E**xperience) provided on the end point.                                     |
| CEF          | Chromium Embedded Framework developed by Google®                                                                            |
| ESP          | Endpoint Security Platform                                                                                                  |
| AM           | Anti-Malware                                                                                                                |
| FW           | Firewall                                                                                                                    |
| WC           | Web Control                                                                                                                 |
| IMDPP        | Install-Migration-Deployment-Packaging-Patching                                                                             |

# Supported Platforms

## Workstation Operating Systems

Windows 8.1 Update 1

Windows 8.1

Windows 8 (not including RT)

Windows 7

Windows Embedded Standard 7

Windows Vista

Windows XP SP3 Professional x86 (XP x64 is not supported)

Windows Embedded for Point of Service (WEPOS)

Windows Embedded 8 (Pro, Standard, Industry)

## Server Operating Systems

Windows Server 2012 R2 Update 1

Windows Server 2012 R2 Essentials/Standard/Datacenter (including Server
Core mode)

Windows Server 2012 Essentials/Standard/Datacenter (including Server
Core mode)

Windows Server 2008 and 2008 R2 Standard/Datacenter/Enterprise/Web
(including Server Core mode)

Windows Storage Server 2008 and 2008 R2

Windows Small Business Server 2003 and 2003 R2

Windows Small Business Server 2008

Windows Small Business Server 2011

Windows Embedded Standard 2009

Windows Point of Service 1.1

Windows Point of Service Ready 2009

## Windows case sensitivity

For information on support for Windows case sensitivity, please see
Windows\_case\_sensitivity\_supportability.docx, which is checked in at
ENS\\hostcommon\\Miscellaneous\\.

# Overview of Major Components

## Summary

Following are the core components of Harvey:

  - Framework (UPC) SDK

  - UX Client SDK

  - IMDPP Framework

This document details the above core components along with the common
module features that form *Endpoint Security Platform*.

## High-level Component Diagram

## Component Details

### BL Framework

![](./media/image2.png)

  - **BLFramework.dll** – This is a framework stub that contains all the
    external facing APIs. Previously these API were part of BLClient.dll
    and BLServer.dll. This library acts as a common interface for
    creating client applications (such as mcconfig.exe) and server
    applications (such as epSecurity.exe, OASBL, ODSBL, etc.).

  - **BLFrameworkRT.dll** – This library provides run-time support for
    executing client calls as well as server calls. This hides all the
    communication details and allows easy upgrade of BL framework during
    patches/fixes without compromising the system security.

  - **McConfigExport.dll** – This library exports only McVariant
    manipulation classes (accessor, builder, etc.). McVariant is a
    variant data type used as a main data exchange format across
    business objects/modules/clients.

  - **LogLib.dll** – Log library that provides logging framework for the
    modules to consume.

  - **EpSecApiLib.dll** – Crypto library meant for providing encryption,
    hashing functionality.

#### Business Objects

Business Objects (BO) are a logical grouping of different features of a
product. These business objects may are not be dependent on each other,
but can work together to get the desired result. For example, common
module has BOs such as System Information BO, Event Manager BO, etc.
On-Demand Scan can consume System information BO feature to know the
system idle state to trigger/pause ODS scan. Similarly Event Manager can
listen to threat events generated from any BO and decide upon sending it
to ePO, Windows Applog, etc.

#### Hosting Services

Hosting services provide a mechanism to host different modules to run
independently of each other. This provides the benefit of not bringing
down all the security technology when there is an unexpected behavior of
any of the business object that leads to crash. Following are the
hosting services of Harvey

1.  Mfeesp.exe – Common module business object hosting service.

2.  Mfetp.exe – Threat prevention business object hosting service.

3.  Mfewc.exe – Web Control business object hosting service.

4.  Mfefw.exe – Firewall business object hosting service.

### Client UI Framework

**Client UI Architecture**

The Client UI is built upon the Chromium embedded framework. It is
deployed as a plugin to the McAfee McTray technology. McTray provides a
familiar context when launching the Endpoint Security Console, and an
infrastructure to enable notifications.

  - Provides separation from Business Logic

  - Extensible and pluggable – ability to plug multiple modules created
    by different teams

  - Interaction with UPC layer

  - Provide summary mashup on home page

  - Support localization and touch interface devices

  - HTML UI using Chromium Embedded Framework

During a base installation, the Client UI files are kept in the Endpoint
Security Platform installation directories:

\<ProgramFile Dir\>\\McAfee\\Endpoint Security\\Endpoint Security
Platform

\<ProgramFile Dir\>\\McAfee\\Endpoint Security\\Endpoint Security
Platform/app (UI resources and code)

\<ProgramFile Dir\>\\McAfee\\Endpoint Security\\Endpoint Security
Platform/modules (technology manifest)

The following files comprise the Client UI:

  - MFEConsole.exe Client UI main executable

  - MetroUtils.dll Provides Windows 8 Toast notification

  - McTrayUPC.dll McTray plugin for Endpoint Security

  - Libcef.dll Chromium embedded framework. Provides browser APIs

  - Icudt.dll Provide ICU Unicode support.

  - Blframework.dll Technology Communication.

  - blframeworkrt.dll Technology Communication.

  - blframeworku.dll Technology Communication.

  - EpSecApiLib.dll Provides cryptography APIs

  - LogLib.dll Provides logging APIs

  - McVariantExport.dll Provides data conversion APIs

**Client Console – Main Status Screen**

When the McAfee Endpoint Security console is first loaded, the ‘Status’
screen will be visible. This screen serves as a dashboard for the McAfee
Endpoint Security system and gives a high-level overview of the Modules
in use and the health of the system.

![](./media/image4.png)

**User Roles and Access**

The Client UI contains functionality that in some cases may be used to
override existing ePO policy. For this reason, the Client UI is designed
to grant and restrict access to functionality based on ePO defined
policy. The ePO common policy can specify three modes of console access:

1\. Full Access - grants a user unrestricted access to all client
features and settings in the UI.

2\. Standard Access - allows a user to interact with the UI, while
restricting access to Technology settings, AMCore Content Rollback (this
option is only available if there is a DAT to rollback to), and loading
Extra.DAT files.

3\. A Locked Client requires a potential user to first login with a
known Administrator password before granting the user full access to the
UI.

The default behaviour of the UI is to grant Standard Access to all users
in an ePO managed configuration and Full Access in unmanaged
configurations.

![](./media/image5.png)

In Standard and Locked Client configurations a user can log in as an
administrator to access advanced features in the UI. Under the drop down
menu on the main UI page, an “Administrator Log In” option is presented.
Once selected a login dialog window is launched in which the user is
prompted for the defined Administrator password. Choosing the “Log In”
button will validate the password and grant access. An incorrect entry
will force the user to renter the password. Selecting the “Cancel”
button will exit and close the dialog and the user’s current access will
remain.

In an ePO managed environment the ePO administrator can change the
Administrator password through the custom policy. Similarly in an
unmanaged environment an administrative user can define access and set a
password through the settings page for the common technology.

**Modules**

Modules are software modules installed within the Endpoint Security
Product responsible for providing a common collection of security
functionality. The product currently supports the following modules:
Threat Prevention, Firewall, and Web Control.

Modules can consist of a single protection technology (e.g. Firewall,
Web Control) or multiple protection technologies (e.g. Threat Prevention
which contains the following technologies – On Access Scan, ScriptScan,
Exploit Prevention, Access Protection)

The overall status of a module will be Enabled when all the underlying
technologies are enabled.

Modules are added to the Client UI as they are installed or removed from
the system. The application detects when a module is installed or
uninstalled by monitoring the folder that contains the modules’ manifest
file. Manifest files reside in the “*modules*“ folder located under the
“Endpoint Security Platform” installation directory. On a typical
installation, manifest files are found here:

*\<ProgramFile Dir\>\\McAfee\\Endpoint Security\\Endpoint Security
Platform\\modules*

When a .manifest file is added, removed, or changed the UI will be
signalled causing an update of the module in the UI. Note, if a user is
not aware of this behaviour, one may report unexpected changes to the
UI. For instance, such changes can cause a Module status change, or
settings page changes resulting from the addition or removal of modules.

**Settings Page**

A Module provides a common set of technologies/features which provide
security functionality. Each technology/feature in a module is described
in code as a business object. An administrator, managed or unmanaged, is
allowed to configure a feature’s behavior through tunable parameters
known as properties. **For instance the Threat Prevention module
contains business objects which represent features such as On Access
Scan, On Demand Scan, Quarantine, Access Protection, etc. The Client UI
interacts with a User Interface layer to communicate property changes to
the Business logic Layer. All business objects obey a common API
specification when providing the basic communication functionality with
the UI.**

**An administrative user can view, modify, and save properties within a
business object by selecting the “Settings” option located in the drop
down menu on the main page of the client UI. When selected a settings
page is launched. The settings page communicates with installed Modules
to populate the UI with currently persisted settings.**

**The Settings window allows the user to view and modify policy settings
for the installed modules. Each module has its own Settings section,
which is loaded on-demand when the navigation link for that module is
selected. Also, each page has a Basic and an Advanced view, which can be
toggled with the “Show/Hide Advanced” button.**

![](./media/image6.png)

**If a Module is offline or non-responsive the error message “Error
Loading Settings” is displayed when the module is selected. When this
happens, one should review the Endpoint Security log files for further
details and try re-starting the corresponding service or rebooting the
machine**

**The upper left of the settings page provides links to the currently
supported Modules. The default view of each Module is a basic view. The
basic view contains general options related to the Module. Selecting
“Show Advanced” allows a user to configure more detailed selections
such as task execution, rule definition, and content actions. Generally
configuration in the advanced view requires a greater understanding of
the functionality of the given Module.**

**Once the user has completed modification of desired settings he
selects the “Apply” button, located at the top right of the page, to
persist changes to the business object. Similarly, selecting the
“Cancel” button exits the page, and no changes are saved. Note: when
the “Apply” button is selected all settings for all Modules are flushed
to the respective business objects. On the client UI there is no record
of which setting modifications have been made, and when saved all are
written. If not aware of this the user may inadvertently persist
unwanted changes.**

**Client Debug Logging**

There has been an attempt to handle debug logging uniformly throughout
Endpoint Security product. Debug logs reside in a common location, and
adhere to a common format. Client logging is enabled differently
depending on whether the host system is ePO managed or is an unmanaged
standalone configuration. For ePO managed systems tunable parameters
such as enabling logging for a technology, defining log file locations,
and specifying log file size are configurable on the ePO server and sent
to the client via policy. Administrative users can modify these settings
via the client UI, but changes will be overwritten during the next
policy enforcement. For an unmanaged system the user has the ability to
define these same parameters via the advanced configuration under the
Common settings page. Note: Errors are logged in
EndPointSecurityPlatform\_Errors.log automatically regardless of debug
logging policy. When debug logging is enabled for any module, client
debug logging will become enabled, however a log file is only created
when there are errors being logged.

![](./media/image7.png)

![](./media/image8.png)

Entries to the log file are formatted as;

“MM/DD/YYYY hh:mm:ss.ms AM|PM \[process\_id\] \<user\_name\>
logged\_message

On a base installation client debug logs are named:

MFEConsole\_Debug.log

On a base installation client debug logs are written to:

\<ProgramDataDir\>\\McAfee\\Endpoint Security\\Logs

**Error Handling**

As in every product errors can occur. There has been a cohesive attempt
to handle errors in an informative standardized manner throughout the
Client UI. Most errors in the Client UI can be broken into two groups;
those resulting from malformed or missing user input, and those
resulting from communication failure with underlying technologies. User
input errors are handled in the UI by focusing on the failure point on a
page and displaying an error message to the right of the input section.
For instance missing required data would result in redirection of the
page to the input section and displaying a red error message “Required
field”. Errors that result from unresponsive technologies display a
message in red in the section of the page to be populated by input from
the technology. Error messages will indicate which module communication
failed. For instance failure to read properties from a business object
would result in “Failure to retrieve product information”. Failed
communication with a scan service would be displayed as “Cannot
communicate with Scan service”.

**Help**

The endpoint security product uses two types of help links throughout
the client UI. The main link is accessible from the Client main page
drop down menu. The menu contains the entry “Help” that when selected
launches the main help console. The user is able to perform case
insensitive searches, and display resulting topics. The second form of
help utilized is in the form of a small round button with a question
mark placed to the immediate right of most features in the client UI.
When the user clicks the button he is again routed to the help page, but
is now focused on the section correlating to the feature from which the
button was selected.

**Scan and Detection Management**

When the Threat Prevention Module is installed as part of the Endpoint
Security Platform suite, the client UI gives the user the ability to
perform scans, view results, and manage detections on the host system.

*Full and Quick Scans:* When a user selects the “Scan System” button
located in the upper right corner of the Client UI, a scan system dialog
is launched. The scan system dialog allows the user to initiate a Full
Scan, a Quick Scan, or view previous detections from an On-Access Scan.
The dialog contains three options; Full Scan, Quick Scan, and On-Access
scan if the product has previous detected infected files. Full and Quick
scan entries provide the date and duration of the last successful scan.
The user can select the corresponding “Scan Now” button to initiate a
scan.

![](./media/image9.png)

Once a scan is launched a Scan Status window is displayed. The Scan
Status window allows the user to view a scan’s status, and
pause/resume/cancel a running scan. Upon completion all detections are
presented, along with tallies of the number of files scanned and the
number of detections found. Note: Although Full and Quick scans may be
run simultaneously only one Scan Status window is presented displaying
the instance of the last selected scan. A user may toggle between views
of the running scans by returning to the scan system dialog and
selecting the “View Scan” button for the desired scan.

*Scan for Threats*: The Threat Prevention module installation includes a
context menu handler, rcScanMenuHandler. This module provides right
click menu context handling and gives the user the ability to perform an
on demand scan of a file object. When the user right mouse clicks a
directory, a file, or a symbolic link, a “Scan for threats” menu item is
displayed. Selection of this item will initiate a one-time scan of the
object. The Scan Status window is launched to allow viewing of the
scan’s progress status. Upon completion all detections are presented,
along with tallies of the number of files scanned and the number of
detections found. “Clean” and “Delete” buttons are presented allowing
the user to perform the desired action on detections. Note: Multiple
“Scan for threats” actions can be performed simultaneously and a
corresponding scan status window is displayed for each running scan.

*On Access Scans*: On access scans are enabled by default during product
installation. An on access scan detection will generate an instance of
the Scan Status window. Subsequent detections will be added to the
window’s detection table. For a given detection the appropriate “Clean”,
“Delete”, and “Remove” buttons are enabled. The “Clean” action cleans
the detection, but the entry remains on the system and in the detection
table. The “Delete” action deletes the detection from the system, but
the entry remains in the detection table. The “Remove” action will
remove the entry from the detection table, and will not be included in
future detection lists. The detection table contains a 5000 entry
history.

**Updates**

Upon installation, the product will perform a full software update to
the host computer. The end user has the ability to manually check for
and download updates to both content and software components on the host
system.

Selecting the “Update Now” button on the main UI page will start the
update process. As the process begins an update progress dialog window
is launched. The dialog contains information on the date of the last
successful update, and displays a progress bar corresponding to the
update status. During the update the user can cancel the scan by
selecting the “Cancel” button.

Upon an update failure, pertinent details will be displayed in the
message area at the bottom of the dialog.

**Notifications**

The endpoint security product utilizes two types of notifications;
Prompts which require user interaction, and Alerts which are informative
in nature. Alerts are presented in two formats. On versions of the
Windows operating system earlier than Windows 8, alerts are presented in
the familiar McTray format. On Windows 8 and later alerts are presented
as Windows Toast Notifications.

Currently the product only displays a single prompt notification, Defer
Scan. If the “Defer Scan” option is specified in the Threat Protection
policy the prompt will be generated when a scheduled scan begins. The
user has the option to 1) start the scan immediately or 2) delay the
scan for a specified amount of time. When launched the prompt starts a
countdown of an interval specified by policy. If the user does not
respond in the allotted amount of time, the prompt is dismissed and the
scan is started.

Alerts are displayed through the McTray interface. The format is common
to many McAfee products. Alerts are informative in nature. An example of
an alert in the product would be “resuming scan”. In the product all
alerts display a Name, Detection type, and Action fields.

On Windows 8 and greater the product presents the same message in a
toast banner. The toast notification is displayed at the uppermost right
corner of the screen. Toast is displayed on both the desktop and metro
environments. By default the Toast notification remains for seven
seconds, or until user input (window dismissal or selection) is
encountered. If the toast banner is clicked control returns to the
window desktop.

If a prompt, alert, or Toast notification is not generated, one can
check the UI’s event viewer to ensure a corresponding event was actually
generated. Secondly one should be verified that the McTray application
is running, and the McTrayUPC.dll and the MetroUtils.dll are loaded
(using process explorer).

**Event Log**

The UI’s Event Log (Viewer) gives the user read access to the event log
generated by the instance of Endpoint Security software running on their
system. The log contains a 30 day history. The viewer allows a user to
sort, search, and filter logged events. Threat detections which have not
been filtered out will be displayed here. Since there may be many events
present on the system, events can be filtered by severity or feature
using the dropdown and specific terms can be searched using the search
text field. The events are also paged and there are controls to change
the number of events per page and to switch pages

![](./media/image10.png)

Filters: On the upper left of the viewer is a drop down list of
available filters. There are currently two available filters; Severity
and Module. When a filter is applied the table of events is limited to
only those entries which match the chosen filter. Granularity of the
Severity filter is; Warning and Greater, Minor and Greater, Major and
Greater, and Critical. Granularity of the Module filter is Threat
Prevention, Firewall, and Web Control. By default no filter is applied.

Search: At the top right of the viewer is a search box. This allows a
user to search all fields of the event for a given text string.
Following a search only data containing matching text is displayed in
the event list. Note: the search is case insensitive

If a new event occurs while the Event Log is open, the refresh button
will turn blue and may be activated to refresh the view.

The viewer presents two viewing panes; the top contains a table of
condensed entries for each event, the lower contains details for a
highlighted event.

**Quarantine Viewer**

The UI’s Quarantine page allows the user to view and manage detection
items which have been placed in a quarantined state. The quarantine page
allows a user to delete, restore, and rescan a file marked as
quarantined.

The page is presented in two viewing panes; the top contains a condensed
entry for detections found, the lower contains details for the
highlighted file. The details pane contains two links in the rightmost
corner; the first “View in Event Log” when selected directs the user to
the event viewer page, the second “Learn more about this threat” when
selected directs the user to an online resource with information
concerning the detection file type.

![](./media/image11.png)

When the user selects a file in the detection page three buttons are
enabled giving the ability to Delete, Restore, or Rescan the selected
detection. The “Delete” button will remove the detection from both the
system and the viewer. The file cannot be retrieved. The “Rescan” button
will rescan the detection. This could be of importance if an updated
.DAT file has been imported in the product. If the rescan has determined
the detection to no longer be a threat, it will restore the file to the
system and remove it from the viewer. The “Restore” button will restore
the file to its original location on the system and remove it from the
viewer. An action that encounters an error will be presented to the user
in the details pane, and will remain in the quarantine viewer.

**McTray Technology Status**

The UI allows a user to visually determine the status of the Endpoint
Security Platform from the McTray icon displayed on the system taskbar.
If an installed technology becomes disabled or unresponsive the icon
will change in appearance and enable the user to obtain details of the
failure. Currently Firewall, Access Protection, Exploit Prevention,
On-Access Scan, Script Scan, Self-Protection, and Web control are
monitored.

A Normal Endpoint Security Platform status is signified
as![](./media/image12.png). Disabled technologies will result
in![](./media/image13.png). Note: Technologies disabled on a managed
system as a result of ePO policy or configuration via Client UI is not
falsely reported. Enhanced details concerning the product status can be
obtained by right clicking the icon and selecting “View Security
Status”.

**Tasks**

*Task Grid*

Task creation, configuration, and monitoring are accomplished via the
"Task" grid located in the Client UI under the advanced settings page
for Common. Upon initial viewing, the task grid presents all pertinent
scans to a given ENS configuration. A non-managed environment presents
the base "Default update scan", "Quick Scan", and "Full Scan". A managed
configuration would include the default scans as well as any ePO managed
scans. The user is able to differentiate a managed from non-managed
through observation of the "Origin" column. Managed or default scans
have an origin defined as *McAfee-defined*, where a non-managed task has
an origin of *User-Defined*. The user is given the option to "Add",
"Delete", "Duplicate", or “Run Now" a highlighted task. Note, the
functionality of each button is dependent upon user permissions based on
the originator of the task.

![](./media/image14.png)

*Custom Tasks*

The Client UI provides the capacity for an end user to quickly create,
schedule, run, and monitor custom tasks. Custom tasks which are created
in a managed configuration are not reported to ePO. Custom tasks are
user-defined and reside local to the host system.

Supported custom tasks include Threat Prevention Scan, Update, and
Mirror.

*Custom on Demand Scan*

Custom on Demand scans are created using the "Add" button on the grid.
The user is prompted for a unique name and must select "Custom Scan"
from the drop down menu.

![](./media/image15.png)

After pressing the "Next" button the user is direct to a page in which
the "Settings" tab allows definition of the scan, and "Schedule" tab
defines the interval of its run.

![](./media/image16.png)

*Custom Mirror Task*

Custom Mirror Tasks are created using the "Add" button on the grid. The
user is prompted for a unique name and must select "Mirror" from the
drop down menu.

![](./media/image17.png)

After pressing the "Next" button the user is direct to a page in which
the "Settings" tab allows definition of the mirror site and content to
be downloaded. The "Schedule" tab defines the interval of its run.

![](./media/image18.png)

*Custom Update Task*

Custom Update Tasks are created using the "Add" button on the grid. The
user is prompted for a unique name and must select "Update" from the
drop down menu.

![](./media/image19.png)

After pressing the "Next" button the user is direct to a page in which
the "Settings" tab allows definition of the mirror site and content to
be downloaded. The "Schedule" tab defines the interval of its run.

![](./media/image20.png)

**Support Links Page**

The Client UI provides the capacity for an end customer to quickly
obtain pertinent information from the McAfee Support web site. When the
user selects the “Support Link” entry from the dropdown on the client
UI’s main page a support window is launched. The page contains four
links; “McAfee Service Portal”, “Knowledge Center”, “Support Tools”, and
“Service Request”. When a link is selected the corresponding support
page on McAfee support site is launched in the systems default web
browser.

**Custom Tasks Creation**

The Client UI provides the capacity for an end customer to quickly
schedule custom tasks. Supported custom tasks include Threat Prevention
Scan, Update and Mirror tasks.

### IMDPP Framework

![](./media/image21.png)

  - MSI based installers

  - Support an extensible blade level deployment

  - Ability to plug-in additional blades

  - Support multiple deployment scenarios
    
      - Managed (ePO on-Prem and on-Cloud)
    
      - Standalone
    
      - TPS deployment modes

  - Provide a wrapper installer for standalone

  - Support all command-line installer options

  - Support third-party frameworks like SCCM

### Extensions

The management portion of McAfee Endpoint Security 10.0 is made up of
four main extensions to support the design concept of four functional
modules that can be added and removed

  - **Endpoint Security Platform Extension**
    
      - This is the base extension also known as Endpoint Security
        Common (in the Policy Catalog), and is required to be installed
        first and removed last. We enforce this by having the other
        three extensions require the Platform extension be installed. In
        addition, the Platform extension cannot be removed unless the
        other three supported extensions are removed first.

  - **Endpoint Security Threat Prevention Extension**
    
      - The Threat Prevention (TP) extension has its roots in VirusScan
        Enterprise (VSE) 8.8. We started with the two extensions from
        VSE 8.8 and created the TP extension, so many of the policies,
        tasks, and queries are similar.

  - **Endpoint Security Web Control Extension**
    
      - The Web Control (WC) extension has its roots in SiteAdvisor
        Enterprise (SAE) 3.5. We started with numerous extensions and
        created one WC extension, so many of the policies, tasks, and
        queries are similar

  - **Endpoint Security Firewall Extension**
    
      - The Firewall (FW) extension has its roots in the Firewall
        portion of Host Intrusion Prevention (HIPS) 8.0. We started with
        numerous extensions and created one WC extension, so many of the
        policies, tasks, and queries are similar

#### Policies

All policies in all extensions have a basic and advanced view, although
the advanced view may be disabled if it contains no settings. The basic
view hides settings that still apply but may not be of interest to all
users

![](./media/image22.png)

When an ePO user edits a policy, ePO remembers if that user is using the
basic or advanced view for that policy. The next time the user edits
that policy, the policy will appear in either the basic or advanced view
the same as the last time they edited that policy. The user can change
the policy view from basic to advanced or from advanced to basic at any
time, and if they save the policy the view settings will be retained.

Endpoint policies have been simplified for a Small Business customer who
doesn’t need all the features of an Enterprise product. To do this, most
tabs in policies have been removed and users must scroll the page to see
all settings. Child settings that are only available if a parent setting
is enabled are also hidden when disabled. This means that users must
enable and then drill-down into the policy features they wish to change

#### Dashboards/Queries

In ePO/MFS 5.1/5.2 there is a new feature introduced (Hot Swappable
Monitors) where we can dynamically add/remove monitors to a preexisting
dashboard as an extension is installed/uninstalled/licensed. Hence
several of the dashboards are installed empty in the Security Platform
(Common) extension, and get filled with monitors as the other extensions
(Threat Prevention/Web Control/Firewall) are installed. The empty
dashboards that do not have any monitor on them will not be displayed
until you add at least one monitor to them by installing the extension
that contains the query/monitor. The first image shows a dashboard with
only the Web Control extension installed/licensed and the second image
shows the same dashboard with all extensions installed/licensed

![](./media/image23.png)

IMPORTANT: In cloud mode permissions in MFS are based on the SQUID table
and not at the query level. Hence queries/monitors (and the dashboards
containing those monitors) in Endpoint Security 10 that are based purely
on EPO tables (EPOEvents, EPOProductProperties etc.) will be displayed
to users who have not licensed Endpoint Security 10. There will be no
data in those monitors/dashboards, but they will still appear to users
who have not licensed Endpoint Security 10 in cloud mode.

The following dashboards are installed by the Endpoint Security Platform
(Common) Extension

1.  Endpoint Security: Compliance Status - Contains monitors that report
    on whether a technology is compliant or not. Technologies will
    report up as being non-compliant when they are disabled on the
    client but are set to be enabled as per policy

2.  Endpoint Security: Detection Status - Reports on the threats
    detected for the previous 24 hours and 7 days

3.  Endpoint Security: Environmental Health - Summarizes the protection
    status of deployed Endpoint Security modules. The currently enabled
    technology monitor is an unusually complicated monitor because it
    reports information from multiple Endpoint modules, some of which a
    customer may not be licensed for (cloud) or may not have the
    appropriate extensions installed to support (on-premise). Therefore,
    the monitor should not report on technologies that a particular
    customer is not using. The monitor uses a stacked bar chart to show
    both the number of enabled technologies and the number of “rogue”
    end-nodes with disabled technologies. The monitor is designed to
    support a dynamic number of Endpoint modules each providing a
    dynamic number of technologies. To provide this support, a patch to
    the Common extension is required whenever the number of available
    Endpoint modules or technologies changes. This is a limitation of
    the implementation.

4.  Endpoint Security: Installation Status - The Installation status
    monitor reports how many installations of each Endpoint module exist
    relative to how many end-nodes a customer has. If a customer is not
    licensed for a module (cloud), or hasn’t installed a module’s
    supporting ePO extension (on-premise), that module will be excluded
    from the monitor. The monitor uses a stacked bar chart to show both
    the number of installed modules and the number of “rogue” end-nodes
    without installations. The monitor is designed to support future
    Endpoint modules. To provide this support, a patch of the Common
    extension is required whenever a new Endpoint module is released.
    This is a limitation of the implementation

5.  Endpoint Security: Threat Behavior - Summarizes threat activity and
    the spread of infection in the environment

6.  Endpoint Security: Threat Event Origins - Reports on how threats are
    entering the environment

The following dashboards are also installed by the Endpoint Security
Platform (Common) Extension, but do not appear on the dashboards screen,
because they do not contain any monitors at that point (when no other
Endpoint Security 10 extensions are installed).

1.  Endpoint Security: Content Status - Reports on the different content
    versions that are deployed within the managed environment

2.  Endpoint Security: Scan Duration - Summarizes the average time for
    the default full and quick scans

The following dashboards are only installed in cloud mode (will not be
displayed in on-prem mode)

1.  Endpoint Security: Protection Summary - shows information on the
    number of nodes installed, protected and whether the content is up
    to date (i.e. less than a week old). There is also an option to
    start the Install Protection workflow from this monitor
    
    In this monitor, the criteria for Installed, Protected, and
    Up-to-date counts is as follows:
    
    Installed: The customer must have all licensed Endpoint modules
    installed on all end-nodes to get a perfect score.
    
    Protected: The customer must have all licensed Endpoint module
    technologies enabled on all end-nodes to get a perfect score.
    
    Up-to-date: The customer must have AMCore content that is less than
    a week old installed on all end-nodes to get a perfect score.

**Queries**

The queries installed with the Common Extension are listed below. The
name in the parenthesis after the report name is the primary target
table that the report accesses. This does not mean that the report will
not access columns from other tables, just that this is the primary
target of the report.

The target table is displayed in EPO as the result type as listed below

GS\_CustomProps – New QueryResult Type (select “Endpoint
Security”)Endpoint Security Platform Systems

EPExtendedEvent – New QueryResult Type (select “Events”)Endpoint
Security Threat Events

The AM\_EndpointTechnologyStatus\_View and
EndpointInstallationStatus\_View are join tables, hence we do not
provide result type targets for them.

1.  Endpoint Security Platform: Hotfixes Installed (GS\_CustomProps)

2.  Endpoint Security: Currently Enabled Technology
    (AM\_EndpointTechnologyStatus\_View)

3.  Endpoint Security: Duration before Detection on Endpoints in the
    Last 2 Weeks (EPExtendedEvent)

4.  Endpoint Security: Installation Status Report
    (EndpointInstallationStatus\_View)

5.  Endpoint Security: Policy Compliance by Computer Name
    (EPOAssignedPolicy)

6.  Endpoint Security: Policy Compliance by Policy Name
    (EPOAssignedPolicy)

7.  Endpoint Security: Primary Vectors of Attack in the Last 7 Days
    (EPExtendedEvent)

8.  Endpoint Security: Self Protection Compliance Status
    (GS\_CustomProps)

9.  Endpoint Security: Summary of Threats Detected in the Last 24 Hours
    (EPOEvents)

10. Endpoint Security: Summary of Threats Detected in the Last 7 Days
    (EPOEvents)

11. Endpoint Security: Threats Detected in the Last 24 Hours (EPOEvents)

12. Endpoint Security: Threats Detected in the Last 7 Days (EPOEvents)

13. Endpoint Security: Top 10 Attacking Systems in the Last 7 Days
    (EPExtendedEvent)

14. Endpoint Security: Top Infected Users in the Last 7 Days
    (EPExtendedEvent)

15. Endpoint Security: Top Threats in the Last 48 Hours
    (EPExtendedEvent)

#### Database

**Extended Event Table (EPExtendedEventMT table / EPExtendedEvent
view)**

The Common Extension (aka Endpoint Security Platform) is the “Common”
extension for all the other Endpoint Security 10 extensions (Threat
Prevention, Web Control, and Firewall) and must be installed prior to
installation of the other Endpoint Security 10 extensions.

All the extensions in Endpoint Security 10 now use the EPO Event parser
– no extension has any custom event parser of its own (no event parser
dll). EPO’s event parser, parses ALL events coming from the clients and
stores them into the appropriate tables. ALL events are primarily stored
in the EPOEvents table that belongs to EPO (this table can be browsed
through the Reporting Threat Event Log screen). Events can have extra
fields that cannot be stored in the existing EPOEvents table. These
extra fields can be stored in Custom Event tables that are foreign keyed
to the EPOEvents table.

Endpoint Security 10 has a custom event table called
**EPExtendedEventMT** (The “MT” suffix stands for multi-tenant. This
suffix is used even in the on-prem install to try and keep the schema
identical as far as possible for both the on-prem and cloud mode). This
EPExtendedEventMT table is foreign keyed to the EPOEvents table through
a one-to-one relationship. The EPExtendedEventMT table is also called
the **DAD Table** (Descriptive Attack Data table).

This EPExtendedEventMT table is accessed through a view called
**EPExtendedEvent**. The EPExtendedEvent view just retrieves all the
fields of the EPExtendedEventMT table in on-prem mode, whereas in cloud
mode the EPExtendedEvent view selects all rows from the
EPExtendedEventMT table for one particular tenant.

The EPExtendedEvent view can be accessed through the SQUID Query
builder. In “Queries & Reports” click on “New Query”. Select “Events” as
the “Feature Group”. In the “**Result Types**” select “**Endpoint
Security Threat Events**”. This result type represents the
EPExtendedEvent view. On the SQUID Filter screen, the filter properties
available for this table are Access Requested, Analyzer McAfee GTI
Query, Attack Vector Type, Direction, Duration Before Detection (Days),
Location, and Module Name. For these filter field’s indexes have been
added to the EPExtendedEventMT table to speed up queries.

A diagram of the EPExtendedEventMT table and its relationship to the
EPOEvents table is shown below.

![](./media/image24.png)

**Custom Properties table (GS\_CustomPropsMT table / GS\_CustomProps
view)**

For each extension that is installed EPO creates a view
EPOProdPropsView\_\<Suffix\> with the Family Name of the extension as a
suffix. This EPOProdPropsView\_\<Suffix\> view is built on the
**EPOProductProperties** table owned by EPO. In case of the Common
extension this property table is called
**EPOProdPropsView\_ENDPOINTSECURITYPLATFORM**.

Each point product has **extra properties** that it sends to the server.
These custom properties are stored in a Custom Properties table that is
foreign keyed to the **EPOProductProperties** table.

The custom properties table for the Common extension is called
**GS\_CustomPropsMT**. Since this table is in the common extension, it
contains several fields that are applicable to the other Endpoint
Security 10 extensions (Threat Prevention, Web Control, and Firewall).
The GS\_CustomPropsMT table is foreign-keyed to the EPOProductProperties
table in a one-to-one relationship.

A view called **GS\_CustomProps** is built on the GS\_CustomPropsMT
table. In an on-prem installation this view selects all the fields in
the GS\_CustomPropsMT table, and the
\[EPOProdPropsView\_ENDPOINTSECURITYPLATFORM\].\[LeafNodeID\] column. In
a cloud installation the CustomProps view selects all rows from the
CustomPropsMT table for one particular tenant along with the related
LeafNodeID for each row. There is one row in the CustomPropsMT table for
each node in the system that has Endpoint Security Platform client
installed.

The **GS\_CustomProps** view can be accessed through the SQUID Query
builder. In “Queries & Reports” click on “New Query”. Select “Endpoint
Security” as the “Feature Group”. In the “**Result Types**” select
“**Endpoint Security Platform Systems**”. This result type represents
the **GS\_CustomProps** view.

A diagram of the **GS\_CustomPropsMT** table and its relationship to the
**EPOProductProperties** table is shown below.

![](./media/image25.png)

### External Components

#### McAfee Agent

Used for scheduling, policy enforcement, reporting and task enforcement.

#### McTray

The Endpoint Security Client UI is deployed as a plugin to the McAfee
McTray technology. This provides a familiar context when launching the
Endpoint Security Console.

The following registry keys are required for loading the client UI
plugin.

*X86:*

\[HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\McTray\\Plugins\\McTrayUPCPlugin\]

“Name" = "McTrayUPCPlugin"

"Path" = "\<ProgramFilesDir\>\\McAfee\\Endpoint Security\\Endpoint
Security Platform\\McTrayUPC.dll"

"MFEConsolePath" = "\<ProgramFilesDir\>\\McAfee\\Endpoint
Security\\Endpoint Security Platform”

64:

\[HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Wow6432Node\\McAfee\\McTray\\Plugins\\McTrayUPCPlugin\]

“Name" = "McTrayUPCPlugin"

"Path" = "\<ProgramFilesDir\>\\McAfee\\Endpoint Security\\Endpoint
Security Platform\\McTrayUPC.dll"

"MFEConsolePath" = "\<ProgramFilesDir\>\\McAfee\\Endpoint
Security\\Endpoint Security Platform”

The plugin DLL is installed at:

"\<ProgramFilesDir\>\\McAfee\\Endpoint Security\\Endpoint Security
Platform\\McTrayUPC.dll"

#### ePolicy Orchestrator (ePO)

Administrators can use McAfee ePO as a security management platform to
manage security for all systems from a centralized security management
console. Using ePO they can perform tasks like:

• Deploy product software to managed systems.

• Manage and enforce security using policy assignments and automated
tasks.

• Update the product components and required security content to ensure
that managed systems are secure.

• Create reports that display informative, user-configured charts and
tables containing their security data.

Endpoint Security 10.0 client can be managed by a McAfee ePO server
(version 5.1.1 or higher) that is installed within the customer’s
environment (on-premise) or via the McAfee ePO Cloud server (version 5.2
or higher) that is hosted by McAfee

**Please make sure that you are familiar with the functionality of
McAfee ePO and McAfee ePO cloud before proceeding further**

# Major Features

## Overview of features

Endpoint Security Platform includes following major features
(represented as business objects)

| Feature            | Description                                                                                                                                |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Self-Protection    | Provides self-protection to all the modules                                                                                                |
| License Manager    | Manages license related activities                                                                                                         |
| Event Manager      | Manages threat events received from different modules/BOs for sending to different destinations such as ePO, Windows application log, etc. |
| Scheduler          | Manages scheduling of tasks using MA                                                                                                       |
| Threat Reputation  | Provides threat reputation for files, URLs, IP addresses, etc. using GTI                                                                   |
| Package Manager    |                                                                                                                                            |
| System Information | Provides information such as system idleness, presentation mode, time change events, user login/logout events, etc.                        |
| Logger             | Facilitates configuration of logging options for various modules in a uniform way.                                                         |

## License Management

Common licensing component (License Manager) is responsible for managing
licensing related activities for all the modules. Endpoint Security
Platform (ESP) provides common services to all the modules and by itself
cannot do anything meaningful. Hence all the modules, except Endpoint
Security Platform, are associated with license.

### Overview

The following chart provides overview of the process of finding the
license information under various management modes.

The components involved in process are as follows:

1.  COMBO – This BO is responsible for identifying management mode for
    the Harvey product. Please refer to ‘Management Mode’ section for
    further details.

2.  License Manager BO – This BO is responsible for deciphering the
    license information based on the management mode. It shares this
    information the other modules by sending notifications. Other
    modules can also query license manager to get the license
    information. This is especially needed when the modules restarts.

3.  NAI Lite API – This library is responsible for reading/writing
    license information from registry. The license information in the
    registry is encrypted using Blowfish algorithm and stored. This
    library is used in self-managed, ePO on-prem and TPS mode only.

4.  MA API – MA LPC interface is used to get the details of license when
    the management mode is ePO Cloud.

### License Types

#### Beta

Beta license expires on a fixed date. This duration is usually 90 days
from the beta launch date. The expiry date is decided during beta
release and gets embedded into each module. All the module features are
fully functional. Please refer to ‘Module behavior on license expiry’
section.

#### Trial/Evaluation

Trial licenses are usually provided for 90 days from the
‘date-of-installation’. All the module features are fully functional.
Trial license can be upgraded to Perpetual/Subscription on purchasing
the product without reinstalling. Please refer to ‘Tools’ section for
details on license conversion tool. Please refer to ‘Module behavior on
license expiry’ section.

##### Extending License expiry

An option is provided to users for extending trial license ‘once’ by 30
days.

| Mode           | Notes                                                                    |
| -------------- | ------------------------------------------------------------------------ |
| ePO (On-prem)  | Installer uses McScripts to extend Eval license.                         |
| ePO (On-cloud) | License expiry date extension is handled by the ePO cloud backend.       |
| Standalone     | Not applicable                                                           |
| TPS (SaaS)     | License expiry date extension is handled by the Security Center backend. |

##### Conversion to Licensed Package

| Mode           | Notes                                                                                                                                                 |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| ePO (On-prem)  | Installer uses McScripts to convert Eval package to licensed (perpetual) package when user upgrades from Eval to licensed.                            |
| ePO (On-cloud) | Not applicable                                                                                                                                        |
| Standalone     | A license conversion tool is available for converting Eval package to licensed (perpetual) package. Please refer to ‘Tools’ section for more details. |
| TPS (SaaS)     | Not applicable.                                                                                                                                       |

#### Perpetual/Licensed

Perpetual licenses are provided for stand-alone/ePO on-prem
installations. Only Trial/Evaluation licenses are allowed to be
converted to perpetual license. Please refer to ‘Module behavior on
license expiry’ section.

#### Subscription/Licensed

Subscription licenses are usually configured for ePO on-prem, cloud and
TPS management platform. Licensing component relies on these management
platforms to find out when the license expires/expired. Please refer to
‘Module behavior on license expiry’ section.

### Files and Registry

Please refer to the ‘License Manager’ entries under Files and Folders
Overview and Registry Overview sections. Following registry is referred
to read/update license information for the following modes:

1.  Stand-alone

2.  ePO On-prem

3.  SaaS (TPS)

| Key (x86)     | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\ProductInfo              |                  |              |                                     |
| ------------- | -------------------------------------------------------------------------- | ---------------- | ------------ | ----------------------------------- |
| Key (x64)     | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\Wow6432Node\\McAfee\\EndPoint\\ProductInfo |                  |              |                                     |
| Name          | Type                                                                       | Default          | Valid Values | Notes                               |
| \<Module Id\> | SZ                                                                         | \<WC/FW/ESP/AM\> |              | Encrypted license blob gets stored. |

\<Module Id\> is an identifier used to identify a module. This is used
as an alternative to software Id of a module because software Id can
change with upgrade releases and it would be hard to maintain the
mapping between modules and the associated software Id. \<Module Id\> is
available under
HKEY\_LOCAL\_MACHINE\\SOFTWARE\[\\Wow6432Node\]\\McAfee\\EndPoint\\Modules\\\<Module\>\\ModuleId.
These module key and the \<Module Id\> registry are populated during
module installation. Following module Ids (as of Harvey) are used

Following is the current mapping of software Id to module Id

| Module Name                | Software Id    | Module Id |
| -------------------------- | -------------- | --------- |
| Endpoint Security Platform | ENDP\_GS\_1000 | ESP       |
| Threat Prevention          | ENDP\_AM\_1000 | AM        |
| Firewall                   | ENDP\_FW\_1000 | FW        |
| Web Control                | ENDP\_WC\_1000 | WC        |

For ePO Cloud mode, license information is directly queried from MA
using the software Id.

### Module Behavior on license expiry

| Mode        | Content Update | Policy Update  | Product Update |
| ----------- | -------------- | -------------- | -------------- |
| ePO On-prem | Allowed        | Blocked        | Allowed        |
| ePO Cloud   | Allowed        | Blocked        | Allowed        |
| TPS         | Blocked        | Blocked        | Blocked        |
| Standalone  | Allowed        | Not applicable | Allowed        |

### License Overutilization

In managed environment the license overutilization issue is handled by
ePO/Security Center. In case of ePO managed environment, MA is
responsible for providing node count details to ePO. Details on this
subject are out of scope of this document. Please refer to ePO/Security
center documentation for further details.

### Troubleshooting

| **Log Messages**                     | **Type** | **Comment**                                                                                                       |
| ------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------- |
| Failed to create/load container      | Error    | License manager BO failed to load settings from configuration file possibly due to a corrupt LcBL.xml or LcBL.xsd |
| Failed to save container             | Error    | License BO is not able to save settings to configuration file. This may result in loss of settings on restart.    |
| Failed to initialize nailite manager | Error    | Failed to initialize nailite manager possibly due to memory issues.                                               |
| Failed to encrypt data               | Error    | Unable to encrypt data due to internal errors                                                                     |
| Failed to decrypt data               | Error    | Unable to decrypt data due to internal errors                                                                     |

#### Eval license is shown as expired within 90 days of installation

> Check the system date/time has been changed. 90 days is calculated
> from the date of install

#### License is shown as ‘Not a valid license’ in ePO cloud

> Restart ‘mfeesp’ and ‘module’ service/system

#### License is shown as ‘Self-managed’ in ePO cloud

> Check if MA service is running

#### License still shows as expired after extending the license

> The license extension tool extends license from the original date of
> expiry and not the current date. So if you try to extend license 30
> days after expiry of evaluation license, the license will still be
> expired.

#### Policy enforcement is failing

Check if license has expired. Either extend/renew the license

Check if MA and modules services are running

### 

###   
Event Management 

### Overview

Event Manager BO manages events for all modules and Client UI in a
centralized approach and stores all the events in local event database.
Whenever BO’s and Client UI post an event, event is processed by Event
Manager based on sink and severity level. Events matching the configured
severity levels will be stored in the database and will be displayed at
Client UI event viewer with the details. Events matching the configured
severity levels and destination flag will be sent to configured
destinations. Event sinks and filter levels are explained at following
sections.

### Event Database

For the local data store, SQLite database is used for containing all of
the events. A single row in the table will contain the data for a single
event.

  - The Event Manager writes every event it receives into the database.

  - The Event Manager owns the Event database. Any and all insertions,
    updates, or deletions are encapsulated and performed by this BO.

### Event database change notification

Whenever an event is added, deleted, or modified, the Event Manager
publishes the event, so that subscribers to this event (UI and BO’s)
will be notified and can choose to refresh the data set.

> 1\. Various business objects independently and asynchronously submit
> events to the Event Manager.
> 
> 2\. The BL Framework client library writes events to a shared memory
> area and immediately releases the sending BO thread to do other
> processing. At this stage, there may be one or dozens or thousands of
> serialized data objects in there, all of varying types.
> 
> 3\. The BL Framework server library thread pulls objects out of the
> shared memory queue, one at a time, and invokes the server-side
> implementation of BLObjectNotify(), which invokes the Event Manager's
> registered callback function along with the Event received.
> 
> 4\. The Event Manager, during processing of other event syncs, writes
> the Event to the Event database by constructing an Event row from the
> data given in the event.
> 
> 5\. The Event Manager notifies all interested parties of the database
> insert by firing an EP\_EVENT\_BO\_CONFIG\_REFRESH event using
> BLObjectNotify (). That event also contains a list of all the ROWIDs
> of each new database row just added. The EM sends at most one
> notification every two seconds for performance reasons. The User
> Interface and all modules should be listening for this event from the
> Event Manager.
> 
> 6\. When appropriate (user clicks button, etc.) the UI will open the
> Event Viewer.
> 
> 7\. The Event Viewer issues a query to the Event Manager for the most
> recent X number of rows, looking for the row with a ROWID equal to
> that of the most recent ROWID provided in step 5 above. This allows
> the Event Viewer to position the viewer window with this row as the
> current row with the detailed information in the lower part of the
> pane.

### Event Sinks

General settings at ePO and the Client UI contain the configuration
settings for the event destinations (or sinks). The Event Manager
supports the following sinks which are configurable for all modules.

  - **ePO:** Receives events matching the configured severity levels.

  - **Windows Event Viewer:** Receives events matching the configured
    severity levels.

  - **Event Database:** The UI does not expose this option, and events
    matching the configured severity levels will be written to local
    event database by default.

### Event Severity

General settings at ePO and the Client UI contain the configuration
settings for the severity levels. The different severity levels
supported by Event Manager are shown below and can be configured for TP,
FW and WC modules.

  - **None:** No events will be sent to the configured destinations and
    all the events will be suppressed.

  - **Critical Only:** Events matching with critical severity will be
    sent to configured destinations.

  - **Major and Critical:** Events matching with major and critical
    severity will be sent to configured destinations. This severity is
    the default setting.

  - **Minor, Major, and Critical:** Events matching with minor, major
    and critical severity will be sent to configured destinations.

  - **All except Informational:** Events matching with warning, minor,
    major and critical severity will be sent to configured destinations.

  - **All:** All events will be sent to configured destinations.

### Event Purge

Event Manager starts separate thread for deleting old events from event
database. This thread purges events from database older than 30 days.
This normally takes place every 24 hours. 20 minutes after the
mfeesp.exe service starts, the thread checks whether 24 hours has passed
since the last purge. If it has, then the purge will take place,
followed by space reclamation to relinquish the unused space back to the
file system. This keeps the physical database file size from growing
unmanageably. Then, for the life of the mfeesp.exe service instance, the
purge interval check will happen every 24 hours.

### Troubleshooting 

#### Events are not populating to the Client UI Event viewer/event database.

Check mfeesp service is running and event severity matches with
configured event severity. Check event data types are valid against
embl.xsd data types.

#### ***The threat event timestamp field in the event viewer does not match the timestamp of the event generation.*** 

Check event has the time stamp data. Time stamp of event data will be
populated not the event generation time.

#### Event severity does not match at Client UI and ePO.

The threat severity levels differ between ENS 10.0 and ePO, largely due
to historical reasons from previous versions or compatibility with them.
To help achieve the best alignment, the Event Manager will assign the
Threat Severity in the event going to ePO according to the following
mapping:

> Endpoint Threat Sev. ePO Threat Sev.
> 
> \-------------- -----------------
> 
> Critical (1) --\> Alert (1)
> 
> Major (2) --\> Critical (2)
> 
> Minor (3) --\> Warning (4)
> 
> Warning (4) --\> Notice (5)
> 
> (otherwise) --\> Info (6)

#### Events are populated at Client UI but not sent to ePO or Windows Event Viewer.

Check event xml has the destination set to ePO or Windows Event Viewer.

#### Non matching event severity events are sent to ePO.

Non-generic events are sent to ePO without considering event severity
i.e., all ePO destination non-generic events are sent to ePO.

#### Events with ePO as destination are not sent to ePO.

Verify that the MA and mfeesp services are running. Check sendtoePO
option is enabled.

#### Events with SNMP and SMTP as destinations are not sent.

SMTP and SNMP are not supported in Harvey.

#### SQL Log messages

By enabling debug logging, every SQL operation (the exact SQL) is
written to the EndpointSecurityPlatform\_Debug.log which can be helpful
in determining what operation is being attempted in the context of a
larger issue.

#### \<ProgramData\>\\McAfee\\Endpoint Security\\DADEvents.db

This file contains all events logged locally on the client machine. It
is a SQLite format database. SQLite Expert, which is a freeware tool, is
convenient for reading the database data outside of the ENS 10.0 client
UI. Self-protection of ENS will prevent modification of any of the data,
most likely, and it is advised that none of the schema is modified as
this will cause the event manager to malfunction.

The DADEvents.db file can be deleted using typical file operations from
within Windows Explorer, for example, with self-protection disabled in
order to reset all client events to an empty state or to reset the
database if there is a suspicion that the database file may be corrupt.
The database file is recreated when the next event is stored.

#### Events do not display in the Client Interface Language chosen.

This is by design, and is a current limitation of the product which a
patch or later version will address. The Event Manager, which runs in
the SYSTEM user context, localizes any localizable event data in the
language of the system/computer before it writes to the DADEvents.db. In
most cases, the system language and the Client Interface Language will
be the same and the user will never see this problem. It is only when
the two languages are different that this problem will exhibit itself.

Another side effect of the current design is all existing events in the
DADEvents.db will always display in the language of the system at the
time the event was written to the database. So if the user switches the
SYSTEM language at a later time, the new language setting will not
affect the existing event table rows, and they will remain in their
original language. Again, this is a limitation that is planned to be
addressed in a subsequent version or patch.

### Policy Settings

Refer Server UI Logger settings section 7.

## Password Protection

### Overview

This feature is used to protect (a) policy settings and (b)
uninstallation by unauthenticated users. This protection is applicable
to all the interfaces using which user can change the policy settings on
the client. User Interface could be a GUI or a console application.
Following flow chart shows the control flow when a user tries to access
policy settings page using client UI application.

Password protection feature is implemented as a business object
(Password BO) in Endpoint Security Platform. It is important to note
that BL framework does not impose any password protection when modifying
policies. It is the responsibility of the client applications to
authenticate with Password BO before allowing user to modify the
policies.

The password policy settings are stored in PwBL.xml file. Please refer
to Files and Folders Overview and Registry Overview sections for more
details.

### Password Types

#### Client interface password

This password is used to unlock the client UI for viewing/modifying the
module settings. The default password is set to ‘mcafee’. When user
changes this password, replace password functionality of the Password BO
is called. Though Password BO has the ability to store multiple
passwords, only one interface password stored in the Password BO and it
is replaced when user changes the password locally or when policy is
enforced from management mode.

*Note:* In case of TPS management mode client interface password is the
company key. Please refer to TPS supportability document for details on
company key.

#### Uninstaller password

This password is used to unlock uninstaller for initiating module
uninstallation. The default uninstaller password is set to ‘mcafee’.
When user changes this password, replace password functionality of the
Password BO is called. Only one uninstaller password stored in the
Password BO and it is replaced when user changes the password locally or
when policy is enforced from management mode.

### Password Mode

Password BO supports following modes.

<table>
<thead>
<tr class="header">
<th>Mode</th>
<th><p>Value</p>
<p>[PASSWORDMODE]</p></th>
<th>Notes</th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Full Access</td>
<td>0</td>
<td>Policy settings are not protected.</td>
</tr>
<tr class="even">
<td>Standard Access</td>
<td>1</td>
<td>User can open the client UI main page, but needs to provide password to access policy settings.</td>
</tr>
<tr class="odd">
<td>Client Interface</td>
<td>2</td>
<td>User needs to provide password in order to open client UI.</td>
</tr>
</tbody>
</table>

PASSWORDMODE is a policy setting for Password BO. Please refer to
PwBL.xsd for all the policy settings.

### Registry

Please refer to the ‘Password BO’ entries under Files and Folders
Overview and Registry Overview sections. Following additional registry
refers to read/update password information.

| Key (x86/x64) | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\PW |                                                                                                      |                                                                                                                                        |
| ------------- | ------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| Name          | Type                                                         | Default                                                                                              | Notes                                                                                                                                  |
| Blob          | BINARY                                                       | Password blob with default passwords as ‘mcafee’ for both interface and uninstaller password fields. | Password hash generated using SHA512 is stored after encrypting using AES\_256\_ECB algorithm                                          |
| Blob1         | BINARY                                                       | Locally generated key                                                                                | This is an additional key used along with inbuilt key to encrypt the password blob to ensure that blob is different on each end point. |

Note: Locally generated key is a secondary key and it is scrambled
before being used. Hence the key stored in the registry is not a
security threat.

### Troubleshooting

| **Log Messages**                | **Type** | **Comment**                                                                                                     |
| ------------------------------- | -------- | --------------------------------------------------------------------------------------------------------------- |
| Failed to create/load container | Error    | Password BO failed to load settings from configuration file possibly due to a corrupt PwBL.xml or LcBL.xsd      |
| Failed to save container        | Error    | Password BO is not able to save settings to configuration file. This may result in loss of settings on restart. |
| Failed to import properties     | Error    | Password BO failed to import settings                                                                           |
| Failed to decrypt data          | Error    | Unable to decrypt data due to internal errors                                                                   |

## Task Scheduler

### Overview

Task scheduler BO is responsible for creating and managing scheduled
tasks. This BO (currently) is a wrapper over MA COM interface for
creating and managing tasks. In Harvey projects a small subset of
scheduler properties are exposed on the UI. The rest of the properties
are kept as default.

Harvey uses MA 5.0 in backward compatibility mode. Previous to MA 5.0
agent services were built for 32-bit platforms and there was no native
64-bit platform support. Harvey supports both 32-bit and native 64-bit
binaries. So in case of 64-bit platform MA COM calls get redirected to
MAComServer.exe which is developed as a part of common module
(out-of-proc COM server) and from within MAComServer.exe actual call to
MA is made. Other than redirecting the calls on 64-bit platform, the
functionality remains some.

### Templates

As scheduler configuration has many settings, Task Scheduler BO provides
default templates, which greatly reduces the number of settings a user
needs to do when creating a scheduled task.

1.  Daily template

2.  Weekly template

3.  Monthly template

4.  Custom template

When user selects Daily/weekly/monthly template, scheduler BO generates
most of the necessary fields internally and submits to MA for
scheduling.

### Features

  - Task management – Allows users to create/delete/modify tasks on
    scheduler. After task is created on scheduler BO, it should be
    assigned to MA with the details such as caller software Id, task Id,
    etc.

  - Query managed tasks – Managed tasks are those tasks which are
    created by ePO. This allows a user to query managed tasks present in
    the given system. The client UI uses this feature to enable/disable
    editing of tasks from the client UI.

  - Query unmanaged tasks – Unmanaged tasks are the tasks that are
    created locally on the client machine.

### Troubleshooting

| **Log Messages**         | **Type** | **Comment**                                                                                                                                   |
| ------------------------ | -------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Failed to load container | Error    | Task Scheduler BO failed to load settings from configuration file possibly due to a corrupt TaskSchedulerBL.xml or TaskSchedulerBL.xsd        |
| Failed to save container | Error    | Task Scheduler BO is not able to save settings to configuration file. This may result in loss of settings on restart.                         |
| queryData failed         | Error    | Invalid xpath is passed to scheduler. This can happen when the schema is changed (TaskScheduler.xsd), but the caller is using the old schema. |
| assignData failed        | Error    | Invalid data is passed to scheduler. This can happen when the schema is changed (TaskScheduler.xsd), but the caller is using the old schema.  |
| Failed to delete task    | Error    | Failed to delete a task from MA.                                                                                                              |
| Commit did not succeed   | Error    | Commit o MA did not succeed.                                                                                                                  |

## Logger

Logger functionality is provided with the Logger BO and Loglib library.
Logger BO is used to configure the logging options for all Modules and
Technologies. Log library is used for actual logging of all Modules and
Technologies.

### Overview

![](./media/image31.emf)

![](./media/image31.emf)

![](./media/image31.emf)

![](./media/image32.emf)

![](./media/image31.emf)

Log configurations and Logging flow are explained in the above diagrams.
Log configurations are exposed at Client UI and policy page from ePO.
Client UI Logger settings are explained at section 5.6.3 and Server
Extension Logger settings are explained at section 7. Based on logger
settings, Logger BO processes and saves settings into loggerbl.xml file.
Then Logger BO passes configurations to loglib library. Loglib library
saves configurations into logcfg.ini file.

Loglib library reads “enabled” and “filter” properties from
configuration file during LOG request. If enabled set to true and filter
matches, logs are written to the file. Log file is created if the file
is not present. Logging happens in three different mechanisms.

1.  Activity: Activity logs are customer facing logs and all the
    activities a BO/Module performs are logged to activity log.

2.  Debug: Debug logs are developer/QA/support team facing logs and all
    the debug logs a BO/Module performs are logged to debug log.

3.  Error Log: These logs are actual failures and all the error logs a
    BO/Module performs are logged to error log.

### Configuration File (Logcfg.ini)

Configuration file has multiple sections whereas each section is for one
log configuration. Each section has following elements explained with an
example.

Example:

> \[SelfProtection\_Activity\]
> 
> type=file
> 
> filename=%DEFLOGDIR%/SelfProtection\_Activity.log
> 
> filter=\*.SP|ApBl.Activity
> 
> format=%A %P(%p.%t) \<%U\> %f.%F.%l: %m
> 
> MaxSize=10485760
> 
> TruncateBy=25
> 
> LimitSize=1
> 
> encoding=UTF-8
> 
> enabled =1

  - Section Name: Loglib library uses configuration attributes based on
    section name. Loglib reads respective section from configuration
    file and logs based on the configurations set in the section.in to
    the file specified with the filename attribute considering other
    attributes.

> Ex: **SelfProtection\_Activity** is the section name from above
> example.

  - Type: Type indicates logging destination and supported destinations
    are file, OutputDebugString and Syslog, which are explained in
    detail at Section 5.6.5 . From the example “File” is the log
    destination.

  - Filename: Name of the file to which logging happens. If the full
    file path including directory is not specified, default path is
    considered. Default path is “\< ProgramData\>\\McAfee\\Endpoint
    Security\\Logs”
    
    **Note**: Default path for XP/2003 is “\<Documents and
    Settings\>\\All Users\\Application Data\\ McAfee\\Endpoint
    Security\\Logs”

Ex: “SelfProtection\_Activity.log” is the file name created at first
request and logs are written to the file.

  - Filter: Log statements are logged to specific log file based on a
    filter. Filter comprises three parts separated by dots.
    \<facility\>.\<topic\>.\<severity\>.

Facility is defined by the originating DLL/Exe. Facility is also used as
Wildcard (\*) for any facility.

Topic name is used in the LOG API to write the logs containing topic
name to the log file. Multiple topic names can be ‘OR’ed by using ‘|’
character.

Severity is detected by the LOG API and used for logging. Example: Refer
highlighted part of the logger API, LOG\_**ERR**, LOG\_**ACTIVITY**,
LOG\_**DBG**

**Ex:** Following are the **f**ilter examples

**\*.SP|ApBl.Activity**

Log statements originating from DLL/Exe with any facility name, but
topic name as SP or ApBL and calling LOG\_ACTIVITY () API, will be
logged.

**AM.OAS|ODS|QM.Debug**

Log statements originating from DLL/Exe which has defined facility as AM
and topic name as “OAS” or ”ODS” or ”QM” and calling LOG\_DBG() API,
will be logged.

  - MaxSize: It indicates the maximum size of log file. Default Max size
    is 10MB. Ex: From example, Maxsize log can grow upto **10MB**
    equivalent to 10485760 bytes.

  - TruncateBy: This is Size in percentage at which the file can
    truncate after reaching to Max Size. Ex: file is truncated **25**%
    (2.5MB) of max size after reaches max size 10MB.

  - LimitSize: It is a Boolean flag, takes value either 0 OR 1 to
    determine whether to limit the size of the log to the value
    specified by MaxSize. A value of 1 indicates Limit the log size and
    value of 0 indicates don't limit.

  - Encoding: It is an Output log file encoding format, Can be one of
    ANSI, or **UTF-8** or UNICODE.

  - Enabled: Logging is controlled by this attribute, Logging is enabled
    if the value is 1 and logging is disabled if the value is 0. Default
    value is 1.

  - Format: is used to specify any of below attributes.

<!-- end list -->

  - %A Date and time in current user locale

  - %a Date and time in system default locale

  - %d date in local time, specify '+' prefix for year in the
    format(YYYY-MM-DD)

  - %D date in local time, specify '+' prefix for year in the
    format(MM/DD/YYYY)

  - %f facility or subsystem name

  - %F topic name

  - %i session id

  - %l level

  - %L source line number

  - %m the message (you probably want this\!)

  - %p process id (hex or decimal integer)

  - %P process name

  - %s source filename (string)

  - %t thread id (hex or decimal integer)

  - %T time in local time, specify '+' to add ms

  - %U user name

  - %w window station

### Client UI Logger Settings

  - LogFileLocation: Logger BO sets the log file location where all
    module log files are generated. Default path is
    “\<ProgramData\>\\McAfee\\Endpoint Security\\Logs”
    
    **Note**: Default path for XP/2003 is “\<Documents and
    Settings\>\\All Users\\Application Data\\ McAfee\\Endpoint
    Security\\Logs”

  - Activity Logging:

<!-- end list -->

  - Enable Activity Logging: This is one option for all modules and
    Enable/Disable Activity logging will enable/disable activity logging
    of all modules. Default value is enabled.

  - Log all scanned files during on-demand scans: this option allows the
    user to log every single file scanned during On-Demand Scans (Quick,
    Full, Right-Click and Custom) into the OnDemandScan\_Activity.log
    file. If a specific action is taken against one or more files, it
    will be logged as well. Default value is disabled.

  - If ODS scan logging is enabled, it is recommended to increase the
    activity log max file size to 100MB.

  - Note: Files in the clean scan cache are not scanned, so they will
    not appear in the log.

<!-- end list -->

  - Language: This option allows the user to select the language in
    which activity logs are written. All currently supported languages
    are an option as well as an automatic selection. If automatic is
    selected, the activity logs will be written in the system locale
    language. If the system language can’t be found, the activity logs
    will default to English.

<!-- end list -->

  - Debug Logging: Enabling Debug logging for any of below module will
    also enable debug logging of Self Protection, Endpoint Security
    Platform and MFEConsole. Disabling debug logging of all below
    modules will automatically disable debug logging of Self Protection,
    Endpoint Security Platform and MFEConsole. Debug logging is disabled
    by default.

<!-- end list -->

  - Enable for Threat Prevention: Enable/Disable Debug logging of Threat
    Prevention allows to enable/disable logging of individual TP
    features, which includes AP, BOP, OAS and ODS.

<!-- end list -->

  - Enable for Access Protection: Enable/Disable Debug logging for AP.

  - Enable for Exploit Protection: Enable/Disable Debug logging for BOP.

  - Enable for On-Access Scanner: Enable/Disable Debug logging for OAS.

  - Enable for On-Demand Scanner: Enable/Disable Debug logging for ODS.

<!-- end list -->

  - Enable for Firewall: Enable/Disable Debug logging for Firewall.

  - Enable for WebControl: Enable/Disable Debug logging for Web Control.

  - Limit Size of each Debug Log File: Size is allowed between 1 to 999
    MB including historical data. Default size is 50 MB. Files will be
    truncated beyond 10MB from the bottom of the file.

### Log Sinks and Log structure.

Loglib library facilitate following sinks as different destinations for
logging.

  - LogFile Sink: File is the log destination and this type of logging
    is configured by “Type = file” attribute in logcfg.ini configuration
    file.

> **Example:** Log statements contain information about date, time
> (UTC), level, facility, process name, process id, thread id, topic,
> file name with number of line, and log message.
> 
> **Header:** In order to show more readable information, from 10.7
> every new file will contain the following header:
> 
> DATE | TIME(UTC) | LEVEL | FACILITY | PROCESS | PID | TID | TOPIC |
> FILE\_NAME(LINE) | MESSAGE
> 
> **Activity Log:**
> 
> 2019-09-11 02:42:37.175Z|Activity|EpService           |mfeesp
>                    |      2492|      7640|mfeesp
>              |EpService.cpp(1503)                     |
> Product version: 10.7.0.1204  
> 2019-09-11 02:42:37.175Z|Activity|EpService           |mfeesp
>                    |      2492|      7640|mfeesp
>              |EpService.cpp(1710)                     |
> Starting service...  
>  
> 
> DATE: 2019-09-11
> 
> TIME (UTC): 02:42:37.175Z
> 
> LEVEL: Activity.
> 
> FACILITY: EpService
> 
> PROCESS: mfeesp.
> 
> Process Id (PID): 2492.
> 
> Thread Id (TID): 7640.
> 
> TOPIC: mfeesp
> 
> FILE\_NAME (LINE): EpService.cpp(1503)
> 
> MESSAGE: Product version: 10.7.0.1204
> 
> *(HH:MM:SS.000Z 24hr time format, UTC time, see
> <https://en.wikipedia.org/wiki/ISO_8601>)*
> 
> **Error Log:**
> 
> 2019-09-11 02:43:08.002Z|Error   |AMSI                |mfetp
>                    |      1800|      7720|AMSI
>                |MfeAmsiModule.cpp(905)
>                  | Found another active AMSI provider
> ID {2781761E-28E0-4109-99FE-B9D127C57AFE}, McAfee AMSI may not work
> properly
> 
> 2019-09-11 02:43:08.002Z|Error   |AMSI                |mfetp
>                    |      1800|      7720|AMSI
>                |MfeAmsiModule.cpp(925)
>                  | Found another active AMSI provider
> ID {2781761E-28E0-4109-99FE-B9D127C57AFE}, McAfee AMSI may not work
> properly for 32 bit applications  
> 
>  
> 
> **Debug Log:**
> 
> 2019-09-12 10:38:28.307Z|Debug   |blframework         |mfetp
>                    |      4900|     10488|blserver
>            |blserverimp.cpp(1811)                   |
> FreeMcVariant(AMSI)  
> 2019-09-12 10:38:28.307Z|Debug   |McTray              |McTray
>                    |     11004|     10644|McTrayUPC
>           |TechnologyTopicHandler.cpp(129)         |
> CheckTechnologyState: boName: AMSI, enabledState: 1, desiredState: 1

**Note**: LogFile sink is used in Harvey and none of below sinks are not
being used. Below sinks may be used in post Harvey.

  - Debug String Sink: Debugger is the log destination and logs are sent
    to the Debug view debugger. This is configured by “Type =
    OutputDebugString” attribute in logcfg.ini configuration file.

  - ETW Sink:

<!-- end list -->

  - Sys/Remote Sink: Remote location is log destination and this is
    configured by “Type = syslog” attribute in logcfg.ini configuration
    file. Additionally, two configuration properties under the same
    section which are port=\<port number \> server=\<server ip address\>
    should be configured.

### Debugger Logger Logs 

Loglib library sends critical logs to debugger when debug logging is
enabled. Debug logging can be enabled with Registry configuration
“dwIsDebugOutputEnabled =1” at
“HKLM\\SOFTWARE\\McAfee\\Endpoint\\Common\\Log”.

This configuration can be enabled for trouble shooting logging issues
and below are few errors sent to the debugger.

Example:

  - Error creating a file map for the log file

  - Failed to open %s file

  - Failed to get root directories

### Troubleshooting 

#### Logging doesn’t happens at newly set log location with environment variable

Check environment variable exists and created before configuring log
path.

#### Logging doesn’t happens at newly set log location from ePO policy

Check policy enforcement applied. Check UI Logger settings and
logcfg.ini file updated with newly set log path.

#### Logging doesn’t happen at newly set log location from UI logger settings.

Check mfeesp service is running. Start/stop the service and check
logcfg.ini file updated with newly set log path.

#### All logging ceases if log path is set to a folder with Japanese (Mulitbyte) characters from either UI or policy from ePO.

Change Logcfg.ini file encoding to UCS-2 Little Endian.

#### Changing log location do not change the log location for all debug/activity logs

Check logcfg.ini file for the sections that are not changed the log
location and verify those sections are controlled by logger. Logger
controls all module and technology debug and activity logs and doesn’t
control like firewalleventmonitor, tpsinstall, tpsrumor, etc.

#### LOG Set path for UNC path is not working

Logger path doesn’t support UNC path.

#### Error log shows “Failed to Load Container”

Loggerbl.xml or loggerbl.xsd files are not existent/corrupted/not
complaint to xml standards.

#### Error log shows “Failed to set Path (\<FILENAME\>) for \<SECTION NAME\>”

Check section Name exists in the logcfg.ini file. Check filename and
path is valid. Verify loglib.dll is loaded in mfeesp.exe

#### Error log shows “Failed to find technology name”

Check Technology name queried for log debug status is valid.

#### Error log shows “Failed to SetLogPathForMERTool”

Check “HKLM\\SOFTWARE\\McAfee\\Endpoint\\Common\\Logger” Registry key
exists. Verify log path has set correct value from UI settings.

### Policy Settings

Refer Client/Server UI Policy settings section 7.

###   

## System Information

### Overview

Systeminfo BO is used to provide user and system information for the
subscribed modules or technologies. User information includes user
idle/busy, Session logon/logoff and Full screen mode On/Off. System
information includes Disk idle/busy, Ram usage, Disk Usage, System Time
change, and power details which will be described in detail in the
following sections. Systeminfo BO posts these notifications when the
user and system state is changed. BO also provides the information when
module query for it.

### Default values:

Systeminfo BO reads the registry for the below properties and sets the
values. If the registry keys are **not** found, default values are set.

<table>
<thead>
<tr class="header">
<th>Key (x86/x64)</th>
<th>HKEY_LOCAL_MACHINE\SOFTWARE\McAfee\EndPoint\Common\ SYSTEMINFO</th>
<th></th>
<th></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Name</td>
<td>Type</td>
<td>Default</td>
<td>Notes</td>
</tr>
<tr class="even">
<td>BytesPerSec</td>
<td>DWORD</td>
<td>350000</td>
<td>Disk usage in terms of bytes per second used to evaluate disk state with the total disk usage</td>
</tr>
<tr class="odd">
<td>DiskPercentage</td>
<td>DWORD</td>
<td>90</td>
<td>Disk percentage used to evaluate Disk state with the actual consumed disk percentage of mcafee process</td>
</tr>
<tr class="even">
<td>McProcList</td>
<td>String</td>
<td><p>Mfetp</p>
<p>Mfeesp</p>
<p>Mcshield</p>
<p>Mfevtps</p>
<p>NaPrdMgr</p>
<p>Mfecore</p>
<p>Mfefire</p>
<p>McAfeeFramework</p>
<p>McTray</p></td>
<td>McAfee process list considered to evaluate Disk usage.</td>
</tr>
</tbody>
</table>

### Systeminfo Notifications

  - **User/System Idle**: User idle is when both user input from
    mouse/keyboard and disk are idle. System info BO retrieves current
    user state for every 30 seconds and verify with the previous value
    from the registry. If the User state is changed to user Idle or
    busy, BO post the notification either user Idle or busy.
    
    Registry:

<!-- end list -->

  - key - “dwIsUserIdleSinceLastCheck”

  - Path-
    “HKEY\_CURRENT\_USER\\SOFTWARE\\\\McAfee\\\\Endpoint\\\\Common\\\\BusinessObjectRegistry\\\\SYSTEMINFO”.
    
    Example: On-Demand Scan subscribes for user idle notification and
    receives notification from Systeminfo BO. If the ODS Scan is
    scheduled to run when user is idle, scan pauses when user is busy
    and resumes when user is idle. At scan start time, ODS BO queries
    Systeminfo BO for user state and starts only if the user is idle.

<!-- end list -->

  - **Disk Idle**: Disk idle is true if the total disk usage is lower
    than “BytesPerSec” threshold. Incase total system disk usage is
    higher than “BytesPerSec“ and if disk percentage usage of mcafee
    process is higher than “DiskPercentage” threshold then Disk idle is
    false, otherwise Disk Idle is true.

  - **Full screen mode**: Full screen mod is on when an application is
    launched in full screen. System info BO retrieves current full
    screen mode state for every 30 seconds and verify with the previous
    value from the registry. If the full screen mode state is changed to
    ON or OFF, BO post the notification either full screen mode is ON or
    OFF Idle or busy.
    
    Registry:

<!-- end list -->

  - key - “dwIsFullScreen”

  - Path-
    “HKEY\_CURRENT\_USER\\SOFTWARE\\\\McAfee\\\\Endpoint\\\\Common\\\\BusinessObjectRegistry\\\\SYSTEMINFO”.
    
    Example: On-Demand Scan subscribes for full screen mode notification
    and receives notification from Systeminfo BO. If the ODS Scan is
    scheduled to run when full screen mode is OFF, scan pauses when
    screen mode is ON and resumes when screen mode is OFF. At scan start
    time, ODS BO queries Systeminfo BO for screen mode state and starts
    only if the screen mode is OFF.

<!-- end list -->

  - **RAM usage:** Systeminfo BO notifies RAM usage and usage could be
    either below or above threshold value for every 30 seconds.

  - **Power details**: Systeminfo BO provides power details for any
    module queries and applicable to laptop. Power details are

<!-- end list -->

  - Power Type: Power plug is in or out.

  - Remaining in percentage

  - Remaining in time in seconds.

<!-- end list -->

  - **Is running on battery**: This is applicable to laptop and true if
    the power cable is disconnected. This property is false if power
    cable is connected. Systeminfo BO provides this information for any
    module queries.

### Windows Notifications

Systeminfo BO registers below windows notifications and publishes the
events.

  - **Session Logon:** This is notified when user is log on.

  - **Session Logoff:** This is notified when user is log off.

  - **System Clock Change:** This event is published when System time is
    changed.

  - **Power State Change:** This is applicable for laptop and notifies
    when power status changes, i.e., when battery is low, power cable
    plugged in or off. Suspended or suspend resumed.

### Troubleshooting

#### Systeminfo BO is not polling notifications immediately after system reboot.

Systeminfo BO poll notifications after 120 seconds of reboot.

#### Systeminfo BO is not polling user log ON/OFF notifications.

Check WTSSession property is enabled in loggerBL.xml. Check mfesp
service is running.

#### ODS Scan runs when user is not idle/presentation mode is on /running on battery.

> Check mfesp service is running. Check ODS Task properties and verify
> run task only when user is idle/presentation mode is off /not running
> on battery

#### Systeminfo BO is not polling User/System Idle and Presentation mode ON/OFF notifications.

> Check mfesp service is running. Check Registry keys
> “dwIsUserIdleSinceLastCheck” and “dwIsFullScreen” present at
> “HKEY\_CURRENT\_USER\\SOFTWARE\\\\McAfee\\\\Endpoint\\\\Common\\\\BusinessObjectRegistry\\\\SYSTEMINFO”.

## Common Package Manager

### Overview

The Common Package Manager (CPM) which is part of the Endpoint Security
Platform Module is designed to act as an intermediary between package
consumers (the Modules) and package suppliers (MA/ePO, TPS/NOC) so that
the consumers don’t need to know where the package is coming from and
the suppliers don’t need to interact with consumers.

The CPM would also interact with any UI elements so the suppliers can
focus on providing the content.

Currently a package can either be content or product update.

To determine what packages are needed by the various modules installed
on a client the CPM uses the Package Topic. This topic gives the ability
for a Modules business objects to provide information on what packages
it uses to update content and products, and to report the current status
of its packages.

By default the package supplier for MA is always installed with the name
PKGSUPPLIER\_MA, The CPM will look for the TPS supplier with the name
PKGSUPPLIER and will use it if it's found. The PKGSUPPLIER\_MA remains
installed and loaded since in the TPS environment the MA supplier is
needed to disable all the sitelist repository entries.

The CPM also supports the Tasks Topic for UPDATE tasks.

Functionality supported by the CPM:

  - Interacts with suppliers to update content and packages.

  - Provides Show Update Now property for the local UI.

  - Provides a generic interface to modify site/repository lists.

  - Provides support for UPDATE tasks.

  - Generates notification progress messages during updates.

  - Generates log entries and ePO events during updates.

  - Provides import of legacy sitelist

  - Provides support for MIRROR tasks

### High-Level Component Diagram / Data Flows

### Components

#### The Package Topic

The package topic is the mechanism used to associate packages with a
Module so the Common Package Manager can determine at runtime which
packages need to be downloaded depending on what Modules are installed
and if it going to process content packages and/or Hotfixes/Patches . A
business object within a Module indicates it uses the Package Topic by
setting the DWORD value EP\_TOPIC\_NAME\_PCO\_PACKAGE to 1 in its Topics
registry location.

#### The Package Supplier Module (PSM)

The CPM interacts with a repository to download packages to the local
client. During the download process the PSM interacts with the CPM
through the ‘ReportStatus’ method to report the download progress.

There are two PSM’s in Harvey, one for MA/ePO and one for TPS/NOC. The
MA supplier uses the business object name of PKGSUPPLER\_MA and the TPS
supplier uses the name of PKGSUPPLIER. When the CPM does an update it
always checks for PKGSUPPLIER and if found will switch to using it,
otherwise it will use the MA supplier which is always loaded.

The PSM also supplies the CPM with a list of features supported by the
PSM. These features are:

  - SelectableUpdates – bool, Indicates the supplier can selectively
    download packages

  - MirrorTask - bool, The supplier supports mirror tasks

  - UpdateTask - bool, The supplier supports update tasks

  - EditSiteList - bool, The supplier has editable site lists

  - Mode – int, The supplier mode, can be one of:
    
      - 0 – Unknown
    
      - 10 – MA Standalone
    
      - 11 – MA On Prem
    
      - 12 – MA Cloud
    
      - 20 – TPS

The PSM supplies these features to the CPM through the
EP\_PSM\_METHOD\_GET\_FEATURES method, if that method is not supported
the CPM defaults to just UpdateTask set to true.

The CPM calls the supplier method “UpdateNow” to kick off an update and
does this on a separate thread so the PSM won’t block the CPM, so it’s
very important that the PSM calls the ReportStatus method with the
proper finished status code when the update is done so the CPM knows
when the update has completed, just returning from the “UpdateNow” is
not enough.

#### The Package Consumer Object (PCO)

The PCO uses content that is downloaded by the PSM and needs to support
the package topic for any packages it supports.

In some cases the PCO needs to be called to consume a package that has
been downloaded, it indicates this by setting the CallConsume property
to true in the package topic. Then during the update process the method
EP\_PCO\_METHOD\_CONSUME is called for a PCO to consume the downloaded
package. The PCO should not return from the call until it is done
processing the content and should return the status in the DataOut
parameter defined in TopicPackageDefs.h.

The information supplied in the DataOut structure indicates to the PSM
the results of the update for that Module and reports the resulting
version.

#### The Common Package Manager (CPM)

The CPM is the main interface for working with packages. To help manage
packages the CPM adds the concept of categories where a category is just
a collection of package types, and categories are associated with UPDATE
tasks.

In Harvey we support two categories, one named ‘Product’ and the other
named ‘Content’. The Content category is used to specify packages that
only update content/dats used by the various PCO’s and is set to ‘DAT’
by default. The Product category is used to specify packages that would
update code such as hotfixes and patches, the default for Product is
‘HOTFIX;PATCH’.

So when an UPDATE task is run it checks to see what categories are
enabled for that task and then builds a list of what package types need
to be updated. Once the package types are known, the CPM queries the
objects that support the package topic and determines the list of
ProductIds that are associated with the package types. Once the list of
package ids is constructed the CPM passes that list on to the Package
Supplier Module (PSM) as an argument to the UpdateNow method.

You can change the package types associated with a category through the
DefinedCategories property.

The CPM stores its properties on disk in the file PackageMgr.xml in the
Endpoint Security Platform folder. The SiteList and Feature properties
are not stored in the xml file since they are retrieved from the PSM any
time they are requested

On start-up the CPM always checks to see if the default update task
PKGMGR\_DEFAULT\_UPDATE\_TASK\_ID exists, if not it will create it since
it is used to when the CPM method UpdateNow is called. The CPM will also
create the default schedule PKGMGR\_DEFAULT\_UPDATE\_TASK\_SCHEDULE\_ID
when the default task is created.

The CPM supports the task topic so that interface can be used to
manipulate tasks. The CPM just adds the extra task property
EnabledCategories to add the ability to enable/disable the categories
for different tasks.

### The Update Process

When an update task is initiated in the CPM, either through a scheduled
local task, one defined via ePO Policy, or from invoking UpdateNow from
the local UI, the CPM builds a list of package ids as described above.
Once the list of ids is generated it is sent to the package supplier
module.

The MA supplier module has the ability to use the list of ids to update
only specific packages while the TPS supplier module will always update
all packages that are out of date.

During the update process the supplier modules will generate status
messages that any framework object can listen for. The notification that
is sent has the id of PKGMGR\_NOTIFY\_REPORT\_STATUS (0x2004) and will
come from the CPM with a severity of INFORMATIONAL. The notification
events provide information as to the status of the update, as well as
the state and message that can be displayed to the end user. These
messages will also be written to the activity log.

The CPM will also generate ePO events of:

  - Running – id = 1120

  - Finished ok – id = 1118

  - Finished Cancelled – id 1121

  - Finished Failed – id 1119

During the update process each package that is updated validates if it
is licensed. The PSM module does this by querying the License Manager to
see if the Module a package belongs to is licensed. If the Module is not
licensed then it will not be updated. The only package that uses this
method in Harvey is the Exploit Prevention content.

### Policy Settings

The end user has the capability to decide what type of content will be
updated through policy settings. These settings are:

  - Security content, hotfixes, and patches

  - Security content

  - Hotfixes and patches

The end user can also modify the source site from where they will
receive updates when using MA from the local UI.

### Files

#### Default File disposition on 32 and 64 bit systems

| Default File Path    | \<Program Files\>\\McAfee\\Endpoint Security\\Endpoint Security Platform |
| -------------------- | ------------------------------------------------------------------------ |
| File Name            | Notes                                                                    |
| **PackageMgr.dll**   | Dll that contains the framework object for PKGMGR                        |
| **PackageMgr.xml**   | Contains the persistent package manager properties                       |
| **PackageMgr.xsd**   | The xml schema definition for the pkgmgr properties                      |
| **MaPkgSuppler.dll** | Dll that contains the framework object for the MA supplier               |

### Registry

#### Common Package Manager Registry Keys

Registry:

| Key            | HKLM\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\PKGMGR |                            |                      |                                             |
| -------------- | ------------------------------------------------------------------------ | -------------------------- | -------------------- | ------------------------------------------- |
| Name           | Type                                                                     | Default                    | Valid Values         | Notes                                       |
| **DllName**    | STRING                                                                   | PackageMgr.dll             | \-                   | Dll that supports the PKGMGR framework BObj |
| **Enable**     | DWORD                                                                    | 1                          | 0,1                  | Specifies if obj is loaded into the service |
| **InstallDir** | STRING                                                                   | \<ESPFolder\>\*            | \-                   | Location of dll                             |
| **DataDir**    | STRING                                                                   | \<ESPFolder\>\*            | \-                   | Location of support files                   |
| **LoadOrder**  | DWORD                                                                    | 1                          | (see framework docs) | Order obj is loaded into service            |
| **ModuleName** | STRING                                                                   | Endpoint Security Platform | \-                   | Endpoint Component                          |
| **Service**    | STRING                                                                   | Mfeesp.exe                 | \-                   | Service module runs under                   |
| **Version**    | DWORD                                                                    | 1000 (0x03e8)              | \-                   | Build version of the object                 |

\* \<ESPFolder\> maps to \<Program Files\>\\McAfee\\Endpoint
Security\\Endpoint Security Platform

#### Common Package Manager Registry Keys

Registry:

| Key                       | HKLM\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\PKGMGR\\Topics |         |              |                                       |
| ------------------------- | -------------------------------------------------------------------------------- | ------- | ------------ | ------------------------------------- |
| Name                      | Type                                                                             | Default | Valid Values | Notes                                 |
| **EP\_TOPIC\_NAME\_TASK** | DWORD                                                                            | 1       | 0,1          | Indicates CPM supports the Task Topic |

#### MA Package Supplier Registry Keys

Registry:

| Key            | HKLM\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\ PKGSUPPLIER\_MA |                            |                      |                                             |
| -------------- | ---------------------------------------------------------------------------------- | -------------------------- | -------------------- | ------------------------------------------- |
| Name           | Type                                                                               | Default                    | Valid Values         | Notes                                       |
| **DllName**    | STRING                                                                             | MaPkgSupplier.dll          | \-                   | Dll that supports the PSM for MA            |
| **Enable**     | DWORD                                                                              | 1                          | 0,1                  | Specifies if obj is loaded into the service |
| **InstallDir** | STRING                                                                             | \<ESPFolder\>\*            | \-                   | Location of dll                             |
| **DataDir**    | STRING                                                                             | \<ESPFolder\>\*            | \-                   | Location of support files                   |
| **LoadOrder**  | DWORD                                                                              | 1                          | (see framework docs) | Order obj is loaded into service            |
| **ModuleName** | STRING                                                                             | Endpoint Security Platform | \-                   | Endpoint Component                          |
| **Service**    | STRING                                                                             | Mfeesp.exe                 | \-                   | Service module runs under                   |
| **Version**    | DWORD                                                                              | 1000 (0x03e8)              | \-                   | Build version of the object                 |

\* \<ESPFolder\> maps to \<Program Files\>\\McAfee\\Endpoint
Security\\Endpoint Security Platform

### Logging and Errors

During an update the CPM will write localized messages to the file
PackageManager\_Activity.log and if debug is on it will write its
messages to the file EndpointSecurityPlatform\_Debug.log. The debug log
is enabled when the Endpoint Security Platform component is enabled.

#### Default File disposition on a 32 and 64bit systems

| Default File Path                       | \<Program Data\>\\McAfee\\Endpoint Security\\Logs |
| --------------------------------------- | ------------------------------------------------- |
| File Name                               | Notes                                             |
| **PackageManager\_Activity.log**        | Translated messages when doing an update          |
| **EndpointSecurityPlatform\_Debug.log** | Detailed debug messages                           |

### Troubleshooting

If an update fails if can happen in three places.

1.  The CPM to PSM communication failed and an update was not initiated.

2.  The PSM started the update process but couldn’t process any
    packages.

3.  The packages were being process but an individual package update
    failed.

You can check the activity log to determine where the failure occurred.
If you don’t see any messages that an update is in progress then it is
case 1 and the issue is with the CPM. If you see update progress
messages but don’t see any messages about files being downloaded then it
is probably case 2 and the issue probably lies with the PSM (either TPS
or MA), if it’s MA you will need to view their logs to determine why the
update failed. If you see files being downloaded but the update didn’t
finish successfully then its case 3 and the issue lies with component
that produced and uses the package being processed.

Please ensure the following are included in any escalation to
engineering:

  - All Endpoint files from %ProgramData%\\McAfee\\EndpointSecurity

  - All MA logs from %ProgramData%\\McAfee\\Agent\\logs

  - All MA .db’s from %ProgramData%\\McAfee\\Agent\\DB

### Potential Call Generators

**Update Progress Dialog Box does not close:** Probably due to MA or TPS
not sending a message indicating update has finished. You would need to
collect all logs and if they can enable debug and reproduce the issue
that would be very helpful.

### Mirror Tasks

A mirror task provides the ability to copy a data repository used for
updates from one location to another and is only supported by the MA
supplier. Mirror tasks are configured through the ENS Client UI common
settings page.

### SiteList Import/Export

This ability allows MA sitelists from previous versions of MA to be
imported into the current environment and provides the ability to export
one client’s current sitelist so it can be imported into a different
Endpoint client.

## Self-Protection

Please refer
‘Supportability\_McAfee\_Endpoint\_Security\_Threat\_Prevention\_10.docx”
supportability document for details on this topic

### McAfee Protection Global Exclusions

Some of AAC rules like AAC rules for Self-Protections keep enabled even
disabled the Self- Protections on ENS installed systems. And it can
cause of access block of important process for customer’s work.

To prevent it McAfee Protection Global Exclusions provide feature that
exclude the important processes temporarily from all AAC rules including
other point product rules and self-protection rules of components (like
AMCore, MPT, and MA). This feature can configure only via to ePO. (The
configuration is locating on Endpoint Security Common settings.)

To exclude specified processes, customer need to specify process name
(full path required and it should contain on of these: ‘\\\\’, ‘:\\’, or
‘%\<environment variable\>%’), and process MD5 hash or Signer
Certificate MD5 hash.

**How to get Process MD5 hash & Signer certificate MD5 hash:**

Valid process MD5 hash (which customer would like to exclude) can be
obtained using Microsoft’s certutil.exe tool that is installed on the
system by default.

Eg: certutil.exe –hashfile “C:\\Windows\\System32\\icacls.exe” MD5

![](./media/image33.png)

Valid Signer certificate MD5 hash can be obtained using SystemCore tool
Vtpinfo.exe with /validatemodule option. (ENS installs the SystemCore so
this tool available on the system which installed ENS.)

Eg: C:\\Program Files\\Common Files\\McAfee\\SystemCore\\vtpinfo.exe
/validatemodule

![](./media/image34.png)

The McAfee Protection Global Exclusions applies the exclusion items when
received ESP policy as part of CommonLPC function so the function tries
to log debug and error information to Endpoint Security Platform logs.

**Note:** That keep exclude Global AAC Exclusions item(s) from AAC rules
can cause of important security issue. To prevent it please remove
Global AAC Exclusions items immediately after finished your process
which blocked by AAC rules.

**How to confirm whether the Global AAC Exclusions items are applied on
client system:**

Global AAC Exclusions configures AAC rules by AAC functions. So, you can
confirm it that use SystemCore tool AACInfo.exe. Please find “ENS-AAC
Global exclusion policy” from the AACInfo result. If Description
containing the string, the policy is for Global AAC Exclusions.

Eg: C:\\Program Files\\Common Files\\McAfee\\SystemCore\\AACInfo.exe
query

\<AacPolicy PolicyGuid="1d3b9679-a8d0-451e-bd26-00285a1445b6"
IsSticky="true"\>

\<Description\>ENS-AAC Global exclusion policy\</Description\>

\<AacRule RuleGuid="f1d4984c-2909-49a4-9260-55e646862e18"
GroupTag="Default" ReactionType="AAC\_REACTION\_EXCEPTIONAL\_ALLOW"
ReportEvent="false" IsEnabled="true"\>

\<Description\>Add Exceptional Allow Access for following
processes\</Description\>

\<AacSubRule Role="AAC\_ROLE\_INITIATOR"\>

\<AacMatchObject ObjectType="AAC\_OBJECT\_PROCESS"\>

\<AacMatchData MatchType="AAC\_MATCH\_OBJECT\_NAME"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"\>

\<TYPE\_STRING\>C:\\WINDOWS\\SYSTEM32\\DLLHOST.EXE\</TYPE\_STRING\>

\</AacMatchData\>

\<AacMatchData MatchType="AAC\_MATCH\_MD5" MatchOp="AAC\_OP\_INCLUDE"
IsRange="false"\>

\<TYPE\_BLOB\>9361355721f51e3a25df53702d10e9de\</TYPE\_BLOB\>

\</AacMatchData\>

\</AacMatchObject\>

\</AacSubRule\>

\<AacSubRule Role="AAC\_ROLE\_INITIATOR"\>

\<AacMatchObject ObjectType="AAC\_OBJECT\_PROCESS"\>

\<AacMatchData MatchType="AAC\_MATCH\_OBJECT\_NAME"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"\>

\<TYPE\_STRING\>C:\\WINDOWS\\SYSTEM32\\CONSENT.EXE\</TYPE\_STRING\>

\</AacMatchData\>

\<AacMatchData MatchType="AAC\_MATCH\_MD5" MatchOp="AAC\_OP\_INCLUDE"
IsRange="false"\>

\<TYPE\_BLOB\>600d506fea867e0baeaffefce54f35b3\</TYPE\_BLOB\>

\</AacMatchData\>

\</AacMatchObject\>

\</AacSubRule\>

\<AacSubRule Role="AAC\_ROLE\_TARGET"\>

\<AacMatchObject ObjectType="AAC\_OBJECT\_FILE"\>

\<AacMatchData MatchType="AAC\_MATCH\_OBJECT\_NAME"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"\>

\<TYPE\_STRING\>\*\*\</TYPE\_STRING\>

\</AacMatchData\>

\<AacMatchData MatchType="AAC\_MATCH\_ACCESS\_MASK"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"
RequiredBits="0x8000000000000000"\>

\<TYPE\_BITMASK\>0xb\</TYPE\_BITMASK\>

\</AacMatchData\>

\</AacMatchObject\>

\</AacSubRule\>

\<AacSubRule Role="AAC\_ROLE\_TARGET"\>

\<AacMatchObject ObjectType="AAC\_OBJECT\_KEY"\>

\<AacMatchData MatchType="AAC\_MATCH\_OBJECT\_NAME"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"\>

\<TYPE\_STRING\>\*\*\\\*\*\</TYPE\_STRING\>

\</AacMatchData\>

\<AacMatchData MatchType="AAC\_MATCH\_ACCESS\_MASK"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"
RequiredBits="0x8000000000000000"\>

\<TYPE\_BITMASK\>0xb\</TYPE\_BITMASK\>

\</AacMatchData\>

\</AacMatchObject\>

\</AacSubRule\>

\<AacSubRule Role="AAC\_ROLE\_TARGET"\>

\<AacMatchObject ObjectType="AAC\_OBJECT\_VALUE"\>

\<AacMatchData MatchType="AAC\_MATCH\_OBJECT\_NAME"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"\>

\<TYPE\_STRING\>\*\*\\\*\*\</TYPE\_STRING\>

\</AacMatchData\>

\<AacMatchData MatchType="AAC\_MATCH\_ACCESS\_MASK"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"
RequiredBits="0x8000000000000000"\>

\<TYPE\_BITMASK\>0xb\</TYPE\_BITMASK\>

\</AacMatchData\>

\</AacMatchObject\>

\</AacSubRule\>

\<AacSubRule Role="AAC\_ROLE\_TARGET"\>

\<AacMatchObject ObjectType="AAC\_OBJECT\_PROCESS"\>

\<AacMatchData MatchType="AAC\_MATCH\_OBJECT\_NAME"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"\>

\<TYPE\_STRING\>\*\*\</TYPE\_STRING\>

\</AacMatchData\>

\<AacMatchData MatchType="AAC\_MATCH\_ACCESS\_MASK"
MatchOp="AAC\_OP\_INCLUDE" IsRange="false"
RequiredBits="0x8000000000000000"\>

\<TYPE\_BITMASK\>0xb\</TYPE\_BITMASK\>

\</AacMatchData\>

\</AacMatchObject\>

\</AacSubRule\>

\</AacRule\>

\</AacPolicy\>

**Troubleshooting:**

Since no AP/SP Event is generated and no entries are added to AP and SP
logs when these exceptional allow events are triggered because of the
noise it can create on every single action of the Global AAC Exclusions
process, the only way to identify whether these processes were allowed
is using procmon or ETL trace.

ETL trace will show that the rule was triggered. Procmon will show the
once denied access will be allowed after the process has been added to
the global exclusion list.

## Threat Reputation (GTI)

### Overview

GTI business object (BO) is a wrapper for Trusted Source (TS) SDK.
Harvey release is using TS SDK version 2.3.0.1. GTI BO takes care of two
main aspects of GTI i.e. proxy server configuration and fetching rating
for URL, File, Network and IP from McAfee GTI server. GTI BO stores
configuration in GTIBL.xml file which can be found in Endpoint Security
Platform installation folder.

All Harvey modules ***do not*** use GTI BO for all their GTI related
functionality. Firewall is fully integrated and it uses full
functionality of a GTI BO. Other modules like Web Control and Threat
Prevention use GTI BO for obtaining proxy configuration only. Web
control takes proxy configuration from GTI BO, but directly uses TS SDK
to fetch ratings for URL, file, IP. Same is the case with Threat
Prevention, it uses proxy configuration from GTI BO and passes on the
same to AMCore.

GTI BO is a delay load business object i.e. it gets loaded in mfeesp.exe
process on first GTI related request. So don’t get surprised if you
don’t find any log entry related to GTI BO loading in Endpoint
Security Platform logs. First request can come in the form of property
collection, policy enforcement or as a part of Firewall module
requesting for GTI rating or Web control or threat prevention module
requesting for proxy configuration.

### Proxy Configuration

GTI BO supports three type of proxy configurations, “No proxy server”,
“Use system proxy settings” and “Manually configured proxy”.
Configuration in use can be found using GTIBL.xml file. Proxy type 0
means no proxy, 1 means use system proxy and 2 means manually configured
proxy.

XML file also has a configuration settings for controlling GTI cache
like number of cache entries etc. but these settings are not currently
configurable using UI.

### Troubleshooting

Most of the time, GTI related problems occur due to proxy configuration
or network connectivity issues. Very rarely a problem is related to
McAfee GTI server/backend where we get wrong rating or there can be some
issue related to TS SDK.

First important step in determining GTI issues is to determine the
module that is showing error signs. Sometimes GTI BO may not be the root
cause because as described earlier that module may not be using full
functionality of GTI BO. Following table summarizes GTI BO messages and
their meaning.

| **Log Messages**                                                                 | **Type** | **Comment**                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| -------------------------------------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| GTI Initialize is failed                                                         | Error    | GTI BO failed to initialize TS SDK and therefore not in a usable state anymore                                                                                                                                                                                                                                                                                                                                                                                 |
| Failed to load container                                                         | Error    | GTI BO failed to load configuration file GTIBL.xml. Possibly a corrupt GTIBL.xml or GTIBL.xsd                                                                                                                                                                                                                                                                                                                                                                  |
| Failed to fetch password                                                         | Debug    | Some issue with password blob and password decryption. Try resetting password and issue may get fixed                                                                                                                                                                                                                                                                                                                                                          |
| Failed to save container                                                         | Error    | GTI BO is not able to save settings to configuration file. GTI BO may not use modified settings on restart.                                                                                                                                                                                                                                                                                                                                                    |
| Unable to get GTI reputation. TS Error code = %d                                 | Error    | Popular error code is 51 which means connection timeout. First check if this is some proxy configuration issue by enabling debug logging for ESP and amount of time that BO spends in fetching proxy settings. You can try changing setting from use system proxy to manual proxy configuration and check if it fixes issue. Connection timeout value is about 6 seconds so if GTI BO doesn’t hear anything form server within 6 seconds then it will timeout. |
| Unable to configure GTI proxy                                                    | Error    | Unable to use proxy configuration for GTI server access.                                                                                                                                                                                                                                                                                                                                                                                                       |
| Unable to get system proxy settings                                              | Debug    | GTI BO runs with system privilege and needs to impersonate in order to get browser proxy settings. Some issue with impersonation.                                                                                                                                                                                                                                                                                                                              |
| Unable to get system proxy configuration for current user                        | Debug    | Windows API failure                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| System proxy settings are not configured, skipping system proxy settings         | Debug    | GTI BO is configured to use system proxy settings but system proxy settings are not configured for a machine.                                                                                                                                                                                                                                                                                                                                                  |
| Unable to get system proxy settings using configuration script or auto detection | Debug    | Unable to find proxy setting using PAC file.                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Couldn't extract proxy host and proxy port from Proxy list                       | Debug    | Able to get proxy settings from PAC file but couldn’t parse proxy settings.                                                                                                                                                                                                                                                                                                                                                                                    |
| Unable to get manual system proxy settings                                       | Debug    | Unable to get manually configured proxy setting from browser/system proxy settings                                                                                                                                                                                                                                                                                                                                                                             |
| Unable to get manual system proxy configuration for current user                 | Debug    | GTI is configured to use system proxy setting and system proxy setting is set for manual configuration but actual configuration is not added in system proxy setting.                                                                                                                                                                                                                                                                                          |

##  DLL Injection Management

### Overview

Intel Security products grant or deny trust based upon a products
digital certificate. A digital certificate is verified using a chain of
trust originating with a certificate authority. Digital signatures allow
the ENS product to authenticate a third party products identity. ENS
grants third party trust through the use of a global McAfee Certificate
store. Third party certificates which are added to the store become
trusted. Third party certificates which are not added to the store are
deemed as untrusted. The CertManagerBO business object is designed to
allow an administor, ePO or local, a means to manage the trust
relationship between ENS and other vendors. Once a vendor's software is
trusted, it may successfully inject into ENS processes.

### Workflow

*The Canary Process*

McAfee Platform Technologies (MPT) has developed a process designed to
detect DLL injections from untrusted sources. The process known as
Canary is responsible for the detection of untrusted injectors and
notification to subscribers. The Canary process is launched by the
CertManagerBO during BLFramework initialization. It runs in the
background until the CertManagerBO is unloaded by BLFramework. As a
third party vendor attempts to inject a DLL into the ENS suite, it will
also attempt injection into the Canary process. Untrusted injections
into Canary will cause notification to CertManagerBO via a
pre-established callback routine. Canary will report the absolute path
to the offending DLL.

*Injector Notification*

Upon a notification from Canary, CertManager uses the absolute path of
the injector to obtain its digital certificate. If the certificate is
untrusted and not yet reported, CertManager generates an event thus
notifying the appropriate administrator; ePO on a managed client and/or
local on an unmanaged system. In an unmanaged environment a McTray
notification and an entry in the Client UI's event viewer are generated.
In a managed configuration a McTray event, entry in the Client UI event
viewer, and an ePO event are generated. Each event contains the Vendor’s
Name, the Subject of the certificate, and the SHA1 hash of the DLL.

*Injection Administration*

In both the managed and unmanaged environment, an administrator is
presented with UI tools which allow management of the injections.

Unmanaged Environment:

![](./media/image35.png)

In an unmanaged environment, Certificate management can be found in the
Client UI under the "Common" advance settings page. An administrator is
presented with a simple interface listing certificates of all DLL
injectors. The administrator is allowed to view, trust, or untrust third
party certificates. When the "Apply" button is selected an updated
certificate policy is flushed to the CertManager business object.

NOTE: In a managed environment the Client UI presents the certificate
table in a read only configuration.

Managed Environment:

![](./media/image36.png)

In a managed environment, Certificate management can be found in the ePO
extension under the "Common" policy page. An administrator is presented
with a simple interface listing certificates of all DLL injectors. The
administrator is allowed to view, trust, or untrust third party
certificates. When the "Save" button is selected an updated certificate
policy is sent to the ENS client.

NOTE a complete list of certificates is sent between client and ePO
server allowing products to be trusted or untrusted on multiple ePO
clients throughout a network.

*Internal Implementation*

CertManager business object accomplishes the management and reporting of
DLL injections through the use of three certificate stores;
CanaryCertStore, *PolicyCertStore*, and the global *McAfee Trust*
certstore.

  - > The *CanaryCertStore* houses certificates of DLL injectors which
    > have been deemed as untrusted, or are in an unknown state. When an
    > injection is reported by the Canary process, the certificate of
    > the injector is stored in the CanaryCertStore and reported to the
    > administrator. If a certificate has been deemed as untrusted by
    > the administrator it is housed in this store. CertManager business
    > object checks new injectors against this certificate store to
    > ensure an injector is only reported once to the administrative
    > tool.

  - > *PolicyCertStore* houses all certificates that are deemed trusted
    > via administrative policy. CertManager business object checks new
    > injectors against this certificate store to determine the
    > injector's is a known trusted vendor certificate.

  - > *McAfee Trust* houses all certificates that are trusted on a
    > product level. CertManager adds trusted certificates to this store
    > to allow future injections by the vendor. Similarly, untrusted
    > certificates are removed from this store restricting further
    > injections by the vendor. NOTE, once a certificate is added or
    > removed VSCORE cache is purged to force a reload of trusted
    > certificates thus allowing future injections from the vendor.

### Debug

  - > *Injection not detected*. If a third party injection is not
    > detected, check the state of the Canary process (MFECanary.exe)
    > using windows taskmanager. The Canary process should mirror the
    > running state of hostCommon (mfeesp). No injections will be
    > detected no reported if the Canary process is not running. If
    > Canary has stopped, the mfeesp service should be stopped and
    > restarted.

## Management Mode

### Overview

Management mode describes how the Endpoint client is managed. Management
mode is used to display management type in Client UI -\> Aboutbox.
Possible management modes for endpoint client are:

  - ***Self-Managed*** – Client is stand-alone install.

  - ***McAfee ePolicy Orchestrator Cloud*** – Client is managed with ePO
    Cloud.

  - ***McAfee ePolicy Orchestrator*** – Client is managed with ePO

  - ***SecurityCenter*** – Client is managed with NOC Security Center.

### ePO Managed Systems

Client machines are managed from ePO prem and ePO Cloud through McAfee
Agent. Following components are involved in Client \< – \>server
communication for policy enforcement, property collection, and task
enforcement of common components.

  - McAfee Agent: Client and server are communicated through MA. MA is
    packaged with Endpoint Security Platform.

  - Extension at ePO: Properties, Policies and Tasks related to common
    components are available with General Settings (GS) extension at
    ePO.

  - Common LPC: Client and MA are communicated via common LPC component.
    This component collects policies and tasks from MA and applies on
    client, collects properties from client and send to MA.

  - COMBO: Common Business Object provides management mode to common LPC
    and other common business objects.

#### Policy, Task and Property

  - Policy enforcement: Policies are configured at General Setting’s
    extension at ePO and enforced with Agent \< - \> Server
    communication. Agent server communication initiated at regular
    interval with policy set for MA at ePO or manually either with Agent
    wakeup at ePO or enforce policies from Agent service monitor at
    client. Once Policies reaches MA, MA passes policy information to
    common LPC component. Common LPC determine policy belongs to which
    business object and applies to respective BO.

  - Task enforcement: Similar to policy enforcement, Task enforcement
    happens from ePO to Client via MA and Common LPC. Different types of
    tasks include product deployment, content update, product update and
    schedule tasks.

  - Property collection: Common LPC component collects all the common
    components properties and passes to McAfee Agent. MA sends
    properties to ePO which will be reported at ePO General Settings
    extension.

### Security Center Managed Systems

Client machines are managed from Security Center (NOC) through TPS
Connector. Following components are involved in Client \< – \> Server
communication for policy enforcement, property collection, and task
enforcement of common components. Refer TPS Connector supportability
document for complete details.

  - TPS Connector: Client and server are communicated through TPS
    Connector. This component collects policies from NOC and applies on
    client, sends properties and reports from client to NOC Security
    Center.

  - McAfee Agent: MA will not play role in TPS environment but packaged
    with Endpoint Security Platform.

  - COMBO: Common Business Object provides management mode to TPS
    Connector and other common business objects.

#### Policy, Task and Property

  - Policy enforcement: Policies are configured at Security Center and
    enforced with Client \< - \> Server communication. Client \< - \>
    server communication initiated at regular interval with policy set
    at Security Center or manually from the client UI. Once Policies
    reaches TPS Connector, TPS Connector determine policy belongs to
    which business object and applies to respective BO.

  - Property collection: TPS Connector sends all common component
    properties to Security Center which will be reported at Security
    Center.

### Troubleshooting

#### Management mode in “Aboutbox” is not correct for ePO/Cloud Managed client. 

Check if mfeesp and MA Agent services are running

#### Management mode in “Aboutbox” is not correct for Security Center Managed client. 

Check mfeesp and mfetps service is running

## Localization Framework

In Harvey project localization is handled in two different places.

1.  Business Object

2.  Client UX

Business Objects mainly deal with generating events and notifications
that can be logged to activity logs, ePO, Windows AppLog, etc. Hence BOs
need a localization framework in order to translate events in the
selected locale. Client UX is responsible for displaying the GUI in the
user preferred/admin preferred/system locate, based on the
configuration. Since client UX is a java script based framework, it has
its own localization framework. Following sections explain each of these
frameworks in detail.

### Business Objects

Harvey is built to support multiple languages and needs a framework to
support localization requirements. In order to utilize the framework,
all the modules in Harvey have must have the following folder structure.

Each module must have a ‘lang’ folder and \<hex lcid\> sub-folders. Each
\<lcid\> folder consists of strings.bin file, which is obfuscated using
scramble.exe provided by VSCore and hence not readable directly. The
localization framework expects this setup for translating string id to
actual strings. If any of the string id is missing from the strings.bin
file, then the translation fails and may lead to empty translated
strings.

### Client UX

The Client UI has a separate set of localized resources from the BO
system. Each module and the core UI installation comes with a set of
JSON formatted string resource files that are installed in
“\<ProgramFilesDir\>\\McAfee\\Endpoint Security\\Endpoint Security
Platform\\modules\\\<module\_id\>\\lang”. The lang folder contains a
\<lcid\> folder for each supported language. The strings.json files are
obfuscated and are loaded on-demand by the Client UI application as
needed.

## About Box

About box content is collected dynamically from each module and
aggregated in the client UI. If any of the module is not available or
the module hosting service is not running, then the details of that
module will not be visible in the about box. In case of ESP module,
COMBO is responsible for providing about box contents. For common module
following information is shown in the about box.

Management Mode

COMBO is responsible for identifying the management mode. It checks with
MA interface to find out if the system is managed or not.

License Information

Since ESP is not associated with any license, license entry will be
visible only for other modules. The license strings displayed on the UI
for various types are as follows.

| Type                 | Display                                 |
| -------------------- | --------------------------------------- |
| **Beta**             | Beta – Active / Beta – Expired          |
| **Evaluation/Trial** | Trial – Active / Trial – Expired        |
| **Subscription**     | Licensed – Active / Not a valid license |
| **Perpetual**        |                                         |

MA Agent version

This value is queried from registry location:

HKLM\\Software\\Wow6432node\\NetworkAssociates\\TVD\\SharedComponents\\Framework\\Version

# Major external dependencies

## Trusted Source (SDK)

Version used: 2.3.0 build 227.1

## Encryption (RSA SDK)

Version used: RSA BSAFE Crypto-C ME 4.0.5

## MPT

Version used: 15.3.0

Components used – AAC, VSCore, Firecore, MMS, VTP

## McAfee Agent

Version used: 5.0

## AMCore

> Version used: 1.3.0

# Policy Settings

This section covers a high level overview of the Common policy setting
for the Endpoint Security Platform

## Client Settings

The common settings on the client can be broken down into two main
buckets:

**<span class="underline">Options</span>**

Consists of the following settings:

**Client Interface Mode** – used to control whether the client is in
Full Access, Standard Access or Locked down mode

**Uninstallation** – used to set the password for protecting the
uninstall

**Client Interface Language** - allows user to choose display language.
By default it is set to automatic which detects the OS language and
displays UI in that language. There are 15 languages that are supported
on the client UI.

**Self Protection** - Self-protection protects ENS files, folders,
registry keys and processes which are required for ENS to function
properly. This protection technology has it’s own activity and debug log
files SelfProtection\_Activity.log and SelfProtection\_Debug.log.
Following self-protection configurations are available:

  - Enable self-protection: Enables\\Disables self protection for ENS
    files, folders, registry and processes.

  - Files and Folders: Enables\\Disables self-protection for ENS files
    and folders only.

  - Registry: Enables\\Disables self-protection for ENS registry keys,
    values and data only.

  - Processes: Enables\\Disables self-protection for ENS processes only.

  - Block Only: This action will enable blocking only. The event logging
    will not occur if this option is selected.

  - Report Only: This will only report a violation but will not block a
    self-protection violation

  - Block and Report: This is the default setting and will block and
    report all self-protection violations.

  - Exclusion these processes: User can configure certain processes to
    be excluded from self-protection. For example: If troubleshooting
    requires that a registry key be added then regedit.exe can be added
    to exclusion list and the regedit.exe can be used to add the
    required key.

**Client Logging** - This section holds the configuration for logging
activity and debug messages from each ENS module into log files which
are by default located at “C:\\ProgramData\\McAfee\\Endpoint
Security\\Logs”. The following configurations are available for client
logging:

  - Log files location: Defines the location on the endpoint where the
    activity and debug logs will be created.

  - Enable activity logging: This enables\\disables the activity logging
    of all protection technologies in ENS.

  - Limit size (MB) of the activity log file: This enable\\disables the
    size limitation of the activity log file. By default the log size
    limitation is enabled and set to 10MB.

  - Language (For Activity Logging): This sets the language in which
    activity logs are to be written. By default, it is set to automatic,
    which sets the logs to be written in the system locale.

  - Debug Logging: This enables\\disables debug logging on a per
    protection technology basis. By default debug logging is turned off
    for all protection technologies.

  - Enabling debug logging for any of the protection technologies will
    by default enable the Self Protection and Endpoint Security Platform
    debug logging since all protection technologies are dependent on the
    services of these two modules.

  - Limit size (MB) of the debug log file: This enable\\disables the
    size limitation of the debug log file. By default the log size
    limitation is enabled and set to 50MB.

Activity logs are defined as “user facing” logs. Important messages like
threat detection are logged into the activity log. There is a activity
log file for each protection technology of ENS as listed below:

  - AccessProtection\_Activity.log

  - EndpointSecurityPlatform\_Activity.log

  - ExploitPrevention\_Activity.log

  - Firewall\_Activity.log

  - OnAccessScan\_Activity.log

  - OnDemandScan\_Activity.log

  - PackageManager\_Activity.log

  - SelfProtection\_Activity.log

  - ThreatPrevention\_Activity.log

  - WebControl\_Ativity.log

There are also corresponding Debug logs for each of the above log files.
The debug logs contain messages which would help troubleshoot any issues

Event logging: Event logging supports logging events from all ENS
modules into Windows Application log and also the “Event Log” on the
client console. In case endpoint is managed by ePO, event logging will
generate ePO events as well. The event logging configuration supports
filtering events based on their severity. The event severity levels are
decided by the ENS modules generating them. By default events which are
deemed Major and Critical are logged to Windows application log, Event
Log on client UI and ePO events. The supported event filter levels are:

  - None: No events will be generated

  - Critical Only: Only critical severity events will be generated

  - Major and Critical: Only events with severity level major and
    critical will be generated

  - Minor, Major and Critical: Only event with severity level as minor,
    major or critical will be generated

  - All except informational: Events with severity level other than
    informational will be generated.

  - All: All events irrespective of its severity level will be
    generated.

**Proxy Server for McAfee GTI** - GTI (Global Threat Intelligence) is
used by various modules of ENS 10. In order to be able to lookup the GTI
source which is in the cloud, the endpoint has to have access to
internet either directly or through a proxy. The proxy configuration for
accessing GTI is exposed in the common settings. Supported proxy types
are:

  - System proxy with and without authentication

  - Proxy server DNS name\\IP address along with port number

**Default Client Update** - The default update task has configurations
on the client console as listed below:

  - “Enable the Update Now button in the client” allows users to start
    update from the client console landing page.

  - “What To Update” configuration allows users to choose which update
    packages should be downloaded. The options available are:
    
      - Security content, hotfixes and patches: This option instructs
        the update task to download Anti-malware content, Exploit
        Prevention content, hotfixes and patches for installed modules.
    
      - Security content: This option instructs the update task to
        download Anti-malware content and Exploit Prevention content
        only.
    
      - Hotfixes and patches: This option instructs the update task to
        download only hotfixes and patches for installed modules.

**Source Sites for Updates** – allows users to specify the location from
where the update packages should be downloaded from. User can also
add\\remove new\\existing source sites by clicking the “Add” and
“Delete” button.

On clicking the Add button, user is presented with a modal configuration
page where the following configurations can be made:

  - Repository type

  - Repository URL\\Path

  - Repository authentication if required

<!-- end list -->

  - “Proxy server for source sites”: User can configure proxy server in
    case the system does not have direct internet connection and uses
    either a system proxy settings or a proxy server on the same network
    as the client. If the proxy uses authentication, these settings can
    also be configured in this section.

**<span class="underline">Tasks</span>**

  - The “TASKS” section displays a list of the three default tasks –
    Quick Scan, Full Scan and Default Client Update that can be
    configured on the system.

  - The schedule configuration of these tasks can be viewed by double
    clicking on the task. This will pop out a modal window with the
    current schedule settings of the task.

  - The schedule configuration defines, “when the task should run”.
    Supported schedule types are “Daily”, “Weekly” and “Monthly”.

  - On choosing a schedule, there are further configurations to choose
    like the day of week, frequency of week, month and day of month etc.
    The schedule configuration window also has a section to configure
    the repeat options and timeout. With these repeat options user can
    configure the task to repeat until a certain time or time duration
    e.g. repeat until 11:59 PM (or repeat for 1 hour) and start every 4
    hours. Also a timeout can be set so that tasks do not run for long
    periods.

  - The schedule configuration also controls one other aspect not
    related to when the task runs. The task can be configured to run in
    a specific user account. Example use case being ODS Task configured
    to scan certain network drives or local paths to which the current
    user does not have access\\rights to create\\read\\write files. In
    this scenario, in order to scan that location, the ODS task can be
    configured to use a specific user account which has the required
    access to the location.

## Server Settings

The server settings for the Endpoint Security Platform are managed by
the “Options” policy of the Endpoint Security Common 10.0 Product in the
Policy Catalog up at ePO. This policy controls common settings for all
Endpoint modules installed on an end-node and are identical to the
common settings on the Client UI: Client Interface Mode, Uninstallation
Password, Client Interface Language, Self-Protection, Client Logging,
and Proxy Server for McAfee GTI and Default Client Update

![](./media/image38.png)

The tasks are managed and scheduled by using ePO’s standard Client Task
Catalog and Client Task Assignment workflows

# Client Installation and Uninstallation

## List of install packages: 

> ENS has several kind of packages for required install methodology,

  - Standalone (combined x86/x64, only x86 and only x64 installer), this
    is also used for 3<sup>rd</sup> party deployment.

  - ePO deployable packages.

> Table 1 lists the different type of Endpoint packages

| **<span class="underline">Package Name</span>**                                                    | **<span class="underline">Package Type</span>** |
| -------------------------------------------------------------------------------------------------- | ----------------------------------------------- |
| Endpoint Master Package Build \<BldNum\> Package \<PkgNum\> .zip                                   | ePO Deployable                                  |
| EndPointInstaller 10.0.0 Build \<BldNum\> Package \#\<PkgNum\> (ENU-LICENSED-RELEASE-MAIN).Zip     | Standalone (32 & 64 bit)                        |
| EndPointInstaller 10.0.0 Build \<BldNum\> Package \#\<PkgNum\> X64 (ENU-LICENSED-RELEASE-MAIN).Zip | Standalone 64 bit                               |
| EndPointInstaller 10.0.0 Build \<BldNum\> Package \#\<PkgNum\> X86 (ENU-LICENSED-RELEASE-MAIN).Zip | Standalone 32 bit                               |

## List of files for different types of packages: 

> Table 2 lists the files that are contained in the **Endpoint Master
> Package Build \<BldNum\> Package \<PkgNum\>.zip** package (ePO
> Deployable)

| **Filename**                                              | **Description**                  |
| --------------------------------------------------------- | -------------------------------- |
| Firewall 10.0.0 Build \<BldNum\> (Extension).Zip          | Firewall Extension               |
| Common 10.0.0 Build \<BldNum\> (Extension).Zip            | ESP Extension                    |
| Threat Prevention 10.0.0 Build \<BldNum\> (Extension).Zip | Threat Prevention Extension      |
| Web Control 10.0.0 Build \<BldNum\> (Extension).Zip       | Web Control Extension            |
| help\_ecn\_1000.Zip                                       | ESP help Extension               |
| help\_efw\_1000.Zip                                       | Firewall help Extension          |
| help\_etp\_1000.Zip                                       | Threat Prevention help Extension |
| help\_ewc\_1000.Zip                                       | Web Control help Extension       |

> Table 3 Lists the files that are contained in **EndpointInstaller
> 10.0.0 Build \<BldNum\> Package \# \<PkgNum\>
> (ENU-LICENSED-RELEASE-MAIN).Zip** Standalone package.

|                                                                                                       |                            |
| ----------------------------------------------------------------------------------------------------- | -------------------------- |
| Filename                                                                                              | Description                |
| msxml6.msi                                                                                            | msxml6 32 bit installer    |
| msxml6\_x64.msi                                                                                       | msxml6 x64 installer       |
| setupEP.Exe                                                                                           | Endpoint Setup Executable. |
| Threat Prevention 10.0.0 Build \<BldNum\>**Package \#**\<PkgNum\> (AAA-BETA-RELEASE-HARVEYBETA 2)     | TP installer content       |
| Web Control 10.0.0 Build \<BldNum\>**Package \#** \<PkgNum\> (AAA-BETA-RELEASE-HARVEYBETA 2)          | WC installer content       |
| Endpoint Security Platform 10.0.0 \<BldNum\>**Package \#** \<PkgNum\> (AAA-BETA-RELEASE-HARVEYBETA 2) | ESP installer content      |
| Firewall 10.0.0 Build \<BldNum\>**Package \#** \<PkgNum\> (AAA-BETA-RELEASE-HARVEYBETA 2)             | Firewall installer content |
| EPDeploy.XML                                                                                          |                            |
| EpInstallStrings.zip                                                                                  |                            |

> Table 4 Lists the files that are contained in **EndpointInstaller
> 10.0.0 Build \<BldNum\>Package \# \<PkgNum\> X64
> (ENU-LICENSED-RELEASE-MAIN).Zip** Standalone package.

|                                                                                                      |                            |
| ---------------------------------------------------------------------------------------------------- | -------------------------- |
| Filename                                                                                             | Description                |
|                                                                                                      |                            |
| msxml6\_x64.msi                                                                                      | msxml6 x64 installer       |
| setupEP.Exe                                                                                          | Endpoint Setup Executable. |
| Threat Prevention 10.0.0 **\<BldNum\>Package \# \<PkgNum\>**X64 (AAA-LICENSED-RELEASE-MAIN)          | TP installer files         |
| Web Control 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>** X64 (AAA-LICENSED-RELEASE-MAIN)         | WC installer files         |
| Endpoint Security Platform 10.0.0 **\<BldNum\>Package \# \<PkgNum\>**X64 (AAA-LICENSED-RELEASE-MAIN) | Common installer files     |
| Firewall 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>**X64 (AAA-BETA-RELEASE-MAIN)                 | Firewall installer files   |
| EPDeploy.XML                                                                                         |                            |
| EpInstallStrings.zip                                                                                 |                            |

> Table 5 lists the files that are contained in **EndpointInstaller
> 10.0.0 Build \<BldNum\>Package \# \<PkgNum\>X86
> (ENU-LICENSED-RELEASE-MAIN).Zip** Standalone package.

|                                                                                                             |                                   |
| ----------------------------------------------------------------------------------------------------------- | --------------------------------- |
| Filename                                                                                                    | Description                       |
| msxml6.msi                                                                                                  | msxml6 x86 installer              |
| setupEP.Exe                                                                                                 | Endpoint Setup Executable.        |
| Threat Prevention 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>** X86 (AAA-LICENSED-RELEASE-MAIN)          | TP installer files                |
| Web Control 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>** (AAA-LICENSED-RELEASE-MAIN)                    | WC installer files                |
| Endpoint Security Platform 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>** X86 (AAA-LICENSED-RELEASE-MAIN) | Common installer files            |
| Firewall 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>**X86 (AAA-BETA-RELEASE-MAIN)                        | Firewall installer files          |
| EPDeploy.XML                                                                                                | Endpoint Setup configuration file |
| EpInstallStrings.zip                                                                                        | Strings file                      |

## ENS Binaries, Location and Services

  - Binaries and Location

  - Services

## SETUP command-line options 

> 8.4.1. EPSetup command-line options (self-managed systems)
> 
> setupEP.exe ADDLOCAL="tp,fw,wc"
> \[INSTALLDIR="install\_path"\]\[/qb\]\[/qb\!\]\[/
> l"install\_log\_path"\]\[/l\*v"install\_log\_path"\] \[/autorestart\]
> \[/import \<file\_name\>\] \[/ module \<TP|FW|WC|ESP\>\]
> \[/nopreservesettings\] \[/override"program\_name"\] \[/policyname
> 
> \<name\>\] \[/unlock \<password\>\]

<table>
<thead>
<tr class="header">
<th><p>ADDLOCAL="tp,fw,wc" Selects the product modules to install:</p>
<p>• tp — Install Threat Prevention.</p>
<p>• fw — Install Firewall.</p>
<p>• wc — Install Web Control.</p>
<p>• tp,fw,wc — Install all three modules.</p>
<p><strong>Example:</strong></p>
<p>setupEP.exe ADDLOCAL="tp,wc"</p>
<p>installs Threat Prevention and Web Control.</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>INSTALLDIR="install_path" Specifies where to install the product files on the computer.</p>
<p><strong>Example:</strong></p>
<p>setupEP.exe ADDLOCAL="tp,fw,wc" INSTALLDIR="D:</p>
<p>\Installed Programs"</p>
<p>installs all product modules under D:\Installed Programs</p>
<p>\EndPoint\. The installation wizard adds the EndPoint folder</p>
<p>at the end of the path automatically.</p>
<p>By default, product files are installed in the folder C:\windows</p>
<p>\Temp\McAfeeLogs.</p></td>
</tr>
<tr class="even">
<td><p>/log"install_log_path" or / • Specifies where to save the installation log files for tracking</p>
<p>l"install_log_path" installation events.</p>
<p>/l*v"install_log_path" <strong>Example:</strong></p>
<p>/l"D:\Installed Programs"</p>
<p>installs the product log files under D:\Installed Programs</p>
<p>\EndPoint\. The installation wizard adds the EndPoint</p>
<p>folder at the end of the path automatically.</p>
<p>By default, log files are saved in the folder C:\windows</p>
<p>\Temp\McAfeeLogs.</p>
<p>• *v — Specifies verbose (more descriptive) logging entries.</p></td>
</tr>
<tr class="odd">
<td><p>/qn or /quiet Specifies how the users can interact with the installation wizard:</p>
<p>/qb! or /passive</p>
<p>• qn — Hide all installation notifications (silent mode). Users</p>
<p>/qb have no interaction.</p>
<p>• qb! — Show only a progress bar without a <strong>Cancel</strong> button. Users cannot cancel the installation while it is in progress (passive mode).</p>
<p>• qb — Show only a progress bar with a <strong>Cancel</strong> button. Users can cancel the installation while it is in progress, if needed.</p></td>
</tr>
<tr class="even">
<td>/autorestart Restarts system automatically during installation.</td>
</tr>
<tr class="odd">
<td>/import &lt;file_name&gt; Imports policy settings from the specified file.</td>
</tr>
<tr class="even">
<td>/policyname &lt;name&gt; Assigns the specified policy to systems where the product is installed.</td>
</tr>
<tr class="odd">
<td>/unlock &lt;password&gt; Sets the password for unlocking the client UI.</td>
</tr>
</tbody>
</table>

<table>
<thead>
<tr class="header">
<th><p>/module &lt;TP|FW|WC|ESP&gt; Applies imported policy settings to the specified product modules.</p>
<p>• TP — Threat Prevention</p>
<p>• FW — Firewall</p>
<p>• WC — Web Control</p>
<p>• ESP — Resources shared by product modules.</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>/nocontentupdate Do not update product content files automatically as part of the installation process.</td>
</tr>
<tr class="even">
<td>/override"hips" Overrides and uninstalls conflicting products as specified:</td>
</tr>
</tbody>
</table>

> 8.4.2. ePO on-Prem and ePO on-Cloud

<table>
<thead>
<tr class="header">
<th><p>INSTALLDIR="install_path" Specifies where to install the product files on the computer.</p>
<p><strong>Example:</strong></p>
<p>INSTALLDIR="D:\Installed Programs"</p>
<p>installs all product modules under D:\Installed Programs</p>
<p>\Endpoint\. Note that the installation wizard adds the Endpoint</p>
<p>folder at the end of path automatically.</p>
<p>By default, product files are installed in the folder C:\windows</p>
<p>\Temp\McAfeeLogs.</p></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>/log"install_log_path" or / • Specifies where to save the installation log files for tracking</p>
<p>l"install_log_path" installation events.</p>
<p>/l*v"install_log_path" <strong>Example:</strong></p>
<p>/l"D:\Installed Programs"</p>
<p>By default, log files are saved in the folder C:\windows\Temp</p>
<p>\McAfeeLogs.</p>
<p>• *v — Specifies verbose (more descriptive) logging entries.</p></td>
</tr>
<tr class="even">
<td>/nocontentupdate Do not update product content files automatically as part of the installation process.</td>
</tr>
</tbody>
</table>

## Product Upgrade 

> Product upgrade are supported for following products in managed mode
> (ePO on-prem and ePO cloud) and standalone mode
> 
> VirusScan Enterprise (Versions 8.7 and 8.8)
> 
> SiteAdvisorEnterprise (Versions 3.0 and 3.5)
> 
> HIPS :
> 
> In managed mode if HIPS is found on the system installation it is
> aborted.
> 
> In standalone mode, users can tell installer to uninstall HIPS
> (Versions 7.0 and 8.0) by launching installer with the switch
> ‘/override“hips” ’ otherwise installation will be aborted if HIPS is
> found. After removing HIPS users will be prompted for a reboot. If
> user chooses to defer the reboot, Installer will exit and resume only
> after system has been rebooted.
> 
> **Note:** /override“hips” is not supported from ePO deployment task.

## Install logs 

> Here are the location for the Installer logs -\>

1.  Self-Managed  Mode (installer SetupEP.exe) -\>

> C:\\DOCUME\~1\\Admin\\LOCALS\~1\\Temp\\McAfeeLogs *(for Pre Vista OS)*
> C:\\Users\\Admin\\AppData\\local\\Temp\\McAfeeLogs.  *(for Post Vista
> OS)*

2.  ePO Managed Mode

> C:\\Windows\\Temp\\McAfeeLogs
> 
> Below table list’s the install the log names.

| Install Logs                                                         |
| -------------------------------------------------------------------- |
| McAfee\_Common\_Bootstrapper\<%timestamp%\>.log                      |
| McAfee\_Common\_CustomAction\_Install\<%timestamp%\>.log             |
| McAfee\_Common\_Install\<%timestamp%\>.log                           |
| McAfee\_Common\_VScore\_Install\<%timestamp%\>.log                   |
| McAfee\_Endpoint\_BootStrapper\<%timestamp%\>.log                    |
| McAfee\_Endpoint\_CA\_Unknown\<%timestamp%\>.log                     |
| McAfee\_Endpoint\_CompetitorUninstaller\<%timestamp%\>.log           |
| McAfee\_Firewall\_Bootstrapper\<%timestamp%\>.log                    |
| McAfee\_Firewall\_CustomAction\_Install\<%timestamp%\>.log           |
| McAfee\_Firewall\_FireCore\_Install\<%timestamp%\>.log               |
| McAfee\_Firewall\_Install\<%timestamp%\>.log                         |
| McAfee\_PasswordProtection\<%timestamp%\>.log                        |
| McAfee\_PasswordProtection\<%timestamp%\>.log                        |
| McAfee\_PasswordProtection\<%timestamp%\>.log                        |
| McAfee\_PasswordProtection\<%timestamp%\>.log                        |
| McAfee\_ThreatPrevention\_Bootstrapper\<%timestamp%\>.log            |
| McAfee\_ThreatPrevention\_Caspercore\_install\<%timestamp%\>.log     |
| McAfee\_ThreatPrevention\_CustomAction\_Install\<%timestamp%\>.log   |
| McAfee\_ThreatPrevention\_ELAM\_AVDriver\_Install\<%timestamp%\>.log |
| McAfee\_ThreatPrevention\_EP\_Install\<%timestamp%\>.log             |
| McAfee\_ThreatPrevention\_Install\<%timestamp%\>.log                 |
| McAfee\_WebControl\_Bootstrapper\<%timestamp%\>.log                  |
| McAfee\_WebControl\_CustomAction\_Install\<%timestamp%\>.log         |
| McAfee\_WebControl\_Install\<%timestamp%\>.log                       |

> Below table list’s the Un-install the log names.

| Uninstall Logs                                                         |
| ---------------------------------------------------------------------- |
| McAfee\_Common\_Uninstall\<%timestamp%\>.log                           |
| McAfee\_CommonUninst\<%timestamp%\>.log                                |
| McAfee\_Common\_CustomAction\_Uninstall\<%timestamp%\>.log             |
| McAfee\_Common\_VScore\_Uninstall\<%timestamp%\>.log                   |
| McAfee\_Firewall\_CustomAction\_Uninstall\<%timestamp%\>.log           |
| McAfee\_Firewall\_FireCore\_Uninstall\<%timestamp%\>.log               |
| McAfee\_ThreatPrevention\_Caspercore\_uninstall\<%timestamp%\>.log     |
| McAfee\_ThreatPrevention\_CustomAction\_Uninstall\<%timestamp%\>.log   |
| McAfee\_ThreatPrevention\_ELAM\_AVDriver\_Uninstall\<%timestamp%\>.log |
| McAfee\_ThreatPrevention\_EP\_Uninstall\<%timestamp%\>.log             |
| McAfee\_WebControl\_CustomAction\_Uninstall\<%timestamp%\>.log         |

## Error Codes 

| **Error Code** | **Title**                                                                                                                                                                                                                | **Description**                                                                                                                          |
| -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| 16002          | “Administrative privileges required."                                                                                                                                                                                    | "Installer requires administrative privileges to run. Please log-in as administrator and launch the installer."                          |
| 16015          | "Restart Required."                                                                                                                                                                                                      | ON "Installer requires a system restart before completing the installation."                                                             |
| 16006          | "MSI not found."                                                                                                                                                                                                         | "Required .msi file was not found. Please verify that you have a valid package."                                                         |
| 16001          | "Conflicting McAfee product(s) found."                                                                                                                                                                                   | "One or more McAfee conflicting products is present on the system. Uninstall them before continuing with the installation."              |
| 16010          | "Migration failed."                                                                                                                                                                                                      | "Installer tried to migrate settings from legacy product, but it encountered an error."                                                  |
| 16025          | "Migration failed."                                                                                                                                                                                                      | "Installer tried to migrate settings from legacy product, but it encountered an error."                                                  |
| 16007          | "Removal failed."                                                                                                                                                                                                        | "The installer tried to remove older versions of this product or existing legacy product(s) but it encountered an error."                |
| 16016          | "Restart required."                                                                                                                                                                                                      | "The installer requires a system restart to complete the installation."                                                                  |
| 16017          | "Restart pending."                                                                                                                                                                                                       | "A system restart from previous install or uninstall operation is pending. Please restart the system to continue with the installation." |
| 16018          | "Incompatible software removal failed."                                                                                                                                                                                  | "The installer tried to remove one or more incompatible software present on the system but installer encountered an error."              |
| 17001          | "Policy import attempted."                                                                                                                                                                                               | "Policy import failed."                                                                                                                  |
| 17001          | "The installer tried to import policies but encountered an error."                                                                                                                                                       | "Policy import failed."                                                                                                                  |
| 16502          | "The installer tried to import policies but encountered an error."                                                                                                                                                       | "Installation failed."                                                                                                                   |
| 16019          | "The installer wizard was interrupted before McAfee Endpoint Security could be completely installed. Your system has not been modified. To install the program at a later time, please run the installation again."      | "Installation canceled."                                                                                                                 |
| 16020          | "The installer wizard was canceled by user before McAfee Endpoint Security could be completely installed. Your system has not been modified. To install the program at a later time, please run the installation again." | "Installation failed."                                                                                                                   |
| 17002          | "Rollback failed."                                                                                                                                                                                                       | "Installation failed. The installer then tried to roll back the changes but it encountered an error."                                    |
| 17003          | "Installation canceled."                                                                                                                                                                                                 | "Rollback failed."                                                                                                                       |
| 17003          | "Installation canceled. The installer then tried to roll back the changes but it encountered an error."                                                                                                                  | "Policy import failed."                                                                                                                  |
| 16501          | "The installation was successful but while importing policy, installer encountered an error."                                                                                                                            | "Policy import failed."                                                                                                                  |
| 16503          | "The installation was successful but while importing policy, installer was not able to retrieve location of dependent module."                                                                                           | "Policy import attempted."                                                                                                               |
| 17004          | "Policy import failed."                                                                                                                                                                                                  | "The installer tried to import policies but it was unable to find dependent module's install location."                                  |
| 16008          | "Launching installer failed."                                                                                                                                                                                            | "The installer tried to launch installation but encountered an error."                                                                   |

## Common installation messages and their causes and solutions

> Error messages are displayed by programs when an unexpected condition
> occurs that can't be fixed by the program itself. Use this list to
> find an error message, an explanation of the condition, and any you
> take to correct it.

<table>
<thead>
<tr class="header">
<th><blockquote>
<p><strong>Message Description Solution</strong></p>
</blockquote></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><blockquote>
<p>Conflicting McAfee The installation wizard detected Uninstall the conflicting products, then try</p>
<p>product(s) found. one or more conflicting McAfee installing again. products (such as Host Intrusion</p>
<p>Prevention or Deep Defender) on the system that it can't remove automatically.</p>
</blockquote></td>
</tr>
<tr class="even">
<td><blockquote>
<p>Administrative You must have administrator Log on as an administrator, then launch the</p>
<p>privileges required. rights to run the installation installation wizard. wizard.</p>
</blockquote></td>
</tr>
<tr class="odd">
<td><blockquote>
<p>Removal failed The installer couldn't remove a Remove these products manually before previous version of this product installing Endpoint Security.</p>
<p>(such as a beta version) or a Contact support if the issue persists. legacy product (such as VirusScan</p>
<p>Enterprise or SiteAdvisor</p>
<p>Enterprise).</p>
</blockquote></td>
</tr>
<tr class="even">
<td><blockquote>
<p>Launching installer The installation wizard could not Contact support.</p>
<p>failed launch.</p>
</blockquote></td>
</tr>
<tr class="odd">
<td><blockquote>
<p>Restart pending A system restart from a previous Restart the system to continue with the installation or removal operation installation.</p>
<p>is pending.</p>
</blockquote></td>
</tr>
<tr class="even">
<td><blockquote>
<p>Incompatible The installation wizard tried and Remove these products manually before</p>
<p>software removal failed to remove one or more installing Endpoint Security.</p>
<p>failed incompatible software products it detected on the system.</p>
</blockquote></td>
</tr>
<tr class="odd">
<td><blockquote>
<p>Installation The user canceled the installation Run the installation wizard again.</p>
<p>canceled. wizard before it had finished installing Endpoint Security. The</p>
<p>wizard made no changes to the user's system.</p>
</blockquote></td>
</tr>
</tbody>
</table>

## Clean Uninstaller tool

> Use:
> 
> This tool can be used to uninstall the product during a situation when
> regular uninstall has failed. This will forcefully attempt to delete
> files, registry and services and after a reboot use can reinstall the
> product.
> 
> Location:
> 
> \\\\Packagemaster\\EPSetup\\10.0.0.ver\\English\\**\<BldNum\>**.bld\\**\<PkgNum\>**.\\Cleanup
> EndPoint Security 10.0.0 Build **\<BldNum\>Package \# \<PkgNum\>**.zip
> 
> Package content as as below
> 
> ![](./media/image41.png)
> 
> **Command:**
> 
> GUI: User can double click the CleanUninstaller.exe and run the tool.

## Issues and resolution –

> \<Coming soon\>
> 
> Readme – Issues, Resolution and workaround

## Hotfixes – 

> \<Coming soon\>

# Extension Installation and Uninstallation

There is no support for migrating policies from VSE, HIPS, SAE to
Endpoint 10 in this first release. However, an on-premise ePO server
should be able to support Endpoint 10, HIPS, SAE and VSE extensions on
the same server.

The same Endpoint extensions can be installed both in the cloud and
on-premise.

## Cloud

### Installation

In a cloud environment, all extensions will be installed by McAfee
personnel, and most McAfee extensions will be installed on each ePO
server to support each tenant’s licensing needs. In this environment,
tenants have access to the Endpoint modules they are licensed for. There
are issues where all tenants will see Endpoint dashboards whether or not
they are licensed for Endpoint 10.

The first Endpoint extension that must be installed is the Common
extension. The other extensions depend upon this extension and will not
install unless the Common extension is installed.

### Upgrades

After initial installation on an ePO cloud server, extension
build-to-build upgrades must be used to install patches, hotfixes, and
POC’s. Installation of POC’s in a cloud environment may be an issue
because the POC will affect functionality for all tenants on that ePO
server.

### Uninstallation

Extensions should not be uninstalled in a cloud environment, as this
will cause all tenants using a particular ePO server to lose data.
Patches, hotfixes, and POC’s to extensions on ePO cloud-based servers
require extension build-to-build upgrades. ePO does have an option
enabled by default in cloud mode to preserve tenant policies when an
Endpoint extension is uninstalled, but other data such as custom
property and event data will be lost for all tenants on that server.
When uninstalling Endpoint extensions, the Common extension must be
uninstalled last. ePO will not allow the extensions to be uninstalled in
the wrong order.

## On-premise

### Installation

In an on-premise environment, licensing is determined entirely by which
Endpoint extensions a customer has installed. The first Endpoint
extension that must be installed is the Common extension. The other
extensions depend upon this extension and will not install unless the
Common extension is installed.

### Upgrades

On-premise customers will usually do build-to-build upgrades of Endpoint
extensions.

### Uninstallation

On-premise customers may uninstall Endpoint extensions but they will
lose all policies, custom properties and events. When uninstalling
Endpoint extensions, the Common extension must be uninstalled last. ePO
will not allow the extensions to be uninstalled in the wrong order.

# Localization / Internationalization

McAfee Endpoint Security supports several languages and locales via a
flexible architecture. The language that is used is governed by
properties in the Common BO (COMBO) and is configurable via policy and
local settings. In the client, the setting can be reached via “Common |
Show Advanced | Client Interface Language”.

There are three ways the Display Language can be set, each with an order
of precedence. From highest to lowest they are:

1)  User Preferred Language – this is the language as selected in the
    Client UI. If chosen, this takes the highest precedence. The UI will
    be displayed in this language. If ‘Automatic’ is chosen, then the
    language used will be determined by the setting with the next
    highest precedence.

2)  Admin Preferred Language – this is the language as specified by the
    policy set in the management platform. If the administrator selects
    a specific language to be used, the client UI will show this
    language. Also, system level events and logs will use this language.
    If ‘Automatic’ is chosen, then the System Language will be used.

3)  System Language – this is the language of the system the Endpoint
    Security Platform is running on. It depends on what Region/Language
    is chosen in the Operating System, and is what is used if both User
    and Admin preferred languages are set to ‘Automatic’. If the
    language of the OS is not one of the languages that we support, then
    the Default Language (English) will be used.

The Display Language is used for the majority of text in the Client UI
such as menus, settings items, about box information, etc. There are a
few places where a different language could be displayed. One of these
is the Event Viewer, which shows the event data in the language that the
System is configured for at the time the event was generated. This is
because there may be several users on a single system with different
display languages configured, but the Event subsystem needs to use a
specific known language.

# Files and Folders Overview

## Default File disposition on a 32 bit system

Following files are used to provide licensing functionality.

| Default File Path                 | \<Program Files\>\\McAfee\\Endpoint Security\\Endpoint Security Platform:                                                                                                              |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **File Name**                     | **Notes**                                                                                                                                                                              |
| **BL Framework**                  |                                                                                                                                                                                        |
| BLFramework.dll                   | This is framework stub that contains all the external facing APIs                                                                                                                      |
| BLFrameworkU.dll                  | This is framework stub that provides support to binaries that are loaded in unsigned process to communicate with Business objects                                                      |
| BLFrameworkRT.dll                 | This library provides run-time support for executing client calls as well as server calls                                                                                              |
|                                   |                                                                                                                                                                                        |
| **BL Framework Helper Utilities** |                                                                                                                                                                                        |
| McVariantExport.dll               | This library exports only McVariant manipulation classes (accessor, builder, etc.)                                                                                                     |
| LogLib.dll                        | Log library that provides logging framework for the modules to consume                                                                                                                 |
| EpSecApiLib.dll                   | Crypto library meant for providing encryption, hashing functionality                                                                                                                   |
| Logcfg.ini                        | Log configuration file used by Loglib library                                                                                                                                          |
|                                   |                                                                                                                                                                                        |
| **License Manager BO**            |                                                                                                                                                                                        |
| **LcBl.dll**                      | Business object (BObj) that encapsulates all the licensing functionality. This library uses nailite.dll and LcMgrImpl.dll                                                              |
| nailite.dll                       | Refactored version of legacy nailite library. Please note that this is not backward compatible with legacy nailite.                                                                    |
| LcMgrImpl.dll                     | This library is used for validating license in standalone mode.                                                                                                                        |
| LcBL.xml                          | Configuration file for storing license related information. This file follows the schema defined by LcBL.xsd                                                                           |
| LcBL.xsd                          | Schema file to be used by License Manager to maintain the LcBL.xml.                                                                                                                    |
| **Event Manager BO**              |                                                                                                                                                                                        |
| EmBL.dll                          | Business object (BObj) that encapsulates all the event logging functionality.                                                                                                          |
| EmBL .xml                         | Configuration file for storing event sink and severity filter related information. This file follows the schema defined by EmBL.xsd                                                    |
| EmBL .xsd                         | Schema file to be used by Event Manager to maintain the EmBL.xml.                                                                                                                      |
| DefXLateMap .xml                  | Schema file to be used by Event Manager to parse the event data                                                                                                                        |
|                                   |                                                                                                                                                                                        |
| **Scheduler BO**                  |                                                                                                                                                                                        |
| TaskSchedulerBL.dll               |                                                                                                                                                                                        |
| TaskSchedulerBL.xml               | Configuration file for storing schedule task related information. This file follows the schema defined by EmBL.xsd                                                                     |
| TaskSchedulerBL.xsd               | Schema file to be used by Scheduler BO to maintain the TaskSchedulerBL.xml                                                                                                             |
|                                   |                                                                                                                                                                                        |
| **Password BO**                   |                                                                                                                                                                                        |
| PwBL.dll                          | Provides symmetric encryption for passwords                                                                                                                                            |
| PwBL.xml                          | Configurations file for storing password. This file follows the schema defined by PwBL.xsd                                                                                             |
| PwBL.xsd                          | Schema file to be used by password BO to maintain the consistent PwBL.xml.                                                                                                             |
|                                   |                                                                                                                                                                                        |
| **Logger BO**                     |                                                                                                                                                                                        |
| LoggerBL.dll                      | Business object configures logger options and act as interface to all the blades for logging configurations. Passes logging requests to loglib.dll for actual logging.                 |
| LoggerBL .xml                     | Configuration file for storing logger configuration information. This file follows the schema defined by LoggerBL.xsd                                                                  |
| LoggerBL .xsd                     | Schema file to be used by Logger Business Object to maintain the LoggerBL.xml.                                                                                                         |
| loglib.dll                        | Utility does the Logging incudes create log files and write the logs. Maintains the logcfg.ini configuration file with the logger configurations received from logger BO.              |
| Logcfg.ini                        | Configuration file for storing logger configuration information. Loglib gets the configurations from this file and logs. file path: \<ProgramData\>\\McAfee\\Endpoint Security\\Logcfg |
| **GTI BO**                        |                                                                                                                                                                                        |
| GTIBL.dll                         | It takes care of proxy server configuration and fetching rating for URL, File, Network and IP from McAfee GTI server                                                                   |
| Ts.dll                            | Provides interfaces to McAfee GTI server to get rating for URL, File, Network and IP                                                                                                   |
| GTIBL .xml                        | Configuration file for storing proxy and cache settings information. This file follows the schema defined by GTIBL.xsd                                                                 |
| GTIBL .xsd                        | Schema file to be used by GTIBL BO to maintain the consistent GTIBL.xml                                                                                                                |
|                                   |                                                                                                                                                                                        |
| **System Information**            |                                                                                                                                                                                        |
| SystemInfoBL.dll                  | Business object provides user and system information by notifications at regular interval and also facilitates to query user and system information.                                   |
| SystemInfoBL.xml                  | Configuration file for storing system related information. This file follows the schema defined by SystemInfoBL.xsd                                                                    |
| SystemInfoBL.xsd                  | Schema file to be used by Systeminfo Business Object to maintain the SystemInfoBL.xml.                                                                                                 |
|                                   |                                                                                                                                                                                        |
| **COMBO**                         |                                                                                                                                                                                        |
| COMBO.dll                         | It retrieves management mode and details of product version required for About Box                                                                                                     |
| COMBO.xml                         | Configuration file for storing About Box required information. This file follows the schema defined by COMBO.xsd                                                                       |
| COMBO.xsd                         | Schema file to be used by COMBO Business Object to maintain the COMBO.xml.                                                                                                             |
|                                   |                                                                                                                                                                                        |
| **Common LPC**                    |                                                                                                                                                                                        |
| CommonLPC.dll                     | Interface between MA and Business objects for policy, task and properties                                                                                                              |

## Default File disposition on a 64 bit system

| **64-bit Path**                    | **\<Program Files\>\\McAfee\\Endpoint Security\\Endpoint Security Platform:**                                                                                                          |
| ---------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **File Name**                      | **Notes**                                                                                                                                                                              |
| **BL Framework**                   |                                                                                                                                                                                        |
| BLFramework.dll                    | This is framework stub that contains all the external facing APIs                                                                                                                      |
| BLFrameworkU.dll                   | This is framework stub that provides support to binaries that are loaded in unsigned process to communicate with Business objects                                                      |
| BLFrameworkRT.dll                  | This library provides run-time support for executing client calls as well as server calls                                                                                              |
|                                    |                                                                                                                                                                                        |
| **BL Framework Helper Utilities**  |                                                                                                                                                                                        |
| McVariantExport.dll                | This library exports only McVariant manipulation classes (accessor, builder, etc.)                                                                                                     |
| LogLib.dll                         | Log library that provides logging framework for the modules to consume                                                                                                                 |
| EpSecApiLib.dll                    | Crypto library meant for providing encryption, hashing functionality                                                                                                                   |
| Logcfg.ini                         | Log configuration file used by Loglib library                                                                                                                                          |
|                                    |                                                                                                                                                                                        |
| **License Manager BO**             |                                                                                                                                                                                        |
| **LcBl.dll**                       | Business object (BObj) that encapsulates all the licensing functionality. This library uses nailite.dll and LcMgrImpl.dll                                                              |
| nailite.dll                        | Refactored version of legacy nailite library. Please note that this is not backward compatible with legacy nailite.                                                                    |
| LcMgrImpl.dll                      | This library is used for validating license in standalone mode.                                                                                                                        |
| LcBL.xml                           | Configuration file for storing license related information. This file follows the schema defined by LcBL.xsd                                                                           |
| LcBL.xsd                           | Schema file to be used by License Manager to maintain the LcBL.xml.                                                                                                                    |
| **Event Manager BO**               |                                                                                                                                                                                        |
| EmBL.dll                           | Business object (BObj) that encapsulates all the event logging functionlaity.                                                                                                          |
| EmBL .xml                          | Configuration file for storing event sink and severity filter related information. This file follows the schema defined by EmBL.xsd                                                    |
| EmBL .xsd                          | Schema file to be used by Event Manager to maintain the EmBL.xml.                                                                                                                      |
| DefXLateMap .xml                   | Schema file to be used by Event Manager to create the event data                                                                                                                       |
|                                    |                                                                                                                                                                                        |
| **Scheduler BO**                   |                                                                                                                                                                                        |
| TaskSchedulerBL.dll                | It is a wrapper over MA COM interface for creating and managing tasks.                                                                                                                 |
| TaskSchedulerBL.xml                | Configuration file for storing schedule task related information. This file follows the schema defined by EmBL.xsd                                                                     |
| TaskSchedulerBL.xsd                | Schema file to be used by Scheduler BO to maintain the TaskSchedulerBL.xml                                                                                                             |
|                                    |                                                                                                                                                                                        |
| **Password BO**                    |                                                                                                                                                                                        |
| PwBL.dll                           |                                                                                                                                                                                        |
| PwBL.xml                           | Configuration file for storing password settings related information. This file follows the schema defined by PwBL.xsd                                                                 |
| PwBL.xsd                           | Schema file to be used by password BO to maintain the consistent PwBL.xml.                                                                                                             |
|                                    |                                                                                                                                                                                        |
| **Logger BO**                      |                                                                                                                                                                                        |
| LoggerBL.dll                       | Business object configures logger options and act as interface to all the blades for logging configurations. Passes logging requests to loglib.dll for actual logging.                 |
| LoggerBL .xml                      | Configuration file for storing logger configuration information. This file follows the schema defined by LoggerBL.xsd                                                                  |
| LoggerBL .xsd                      | Schema file to be used by Logger Business Object to maintain the LoggerBL.xml.                                                                                                         |
| loglib.dll                         | Utility does the Logging incudes create log files and write the logs. Maintains the logcfg.ini configuration file with the logger configurations received from logger BO.              |
| Logcfg.ini                         | Configuration file for storing logger configuration information. Loglib gets the configurations from this file and logs. file path: \<ProgramData\>\\McAfee\\Endpoint Security\\Logcfg |
| **GTI BO**                         |                                                                                                                                                                                        |
| GTIBL.dll                          | It takes care of proxy server configuration and fetching rating for URL, File, Network and IP from McAfee GTI server                                                                   |
| Ts.dll                             | Provides interfaces to McAfee GTI server to get rating for URL, File, Network and IP                                                                                                   |
| GTIBL .xml                         | Configuration file for storing proxy and cache settings information. This file follows the schema defined by GTIBL.xsd                                                                 |
| GTIBL .xsd                         | Schema file to be used by GTIBL BO to maintain the consistent GTIBL.xml                                                                                                                |
|                                    |                                                                                                                                                                                        |
| **System Information**             |                                                                                                                                                                                        |
| SystemInfoBL.dll                   | Business object provides user and system information by notifications at regular interval and also facilitates to query user and system information.                                   |
| SystemInfoBL.xml                   | Configuration file for storing system realted information. This file follows the schema defined by SystemInfoBL.xsd                                                                    |
| SystemInfoBL.xsd                   | Schema file to be used by Systeminfo Business Object to maintain the SystemInfoBL.xml.                                                                                                 |
|                                    |                                                                                                                                                                                        |
| **COMBO**                          |                                                                                                                                                                                        |
| COMBO.dll                          | It retrieves management mode and details of product version required for About Box                                                                                                     |
| COMBO.xml                          | Configuration file for storing About Box required information. This file follows the schema defined by COMBO.xsd                                                                       |
| COMBO.xsd                          | Schema file to be used by COMBO Business Object to maintain the COMBO.xml.                                                                                                             |
|                                    |                                                                                                                                                                                        |
| **Common LPC**                     |                                                                                                                                                                                        |
| CommonLPC.dll                      | Interface between MA and Business objects for policy, task and properties                                                                                                              |
| **Package Manager**                |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
| **32-bit Path**                    | **\<Program Files(x86)\>\\McAfee\\Endpoint Security\\Endpoint Security Platform:**                                                                                                     |
| **File Name**                      | **Notes**                                                                                                                                                                              |
| BLFramework.dll                    | This is framework stub that contains all the external facing APIs                                                                                                                      |
| BLFrameworkU.dll                   | This is framework stub that provides support to binaries that are loaded in unsigned process to communicate with Business objects                                                      |
| BLFrameworkRT.dll                  | This library provides run-time support for executing client calls as well as server calls                                                                                              |
|                                    |                                                                                                                                                                                        |
| **BL Framework Helper Utilities**  |                                                                                                                                                                                        |
| McVariantExport.dll                | This library exports only McVariant manipulation classes (accessor, builder, etc.)                                                                                                     |
| LogLib.dll                         | Log library that provides logging framework for the modules to consume                                                                                                                 |
| EpSecApiLib.dll                    | Crypto library meant for providing encryption, hashing functionality                                                                                                                   |
| Logcfg.ini                         | Log configuration file used by Loglib library                                                                                                                                          |
| **McTray Plugin**                  |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
| **Client UI Framework Components** |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |
|                                    |                                                                                                                                                                                        |

# Registry Overview

## Business Object Registry Structure

<table>
<thead>
<tr class="header">
<th>Key</th>
<th>HKEY_LOCAL_MACHINE\SOFTWARE\[Wow6432Node\]McAfee\Endpoint\CommonBusinessObjectRegistry\&lt;BusinessObject&gt;</th>
<th></th>
<th></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td>Name</td>
<td>Type</td>
<td>Valid Values</td>
<td>Notes</td>
</tr>
<tr class="even">
<td>DllName</td>
<td>SZ</td>
<td></td>
<td>DLL name of the Business Object (BO).</td>
</tr>
<tr class="odd">
<td>ModuleName</td>
<td>SZ</td>
<td></td>
<td>Name of the module this component belongs to.</td>
</tr>
<tr class="even">
<td>InstallDir</td>
<td></td>
<td></td>
<td>Installed directory of this component.</td>
</tr>
<tr class="odd">
<td>DataDir</td>
<td>SZ</td>
<td></td>
<td>Indicates where the configuration files/settings are stored or updated.</td>
</tr>
<tr class="even">
<td>Service</td>
<td>SZ</td>
<td></td>
<td>Name of the service/executable where this DLL is loaded.</td>
</tr>
<tr class="odd">
<td>Enable</td>
<td>DWORD</td>
<td>0~3</td>
<td><p>0 – Business object is not loaded in to hosting service.</p>
<p>1 – BO is a core component. Hosting service does not start if it fails to load BO.</p>
<p>2 – Hosting service starts even if it fails to load BO.</p>
<p>3 – Load BO only when needed. Once loaded, it continues to be loaded.</p></td>
</tr>
<tr class="even">
<td>LoadOrder</td>
<td>DWORD</td>
<td>0~FFFF</td>
<td><p>0 – Highest priority, loaded first during service startup.</p>
<p>FFFF – Lowest priority, loaded at the end.</p>
<p>This entry may not be present for all the components. If not present, the DLL will be loaded at the end during service startup</p></td>
</tr>
<tr class="odd">
<td>Version</td>
<td>DWORD</td>
<td>1000</td>
<td>Version of the BO.</td>
</tr>
<tr class="even">
<td>Feature</td>
<td>SZ</td>
<td></td>
<td>Deprecated. Will be removed.</td>
</tr>
</tbody>
</table>

## Endpoint Security Platform Registry

| **Installation**                       |                                                                                              |                            |              |                                                                                                                                               |
| -------------------------------------- | -------------------------------------------------------------------------------------------- | -------------------------- | ------------ | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint                                             |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| szInstallDir32                         | SZ                                                                                           |                            |              |                                                                                                                                               |
| szInstallDir64                         | SZ                                                                                           |                            |              |                                                                                                                                               |
| RTPath                                 | SZ                                                                                           |                            |              |                                                                                                                                               |
| **Endpoint Security Platform Modules** |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common                                     |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| szInstallDir32                         | SZ                                                                                           |                            |              |                                                                                                                                               |
| szInstallDir64                         | SZ                                                                                           |                            |              |                                                                                                                                               |
| **Business Object Registry**           |                                                                                              |                            |              |                                                                                                                                               |
| **License Manager BO**                 |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\LC         |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           | LcBL.dll                   |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           | Mfeesp.exe                 |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        | 2                          |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        | 1000                       |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **Event Manager BO**                   |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\EM         |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        |                            |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **Password BO**                        |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\PW         |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        |                            |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **COMBO**                              |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\COMBO      |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        |                            |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **GTI BO**                             |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\GTI        |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        |                            |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **Scheduler BO**                       |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\SCHEDULER  |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        |                            |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **System Info BO**                     |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\SYSTEMINFO |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           | SystemInfoBL.dll           |              | Dll that provides user and system information by notifications at regular interval and also facilitates to query user and system information. |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           | \<ESPFolder\>              |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           | \<ESPFolder\>              |              |                                                                                                                                               |
| Service                                | SZ                                                                                           | Mfeesp.exe                 |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        | 2                          |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        | 1000                       |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **Logger BO**                          |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\Logger     |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           | LoggerBl.dll               |              | Dll that supports logging configuration of all blades and technologies.                                                                       |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           | \<ESPFolder\>              |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           | \<ESPFolder\>              |              |                                                                                                                                               |
| Service                                | SZ                                                                                           | Mfeesp.exe                 |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        | 2                          |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        | 1000                       |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |
| **Package Manager BO**                 |                                                                                              |                            |              |                                                                                                                                               |
| Key                                    | HKEY\_LOCAL\_MACHINE\\SOFTWARE\\McAfee\\Endpoint\\Common\\BusinessObjectRegistry\\PKGMGR     |                            |              |                                                                                                                                               |
| Name                                   | Type                                                                                         | Default                    | Valid Values | Notes                                                                                                                                         |
| DllName                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| ModuleName                             | SZ                                                                                           | Endpoint Security Platform |              |                                                                                                                                               |
| InstallDir                             | SZ                                                                                           |                            |              |                                                                                                                                               |
| DataDir                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Service                                | SZ                                                                                           |                            |              |                                                                                                                                               |
| Enable                                 | DWORD                                                                                        |                            |              |                                                                                                                                               |
| LoadOrder                              | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Version                                | DWORD                                                                                        |                            |              |                                                                                                                                               |
| Feature                                | SZ                                                                                           | Endpoint Security Platform |              | Deprecated                                                                                                                                    |

# Log Files

| Default File Path                          | \< ProgramData\>\\McAfee\\Endpoint Security\\Logs                                   |
| ------------------------------------------ | ----------------------------------------------------------------------------------- |
| File Name                                  | Notes                                                                               |
| **EndpointSecurityPlatform\_Activity.log** | Customer facing log                                                                 |
| **EndpointSecurityPlatform\_Debug.log**    | Debug log generated only when debug log is enabled for any of the module/technology |
| **EndpointSecurityPlatform\_Errors.log**   | Common error log for all the modules                                                |
|                                            |                                                                                     |

# Appendix C: Tools

## Support Tool

### License Conversion Tool

The Endpoint Security License tool (ESLicenseTool.exe) converts from
Eval(Trial) to License, only for self-managed systems having license
type as Eval, Eval expired or Eval Extended. User needs admin privileges
to run this utility.

#### Usage:

  - Binaries mentioned in the Files section should be copied from
    \\\\packagemaster\\HostCommon\\10.0.0.ver\\
    MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon
    Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip to local
    directory.

  - Extract the files from zip and access Release\<32/64\> folder based
    on Operating System.

  - Run the utility in command prompt with administrator privileges
    without arguments.

#### Troubleshooting

##### Utitlity ends with error “User needs admin privileges to run this utility"

Utility needs to execute with administrator privileges in command
prompt.

##### Utitlity ends with error “Failed to initialize framework”

Check blfrmework.dll is loaded in the eslicensetool process. Verify
blframework.dll and other components are mcafee signed.

##### Utitlity ends with error " Failed to retrive Object Handle"

Check mfeesp service is running and lcbl.dll is loaded in mfeesp
service.

##### Utitlity ends with error “Product is not StnadAlone Install and Conversion of Eval to Licensed is not Allowed”

Check client install is standalone install.

#### Files

Utility needs BLFramework and EPUtility components to communicate Harvey
Business Object’s.

##### **Default File disposition** 

All files associated with this feature

| Default File Path       | \\\\packagemaster\\HostCommon\\10.0.0.ver\\MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| File Name               | Notes                                                                                                                                                              |
| ESLicenseTool.exe       | License conversion utility                                                                                                                                         |
| **Blframework.dll**     | BLFramework library                                                                                                                                                |
| **EpSecApiLib.dll**     | Encryption Library                                                                                                                                                 |
| **LogLib.dll**          | Log Library                                                                                                                                                        |
| **McVariantExport.dll** | McVariant Library (Relate to Data Structures)                                                                                                                      |

### License Extension Tool

The Endpoint Security Extension tool (ESExtendTool.exe) extends for 30
days from expiry date, only for self-managed systems having license type
as Eval or Eval expired. User needs admin privileges to run this
utility.

#### Usage:

  - Binaries mentioned in the Files section should be copied from
    \\\\packagemaster\\HostCommon\\10.0.0.ver\\
    MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon
    Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip to local
    directory.

  - Extract the files from zip and access Release\<32/64\> folder based
    on Operating System.

  - Run the utility in command prompt with administrator privileges
    without arguments.

#### Troubleshooting

##### Utitlity ends with error “User needs admin privileges to run this utility"

Utility needs to execute with administrator privileges in command
prompt.

##### Utitlity ends with error “Failed to initialize framework”

Check blfrmework.dll is loaded in the ESExtendTool process. Verify
blframework.dll and other components are mcafee signed.

##### Utitlity ends with error " Failed to retrive Object Handle"

Check mfeesp service is running and lcbl.dll is loaded in mfeesp
service.

##### Utitlity ends with error “Product is not StnadAlone Install and extension of evaluation license is not Allowed”

Check client install is standalone install.

#### Files

Utility needs BLFramework and EPUtility components to communicate Harvey
Business Object’s.

##### **Default File disposition** 

All files associated with this feature

| Default File Path       | \\\\packagemaster\\HostCommon\\10.0.0.ver\\MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| File Name               | Notes                                                                                                                                                              |
| ESExtendTool.exe        | License extension utility                                                                                                                                          |
| **Blframework.dll**     | BLFramework library                                                                                                                                                |
| **EpSecApiLib.dll**     | Encryption Library                                                                                                                                                 |
| **LogLib.dll**          | Log Library                                                                                                                                                        |
| **McVariantExport.dll** | McVariant Library (Relate to Data Structures)                                                                                                                      |

### Password Tool

The Endpoint Security password tool (ESPwTool.exe) resets the password
to random generated password and logs reset password at command prompt.
Utility resets password only for self-managed systems and user needs
admin privileges to run this utility. Utility does not reset password
when the Password mode is in Full Access.

#### Usage:

  - Binaries mentioned in the Files section should be copied from
    \\\\packagemaster\\HostCommon\\10.0.0.ver\\
    MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon
    Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip to local
    directory.

  - Extract the files from zip and access Release\<32/64\> folder based
    on Operating System.

  - Run the utility in command prompt with administrator privileges
    without arguments.

#### Troubleshooting

##### Utitlity ends with error “User needs admin privileges to run this utility"

Utility needs to execute with administrator privileges in command
prompt.

##### Utitlity ends with error “BLFrameworkInit() Failed”

Check blfrmework.dll is loaded in the eslicensetool process. Verify
blframework.dll and other components are mcafee signed.

##### Utitlity ends with error " BLGetObjectHandle Failed COMBO bo" / “BLGetObjectHandle Failed for PW BO” / " Server not Started"

Check mfeesp service is running and pwbl.dll and combo.dll are loaded in
the mfeesp.

##### Utitlity ends with error “Password ResetTool is only allowed to use when the Client mode is StandAlone”

Check client install is standalone install.

##### " Failed to reset password” / “ BLInvokeMethod failed for PW\_REPLACE\_PASSWORD with error code” / “ BLSetPropertiesEx failed for PW\_OBJECT\_CONFIG\_PASSWORD\_MODE with error code”

For all above 3 errors, Check mfeesp service is running and pwbl.dll is
loaded in the mfeesp.

#### Files

Utility needs BLFramework and EPUtility components to communicate Harvey
Business Object’s and should be copied to the ESPw tool location.

##### **Default File disposition** 

All files associated with this feature

| Default File Path                          | \\\\packagemaster\\HostCommon\\10.0.0.ver\\MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| File Name                                  | Notes                                                                                                                                                              |
| ESPwTool.exe                               | Password reset utility                                                                                                                                             |
| **Blframework.dll**                        | BLFramework library                                                                                                                                                |
| **EpSecApiLib.dll**                        | Encryption Library                                                                                                                                                 |
| **LogLib.dll**                             | Log Library                                                                                                                                                        |
| **McVariantExport.dll**                    | McVariant Library (Relate to Data Structures)                                                                                                                      |
| **EndpointSecurityPlatform\_Activity.log** |                                                                                                                                                                    |

### Service Management Tool

The utility (epmmsutil.exe) is used to manage Endpoint MMS managed
services, i.e., to Start, Stop and Enumerate the MMS managed services.
Endpoint Self-Protection should be off to perform above actions. User
needs admin privileges to run this utility.

#### Usage:

  - Binaries mentioned in the Files section should be copied from
    \\\\packagemaster\\HostCommon\\10.0.0.ver\\
    MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon
    Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip to local
    directory.

  - Extract the files from zip and access Release\<32/64\> folder based
    on Operating System.

  - Run the utility in command prompt with administrator privileges with
    below arguments.
    
      - START \<SERVICENAME\>: Starts the provided Service name if it is
        not in start mode.
        
        Example: Epmmsutil start mfeesp
        
        Starts the mfeesp service if it is in stopped state.
    
      - STOP \<SERVICENAME\>: Stops the provided Service name if it is
        not in stop mode.
        
        Example: Epmmsutil stop mfetp
        
        Stops the mfetp service if it is in running state.
    
      - ENUM: Lists all MMS Services and their status.
    
      - Example: epmmsutil enum
    
      - HELP: epmmsutil ‘help’ will provide details of more commands.
        You can also ‘start/stop’ all windows and MMS integrated
        services.
        
        Example: epmmsutil -help

#### Troubleshooting

##### Utitlity ends with error “User needs admin privileges to run this utility"

Utility needs to execute with administrator privileges in command
prompt.

##### Utility ends with error “BL Framework initialization failed\!\!\!"

Check blfrmework.dll is loaded in the epmmsutil process. Verify
blframework.dll and other components are mcafee signed.

##### " Self protection is ON\!\!\! Command execution not allowed\!\!\!"

Check Self Protection is ON and should be off to run the command.

##### " Service not found" / " is not a valid service."

Check the service requested to start is Harvey service and registered
with MMS. Only registered Harvey services with MMS can be started. Query
with enum switch for list of registered services.

##### “ is not an endpoint MMS managed service and cannot be controlled. “

Check the service requested to start is registered with MMS.

#### Files

Utility needs BLFramework and EPUtility components to communicate Harvey
Business Object’s and MMS Util. These dependent components should be
copied to the EPMMS Utility location.

##### **Default File disposition** 

All files associated with this feature

| Default File Path       | \\\\packagemaster\\HostCommon\\10.0.0.ver\\MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| File Name               | Notes                                                                                                                                                              |
| epmmsutil.exe           | Endpoint MMS services management utility                                                                                                                           |
| **Blframework.dll**     | BLFramework library                                                                                                                                                |
| **EpSecApiLib.dll**     | Encryption Library                                                                                                                                                 |
| **LogLib.dll**          | Log Library                                                                                                                                                        |
| **McVariantExport.dll** | McVariant Library (Relate to Data Structures)                                                                                                                      |

## 

## Policy Import/Export Tool

This tool (ESConfigTool.exe) is used for exporting and importing policy
configuration. Utility updates about box details during importing policy
configuration and please refer the About box section for complete
details. Utility needs password if the client interface is password
protected. Only Encrypted file should be provided for import. User needs
admin privileges to run this utility.

### **Usage**:

  - Binaries mentioned in the Files section should be copied from
    \\\\packagemaster\\HostCommon\\10.0.0.ver\\
    MULTI-LANGUAGE\\\<\#bldNo.bld\>\\Package\_\<\#No\>\\HostCommon
    Support Tools 10.0.0 Build \<\#No\> Package \<\#No\>.zip to local
    directory.

  - Extract the files from zip and access Release\<32/64\> folder based
    on Operating System.

  - Run the utility in command prompt with administrator privileges with
    below arguments.

<!-- end list -->

  - Export: Exports specific module/all modules policy configuration to
    provided file.

> Syntax: Esconfigtool export \<filename\> \[/module \<TP|FW|WC|ESP\>\]
> \[/unlock \<password\> \] \[/plaintext \]

  - Filename – filename to which policy configuration of BO\[s\] to
    export.

  - Module – is an optional parameter and indicates which BO policy is
    to be exported. Exports all modules if not provided.

  - Unlock- is required if the client interface is password protected
    (not full access).

  - Plaintext-

<!-- end list -->

  - Import: Imports specific module /all modules policy configuration
    from an encrypted input file to specific module /all modules.

> Syntax: esconfigtool import \<filename\> \[/module \<TP|FW|WC|ESP\> \]
> \[/unlock \<password\> \] \[/policyname \<name\> \]

  - Filename – filename from which policy configuration of BO\[s\] to
    import to BO\[s\].

  - Module – is an optional parameter and indicates to which BO, policy
    is to be imported from an input file. Imports to all modules if not
    provided.

  - Unlock- is required if the client interface is password protected
    (not full access).

  - Policyname- Name of policy configuration to import to specified
    BO\[s\].

### Troubleshooting

#### Utitlity ends with error “User needs admin privileges to run this utility"

Utility needs to execute with administrator privileges in command
prompt.

#### Utitlity ends with error “Failed to initialize BL Framework”"

Check blfrmework.dll is loaded in the epmmsutil process. Verify
blframework.dll and other components are mcafee signed.

#### "Unable to import policies, specified module is not installed" / "Unable to export policies, specified module is not installed"

Check the module opted for import / export is installed.

#### " Unable to get business object list"

Check the blframework.dll is loaded in the esconfigtool service.

#### " Failed to encrypt data" / “ Failed to decrypt data” 

Check the **EpSecApiLib.dll is l**oaded in the esconfigtool service and
mcafee signed.

#### " Failed to import policies, empty file name"

Check the file used to import has policies.

### Files

#### Default File disposition 

All files associated with this feature

| Default File Path       |                                                                        |
| ----------------------- | ---------------------------------------------------------------------- |
| File Name               | Notes                                                                  |
| ESConfigTool.exe        | Configuration utility for exporting and importing policy configuration |
| **Blframework.dll**     | BLFramework library                                                    |
| **EpSecApiLib.dll**     | Encryption Library                                                     |
| **LogLib.dll**          | Log Library                                                            |
| **McVariantExport.dll** | McVariant Library (Relate to Data Structures)                          |

# Appendix D: Known Issues

\<Refer Release Notes / ReadMe, KB Articles\>
