# Microsoft Azure CLI 'sentinel' Extension

## What is Azure Sentinel?
Azure Sentinel is a scalable, cloud-native, security information event management (SIEM) and
security orchestration automated response (SOAR) solution. Azure Sentinel delivers intelligent security analytics and
threat intelligence across the enterprise, providing a single solution for alert detection, threat visibility,
proactive hunting, and threat response

## Sentinel As Code
While Sentinel provides a UI wizard to configure new Detections(also referred to as Analytics Rules)
through the **Analytics**  tab, there is still a need to manage these detections via code so that
- Detections can be version controlled
- CI/CD steps such as testing, validation, staged deployments, rollbacks etc., can be setup
- Detections be deployed to multiple environments(such as different workspaces, subscriptions etc.,) 
- Peer reviews for these detections can be performed via Github/Azure Repos before they are deployed
- Refactoring across several detections are easy

This document will show you how to use the Azure Sentinel Extension independently as well as
in conjunction with Azure Pipelines to develop and deploy detections

Note: This is only applicable for the custom resources your organization maintains. Refer to 
https://github.com/Azure/Azure-Sentinel for public Sentinel resources.
## Architecture
At a high level, this CLI wraps the Azure API endpoints available via https://github.com/Azure/azure-rest-api-specs/
and adds a few helper methods such as validate, create that makes it easy to create a detection from scratch
This CLI aims to support both
- Development, validation and deployment to Azure Sentinel instance directly via CLI
- Validation and deployment to Azure Sentinel instances via CI/CD pipelines such as Azure Pipelines

## Detection Workflow
### Installing the CLI extension locally
Until the extension is published into the extensions index, you'll need to build it from source
In order to install from source
- Install azure CLI from https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest
- Install Azure CLI Dev Tools https://pypi.org/project/azdev/0.0.6/ (preferable into your virtualenv)
- Build this extension with **azdev extension build sentinel**
- Install the extension with **az extension add --source dist/sentinel-0.1.1-py2.py3-none-any.whl**

## CLI Commands
```bash
(azuredev) [master !x+] ~/Workspace/github/azure-cli-extensions/src/sentinel  $ az sentinel -h
                                                                                
Group
    az sentinel : Commands to manage Sentinels.
        This command group is in preview. It may be changed/removed in a future release.
Commands:
    create   : Create a Sentinel resource.
    delete   : Delete a Sentinel resource.
    generate : Creates a scaffolding for the given resource based on the configured template.
    list     : List Sentinels.
    show     : Show details of a Sentinel.
    update   : Update a Sentinel resource.
    validate : Validates the given resources against its configured JSON schema.
```
## Developing a new Scheduled Detection
We'll be using the https://github.com/hpsan/sample-sentinel-setup to illustrate how to use the CLI commands
### Step 1: Create the scaffold
```bash
(azuredev) [master] ~/Workspace/sample-sentinel-setup/Detections  $ az sentinel generate -t scheduled_detection
Command group 'sentinel' is in preview. It may be changed/removed in a future release.
Name your detection(alphanumeric without spaces): NewDetection
(azuredev) [master ?] ~/Workspace/sample-sentinel-setup/Detections  $ tree NewDetection/
NewDetection/
├── NewDetection.md
└── NewDetection.yaml

0 directories, 2 files
(azuredev) [master ?] ~/Workspace/sample-sentinel-setup/Detections  $
```
### Step 2: Complete your detection configuration 
Open NewDetection.yaml. 

You will see that there is a basic template populated for you with some good defaults and 
some placeholder tags for properties that you need to fill

_Note:_ 
Recommend using VSCode to fill out these properties and setting up JSON schema validation for your files.

You will find that setup in the [toy repo](https://github.com/hpsan/sample-sentinel-setup) For details, please refer
to https://joshuaavalon.io/intellisense-json-yaml-vs-code

### Step 3: Validate your detection configuration
Run the validate command to check your detection configuration
```bash
(azuredev) [master ?] ~/Workspace/sample-sentinel-setup/Detections  $ az sentinel validate -t scheduled_detection -d .
Command group 'sentinel' is in preview. It may be changed/removed in a future release.
'<PLACEHOLDER>' is not one of ['InitialAccess', 'Execution', 'Persistence', 'PrivilegeEscalation', 'DefenseEvasion', 'CredentialAccess', 'Discovery', 'LateralMovement', 'Collection', 'Exfiltration', 'CommandAndControl', 'Impact']
(azuredev) [master ?] ~/Workspace/sample-sentinel-setup/Detections  $
```
Fix your detection configuration until the validation passes
```bash
(azuredev) [master ?] ~/Workspace/sample-sentinel-setup/Detections  $ az sentinel validate -t scheduled_detection -d .
Command group 'sentinel' is in preview. It may be changed/removed in a future release.
(azuredev) [master ?] ~/Workspace/sample-sentinel-setup/Detections  $
```

### Step 4: Deploy your detections
You can deploy your detection using the **az sentinel detection create** command
If you are doing it directly from your development, you will need to login into your instance via **az login** before running it

You can use **az sentinel detection list** command to list all the detections that are deployed in your instance

But you'll likely want to run it as a part of a CI/CD pipeline. This repo includes a sample azure pipeline YAML file
that you can use. You will also find it in the toy repo https://github.com/hpsan/sample-sentinel-setup/blob/master/.azure-pipelines/deploy.yml#L31

For more details on how to setup a deployment pipeline using Azure pipelines, refer to https://docs.microsoft.com/en-us/azure/devops/pipelines/yaml-schema

## Development
Read up on https://github.com/Azure/azure-cli/blob/dev/doc/authoring_command_modules/authoring_commands.md to understand how to author new commands in the extension

Read up on https://github.com/Azure/azure-cli/blob/master/doc/extensions/authoring.md to understand how to perform basic actions with the CLI like lint checks, tests etc.,
### Testing
You can test using the azure CLI dev tools extension. Note that it uses VCR.py to perform integration tests. So you will need to manually change the references to the
recorded file if you are running a live test. See https://vcrpy.readthedocs.io/en/latest/ for details
```bash
(azuredev) [master !x+] ~/Workspace/github/azure-cli-extensions/src/sentinel  $ azdev test sentinel --series

=============
| Run Tests |
=============

The tests are set to run against current profile latest.

test index found: /Users/hprasann/.azdev/env_config/Users/hprasann/.venv/azuredev/test_index/latest.json

TESTS: sentinel

============================================================================================= test session starts ==============================================================================================
platform darwin -- Python 3.7.5, pytest-4.4.2, py-1.8.1, pluggy-0.13.1
rootdir: /Users/hprasann/Workspace/github/azure-cli-extensions/src/sentinel
plugins: xdist-1.31.0, nbval-0.9.5, forked-1.1.3
collected 3 items

azext_sentinel/tests/latest/test_sentinel_scenario.py ...                                                                                                                                                [100%]

----------------------------------------------------- generated xml file: /Users/hprasann/.azdev/env_config/Users/hprasann/.venv/azuredev/test_results.xml -----------------------------------------------------
=========================================================================================== 3 passed in 2.80 seconds ===========================================================================================

 Results
=========

Time: 2.800 sec	Tests: 3	Skipped: None	Failures: 0	Errors: 0

(azuredev) [master !x+] ~/Workspace/github/azure-cli-extensions/src/sentinel  $
```
### Building
**azdev extension build sentinel** will create a whl file under a dist directory

## Appendix
### Design considerations
- There is a CLI command for data_source. It currently a work in progress, and does not currently deploy the data source
- There are a couple of vendored in SDKs generated from https://github.com/Azure/azure-rest-api-specs/ using https://github.com/Azure/autorest/ Ideally, this should use https://github.com/Azure/azure-sdk-for-python
to get those libraries
- If you want to deploy to multiple instances of Azure Sentinel(say in different subscriptions, workspaces), you can configure them in Azure Pipelines with different Service Connections  
### Roadmap
- Add support to deploying other Sentinel resources such as playbooks, data sources, etc., via the CLI
- Add support to new features added to detections such as alert grouping. This is currently blocked on this being available via the Azure REST API  
### References
- Prior art, Powershell library https://github.com/wortell/AZSentinel
- Prior art, sample repo setup using the powershell library https://github.com/javiersoriano/sentinelascode