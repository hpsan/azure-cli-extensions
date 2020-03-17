## Goal
The goal is the intended purpose of the alert. It is a simple, plaintext description of the type of behavior you're attempting to detect 

## Strategy Abstract
The strategy abstract is a high-level walkthrough of how the detection functions. This describes what the alert is looking for, what technical data sources are used, any enrichment that occurs, and any false positive minimization steps.

## Technical Context
Technical Context provides detailed information and background needed for a responder to understand all components of the alert. This should appropriately link to any platform or tooling knowledge and should include information about the direct aspects of the alert. The goal of the Technical Context section is to provide a self-contained reference for a responder to make a judgement call on any potential alert, even if they do not have direct subject matter expertise on the detection itself.

## Blind Spots and Assumptions
Blind Spots and Assumptions are the recognized issues, assumptions, and areas where a Detection may not fire. No Detection is perfect and identifying assumptions and blind spots can help other engineers understand how a Detection may fail to fire or be defeated by an adversary.

## False Positives
False Positives are the known instances of a Detection misfiring due to a misconfiguration, idiosyncrasy in the environment, or other non-malicious scenario. The False Positives section notes uniqueness to your own environment, and should include the defining characteristics of any activity that could generate a false positive alert.

Each alert / detection strategy needs to be tested and refined to remove as many false positives as possible before it is put into production.

False positive minimization relies on looking at several principles of the strategy and making adjustments, such as:

- Add an additional component to the rule to maximize true positives.
- Remove common false positives through patterns.
- Back-end filtering to store indices of expected false positives.

Ideally, you want your strategy to have the fewest false positives possible while maintaining the spirit of your rule. If a low false positive rate cannot be reached, the alert may need to be broken down, refactored, or entirely discarded.

## Validation
Validation are the steps required to generate a representative true positive event which triggers this alert. This is similar to a unit test and describes how an engineer can cause the detection to fire. 

Each alert / detection strategy must have true positive validation. This is a testing process designed to prove the true positives are detected.

True positive validation relies on generating a scenario in which the detection strategy is testing, and then validating in the tool.

To perform positive validation:

- Generate a scenario where a true positive would be generated.
- Document the process of your testing scenario.
- From a testing device, generate a true positive alert.
- Validate the true positive alert was detected by the strategy.

If you are unable to generate a true positive alert, the alert may need to be broken down, refactored, or entirely discarded.

## Automation
Automation in form of a Playbook for enrichment (if required) and/or an Azure Notebook for investigation is a required deliverable for detections with a high volume are required deliverables.

This is where you want to link the work items for Playbooks and/or Azure Notebooks. 

## Response
These are the general response steps in the event that this alert fired. These steps instruct the next responder on the process of triaging and investigating an alert.

## References
Additional Resources are any other internal, external, or technical references that may be useful for understanding the Detection.