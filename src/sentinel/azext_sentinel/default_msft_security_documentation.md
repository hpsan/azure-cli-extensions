## Goal
The goal is the intended purpose of the alert. It is a simple, plaintext description of the type of behavior you're attempting to detect 

## Microsoft Security Detection Details
Please provide a brief description of the Microsoft Security Detection in use and its use cases

## Strategy Abstract
The strategy abstract is a high-level walkthrough of how the detection functions. This describes what the alert is looking for, what technical data sources are used, any enrichment that occurs, and any false positive minimization steps.

## Technical Context
Technical Context provides detailed information and background needed for a responder to understand all components of the alert. This should appropriately link to any platform or tooling knowledge and should include information about the direct aspects of the alert. The goal of the Technical Context section is to provide a self-contained reference for a responder to make a judgement call on any potential alert, even if they do not have direct subject matter expertise on the detection itself.

## False Positives
False Positives are the known instances of a Detection misfiring due to a misconfiguration, idiosyncrasy in the environment, or other non-malicious scenario. The False Positives section notes uniqueness to your own environment, and should include the defining characteristics of any activity that could generate a false positive alert.

## Included Detections
List of detection names on which the cases will be generated 

## Excluded Detections
List of detection names which must be excluded from this detection

## Response
These are the general response steps in the event that this alert fired. These steps instruct the next responder on the process of triaging and investigating an alert.

## References
Additional Resources are any other internal, external, or technical references that may be useful for understanding the Detection.