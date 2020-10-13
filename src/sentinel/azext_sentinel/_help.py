# coding=utf-8
# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from knack.help_files import helps  # pylint: disable=unused-import


helps[
    "sentinel"
] = """
    type: group
    short-summary: Commands to manage Sentinels.
"""

helps[
    "sentinel create"
] = """
    type: command
    short-summary: Create a Sentinel.
"""

helps[
    "sentinel list"
] = """
    type: command
    short-summary: List Sentinels.
"""

helps[
    "sentinel delete"
] = """
    type: command
    short-summary: Delete a Sentinel.
"""

helps[
    "sentinel show"
] = """
    type: command
    short-summary: Show details of a Sentinel.
"""

helps[
    "sentinel update"
] = """
    type: command
    short-summary: Update a Sentinel.
"""
