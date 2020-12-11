# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long
from azure.cli.core.commands import CliCommandType
from azext_sentinel._validators import resource_create_validator, generate_validator
from azext_sentinel._client_factory import cf_sentinel, cf_sentinel_alert_rules


def load_command_table(self, _):

    sentinel_sdk = CliCommandType(
        operations_tmpl="azext_sentinel.vendored_sdks.security_insights.operations#{}",
        client_factory=cf_sentinel,
    )

    sentinel_alert_rules_sdk = CliCommandType(
        operations_tmpl="azext_sentinel.vendored_sdks.security_insights.operations#AlertRulesOperations.{}",
        client_factory=cf_sentinel_alert_rules,
    )
    cmd_util = CliCommandType(operations_tmpl="azext_sentinel.custom#{}")

    with self.command_group("sentinel", sentinel_alert_rules_sdk) as g:
        g.command("show", "get")
        g.command("delete", "delete")
        g.command("list", "list")

    with self.command_group("sentinel", sentinel_sdk) as g:
        g.custom_command(
            "create", "create_resources", validator=resource_create_validator
        )
        g.custom_command(
            "update", "create_resources", validator=resource_create_validator
        )

    with self.command_group("sentinel", cmd_util) as g:
        g.command("validate", "validate_resources")
        g.command("generate", "generate_resource", validator=generate_validator)

    with self.command_group("sentinel", is_preview=True):
        pass
