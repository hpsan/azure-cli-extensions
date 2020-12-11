# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint: disable=line-too-long
from argcomplete import FilesCompleter
from argcomplete.completers import DirectoriesCompleter, ChoicesCompleter
from azure.cli.core.commands.parameters import get_three_state_flag, file_type
from knack.arguments import CLIArgumentType


def load_arguments(self, _):
    resources_directory_type = CLIArgumentType(
        options_list=["--resources-directory", "-d"],
        completer=DirectoriesCompleter(),
        type=file_type,
        help="Directory which contains the resources",
    )
    resource_file_type = CLIArgumentType(
        options_list=["--resource-file", "-f"],
        completer=FilesCompleter(allowednames=["json", "yaml"]),
        type=file_type,
        help="Resource file path",
    )
    resource_schema_type = CLIArgumentType(
        options_list=["--resource-schema", "-s"],
        completer=FilesCompleter(allowednames=["json", "yaml"], directories=False),
        type=file_type,
        help="Resource schema file path",
    )
    resource_type = CLIArgumentType(
        options_list=["--resource-type", "-t"],
        choices=["scheduled_detection", "microsoft_security_detection", "data_source"],
        help="Resource type",
    )
    aux_subscription_type = CLIArgumentType(
        options_list=["--aux-subscriptions"],
        help="Auxiliary subscriptions for multi-tenant resource deployment such as cross tenant Logic App linking",
    )

    with self.argument_context("sentinel") as c:
        c.argument(
            "workspace_name",
            options_list=["--workspace-name", "-n"],
            help="Name of the Sentinel Workspace",
        )

    with self.argument_context("sentinel create") as c:
        c.argument("aux_subscriptions", aux_subscription_type)
        c.argument("resource_type", resource_type)
        c.argument("resources_directory", resources_directory_type)
        c.argument("resource_file", resource_file_type)
        c.argument(
            "enable_validation",
            options_list=["--enable-validation"],
            arg_type=get_three_state_flag(),
            help="Enable/Disable resource validation before deploying it",
        )
        c.argument("resource_schema", resource_schema_type)

    with self.argument_context("sentinel validate") as c:
        c.argument("resource_type", resource_type)
        c.argument("resources_directory", resources_directory_type)
        c.argument("resource_file", resource_file_type)
        c.argument("resource_schema", resource_schema_type)

    with self.argument_context("sentinel generate") as c:
        c.argument("resource_type", resource_type)
        c.argument("resources_directory", resources_directory_type)
        c.argument(
            "skip_interactive",
            options_list=["--skip-interactive"],
            arg_type=get_three_state_flag(),
            help="Enable/Disable interactive resource generation",
        )
        # TODO: Add all detection configurations as arguments here
        c.argument(
            "name",
            options_list=["--name", "-n"],
            help="Name of your resource(alphanumeric without spaces)",
        )
        c.argument(
            "create_directory",
            options_list=["--create-dir"],
            arg_type=get_three_state_flag(),
            help="Enable/Disable creating new directory for the resource",
        )
        c.argument(
            "with_documentation",
            options_list=["--with-documentation", "--doc"],
            arg_type=get_three_state_flag(),
            help="Enable/Disable resource documentation",
        )
