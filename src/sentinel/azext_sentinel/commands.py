# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long
from azure.cli.core.commands import CliCommandType
from azext_sentinel._validators import detection_create_validator, detection_generate_validator
from azext_sentinel._client_factory import cf_sentinel, cf_sentinel_alert_rules
from azext_sentinel._exception_handler import resource_exception_handler


def load_command_table(self, _):

    sentinel_sdk = CliCommandType(
        operations_tmpl='azext_sentinel.vendored_sdks.operations#{}',
        client_factory=cf_sentinel,
        exception_handler=resource_exception_handler
    )

    sentinel_alert_rules_sdk = CliCommandType(
        operations_tmpl='azext_sentinel.vendored_sdks.operations#AlertRulesOperations.{}',
        client_factory=cf_sentinel_alert_rules,
        exception_handler=resource_exception_handler
    )
    cmd_util = CliCommandType(
        operations_tmpl='azext_sentinel.custom#{}'
    )

    with self.command_group('sentinel detection', sentinel_alert_rules_sdk) as g:
        g.command('show', 'get')
        g.command('delete', 'delete')
        g.command('list', 'list')

    with self.command_group('sentinel detection', sentinel_sdk) as g:
        g.custom_command('create', 'create_detections', validator=detection_create_validator)
        g.custom_command('update', 'create_detections', validator=detection_create_validator)

    with self.command_group('sentinel detection', cmd_util) as g:
        g.command('validate', 'validate_detections')
        g.command('generate', 'generate_detection', validator=detection_generate_validator)

    with self.command_group('sentinel', is_preview=True):
        pass
