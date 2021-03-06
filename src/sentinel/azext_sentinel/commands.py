# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long
from azure.cli.core.commands import CliCommandType
from azext_sentinel._validators import detection_create_validator, data_source_create_validator, generate_validator
from azext_sentinel._client_factory import cf_sentinel, cf_sentinel_alert_rules


def load_command_table(self, _):

    sentinel_sdk = CliCommandType(
        operations_tmpl='azext_sentinel.vendored_sdks.security_insights.operations#{}',
        client_factory=cf_sentinel
    )

    sentinel_alert_rules_sdk = CliCommandType(
        operations_tmpl='azext_sentinel.vendored_sdks.security_insights.operations#AlertRulesOperations.{}',
        client_factory=cf_sentinel_alert_rules
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
        g.command('generate', 'generate_detection', validator=generate_validator)

    with self.command_group('sentinel data_source', sentinel_sdk) as g:
        g.custom_command('create', 'create_data_sources', validator=data_source_create_validator)
        g.custom_command('update', 'create_data_sources', validator=data_source_create_validator)

    with self.command_group('sentinel data_source', cmd_util) as g:
        g.command('validate', 'validate_data_sources')
        g.command('generate', 'generate_data_source', validator=generate_validator)

    with self.command_group('sentinel', is_preview=True):
        pass
