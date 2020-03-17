# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

# pylint: disable=line-too-long
from azext_sentinel._validators import detection_input_validator
from azure.cli.core.commands import CliCommandType
from azext_sentinel._client_factory import cf_sentinel


def load_command_table(self, _):
    """
    az sentinel detection generate scaffold --detection-dir $detectionDir --detection-name $detectionName
    az sentinel detection validate --detection-dir $detectionDir --detection-schema --$detectionSchema
    az sentinel detection validate --detection-file $detectionFile  --detection-schema --$detectionSchema
    az sentinel detection create --detection-dir $detectionDir --resource-group $ResourceGroup --workspace $Workspace
    az sentinel detection create --detection-file $detectionFile --resource-group $ResourceGroup --workspace $Workspace
    az sentinel detection run-query --detection-id $detectionName --resource-group $ResourceGroup --workspace $Workspace
    """

    sentinel_sdk = CliCommandType(
        operations_tmpl='azext_sentinel.vendored_sdks.operations#AlertRulesOperations.{}',
        client_factory=cf_sentinel)
    cmd_util = CliCommandType(
        operations_tmpl='azext_sentinel.custom#{}'
    )

    with self.command_group('sentinel detection', sentinel_sdk) as g:
        g.custom_command('create', 'create_detections', validator=detection_input_validator)
        g.custom_command('update', 'create_detections', validator=detection_input_validator)
        g.command('list', 'list')
        g.command('delete', 'delete')
        g.show_command('show', 'get')

    with self.command_group('sentinel detection', cmd_util) as g:
        g.command('validate', 'validate_detections')
        g.command('generate', 'generate_detection')

    with self.command_group('sentinel', is_preview=True):
        pass

