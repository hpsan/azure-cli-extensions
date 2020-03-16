# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint: disable=line-too-long
from azext_sentinel._validators import detection_input_validator
from azure.cli.core.commands.parameters import get_three_state_flag
from knack.arguments import CLIArgumentType


def load_arguments(self, _):

    with self.argument_context('sentinel') as c:
        c.argument('workspace_name', options_list=['--workspace-name', '-n'], help='Name of the Sentinel Workspace')

    with self.argument_context('sentinel detection create') as c:
        c.argument('detections_folder', options_list=['--detections-folder', '-df'],
                   help='Folder which contains the detection files', validator=detection_input_validator)
        c.argument('enable_validation', options_list=['--enable-validation', '-vl'],
                   arg_type=get_three_state_flag(), help='Folder which contains the detection files')
        c.argument('detection_schema', options_list=['--detection-schema', '-ds'],
                   help='JSON schema file to use for validating the detections')

    with self.argument_context('sentinel detection validate') as c:
        c.argument('detections_folder', options_list=['--detections-folder', '-df'],
                   help='Folder which contains the detection files')
        c.argument('detection_schema', options_list=['--detection-schema', '-ds'],
                   help='JSON schema file to use for validating the detections')

        # c.argument('detection', options_list=['--detection', '-d'],
        #            help='Detection file')
