# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint: disable=line-too-long

from knack.arguments import CLIArgumentType


def load_arguments(self, _):
    workspace_name_type = CLIArgumentType(options_list='--workspace-name', help='Name of the Sentinel Workspace',
                                          id_part='name')

    with self.argument_context('sentinel') as c:
        c.argument('workspace_name', workspace_name_type, options_list=['--name', '-n'])

    with self.argument_context('sentinel get') as c:
        c.argument('detection_id', options_list=['--detection-id', '-di'], help='ID of the detection to get')

    with self.argument_context('sentinel delete') as c:
        c.argument('detection_id', options_list=['--detection-id', '-di'], help='ID of the detection to delete')

    with self.argument_context('sentinel detection create') as c:
        c.argument('detections_folder', options_list=['--detections-folder', '-df'],
                   help='Folder which contains the detection files')
        c.argument('enable_validation', options_list=['--enable-validation', '-vl'],
                   help='Folder which contains the detection files')
        c.argument('detection_schema', options_list=['--detection-schema', '-ds'],
                   help='JSON schema file to use for validating the detections')

    with self.argument_context('sentinel detection validate') as c:
        c.argument('detections_folder', options_list=['--detections-folder', '-df'],
                   help='Folder which contains the detection files')
        c.argument('detection_schema', options_list=['--detection-schema', '-ds'],
                   help='JSON schema file to use for validating the detections')

        # c.argument('detection', options_list=['--detection', '-d'],
        #            help='Detection file')
