# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
# pylint: disable=line-too-long
from argcomplete import FilesCompleter
from argcomplete.completers import DirectoriesCompleter
from azure.cli.core.commands.parameters import get_three_state_flag, file_type
from knack.arguments import CLIArgumentType


def load_arguments(self, _):
    detections_directory_type = CLIArgumentType(options_list=['--detections-directory', '-d'],
                                                completer=DirectoriesCompleter(), type=file_type,
                                                help='Directory which contains the detection files')
    detection_file_type = CLIArgumentType(options_list=['--detection-file', '-f'],
                                          completer=FilesCompleter(allowednames=['json', 'yaml']),
                                          type=file_type, help="File path of the detection")
    detection_schema_type = CLIArgumentType(options_list=['--detection-schema', '-s'],
                                            completer=FilesCompleter(allowednames=['json', 'yaml'], directories=False),
                                            type=file_type, help="File path of the detection schema")
    data_sources_directory_type = CLIArgumentType(options_list=['--data-sources-directory', '-d'],
                                                 completer=DirectoriesCompleter(), type=file_type,
                                                 help='Directory which contains data source files')
    data_source_file_type = CLIArgumentType(options_list=['--data-source-file', '-f'],
                                            completer=FilesCompleter(allowednames=['json', 'yaml']),
                                            type=file_type, help="File path of the data source")
    data_source_schema_type = CLIArgumentType(options_list=['--data-source-schema', '-s'],
                                              completer=FilesCompleter(allowednames=['json', 'yaml'],
                                                                       directories=False),
                                              type=file_type, help="File path of the data source schema")

    with self.argument_context('sentinel') as c:
        c.argument('workspace_name', options_list=['--workspace-name', '-n'], help='Name of the Sentinel Workspace')

    with self.argument_context('sentinel detection create') as c:
        c.argument('detections_directory', detections_directory_type)
        c.argument('detection_file', detection_file_type)
        c.argument('enable_validation', options_list=['--enable-validation'],
                   arg_type=get_three_state_flag(), help='Enable/Disable detection validation before deploying it')
        c.argument('detection_schema', detection_schema_type)

    with self.argument_context('sentinel detection validate') as c:
        c.argument('detections_directory', detections_directory_type)
        c.argument('detection_file', detection_file_type)
        c.argument('detection_schema', detection_schema_type)

    with self.argument_context('sentinel detection generate') as c:
        c.argument('detections_directory', detections_directory_type)
        c.argument('skip_interactive', options_list=['--skip-interactive'],
                   arg_type=get_three_state_flag(), help='Enable/Disable interactive detection creation')
        # TODO: Add all detection configurations as arguments here
        c.argument('name', options_list=['--name', '-n'], help='Name of your detection(alphanumeric without spaces)')
        c.argument('create_directory', options_list=['--create-dir'],
                   arg_type=get_three_state_flag(), help='Enable/Disable creating new directory for the detection')
        c.argument('with_documentation', options_list=['--with-documentation', '--doc'],
                   arg_type=get_three_state_flag(), help='Enable/Disable detection documentation')

    with self.argument_context('sentinel data_source validate') as c:
        c.argument('data_sources_directory', data_sources_directory_type)
        c.argument('data_source_file', data_source_file_type)
        c.argument('data_source_schema', data_source_schema_type)

    with self.argument_context('sentinel data_source generate') as c:
        c.argument('data_sources_directory', data_sources_directory_type)
        c.argument('skip_interactive', options_list=['--skip-interactive'],
                   arg_type=get_three_state_flag(), help='Enable/Disable interactive data siyrce creation')
        # TODO: Add all detection configurations as arguments here
        c.argument('name', options_list=['--name', '-n'], help='Name of your data source(alphanumeric without spaces)')
        c.argument('create_directory', options_list=['--create-dir'],
                   arg_type=get_three_state_flag(), help='Enable/Disable creating new directory for the data source')
        c.argument('with_documentation', options_list=['--with-documentation', '--doc'],
                   arg_type=get_three_state_flag(), help='Enable/Disable data source documentation')