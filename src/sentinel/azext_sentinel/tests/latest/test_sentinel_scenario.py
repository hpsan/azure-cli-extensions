# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import tempfile
from pathlib import Path

import yaml
from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer, create_random_name)
from knack.util import CLIError

TEST_ROOT_PATH = Path(__file__).parent
TEST_RESOURCE_GROUP_PREFIX = 'test_sentinel_rg_'
TEST_WORKSPACE_TEMPLATE = TEST_ROOT_PATH / 'deploylaworkspacetemplate.json'
TEST_VALID_DETECTIONS_FOLDER = TEST_ROOT_PATH / 'test_detections/valid_detections'
TEST_INVALID_DETECTIONS_FOLDER = TEST_ROOT_PATH / 'test_detections/invalid_detections'
TEST_INDIVIDUAL_DETECTION_FILE = TEST_ROOT_PATH / 'test_detections/test_individual_detection.yaml'
TEST_LOCATION = 'eastus'

# See test_sentinel.yaml for details
# TODO: Load recorded constants from the recorded files
RECORDED_RESOURCE_GROUP = 'test_sentinel_rg_rgfaxbp'
RECORDED_WORKSPACE_NAME = 'clitestrw4cmvsk4675avtji'


class SentinelScenarioTest(ScenarioTest):
    def setUp(self):
        self.test_individual_detection = yaml.safe_load(TEST_INDIVIDUAL_DETECTION_FILE.read_text())
        self.test_folder_detections = \
            [yaml.safe_load(file.read_text()) for file in TEST_VALID_DETECTIONS_FOLDER.glob('**/*.yaml')]
        if self.in_recording:
            self.resource_group_name = create_random_name(TEST_RESOURCE_GROUP_PREFIX)
            self.workspace_name = create_random_name()
            rg_create_template = 'az group create --location {} --name {}'
            workspace_create_template = 'az deployment group create -g {} --name LAWorkspace --template-file {} ' \
                                        '--parameters workspaceName={} '
            self.cmd(rg_create_template.format(TEST_LOCATION, self.resource_group_name))
            self.cmd(workspace_create_template.format(
                self.resource_group_name, str(TEST_WORKSPACE_TEMPLATE), self.workspace_name))
        else:
            self.resource_group_name = RECORDED_RESOURCE_GROUP
            self.workspace_name = RECORDED_WORKSPACE_NAME
        super(ScenarioTest, self).setUp()

    def tearDown(self):
        if self.in_recording:
            rg_delete_template = 'az group delete --name {} --yes --no-wait'
            workspace_delete_template = 'az deployment group delete -g {} --name {} --no-wait'
            self.cmd(workspace_delete_template.format(self.resource_group_name, self.workspace_name))
            self.cmd(rg_delete_template.format(self.resource_group_name))

    def test_sentinel_detection_create(self):
        # Create test detection
        create_cmd_template = 'az sentinel detection create -g {} -n {} -f {}'
        create_cmd = create_cmd_template.format(
            self.resource_group_name, self.workspace_name, TEST_INDIVIDUAL_DETECTION_FILE)
        self.cmd(create_cmd)

        # Test if the deployed detection is the same as the local detection to see if create worked as expected
        file_deployed_detection = self._get_sentinel_detection(self.test_individual_detection['id'])
        self.assertEqual(file_deployed_detection['name'], self.test_individual_detection['id'])

        # Cleanup created detection
        self._delete_sentinel_detection(self.test_individual_detection['id'])

        # Test detection creation from folder
        create_cmd_template = 'az sentinel detection create -g {} -n {} -d {}'
        create_cmd = create_cmd_template.format(
            self.resource_group_name, self.workspace_name, TEST_VALID_DETECTIONS_FOLDER)
        self.cmd(create_cmd)

        folder_deployed_detections = self._list_sentinel_detections()
        folder_deployed_detections_ids = [detection['name'] for detection in folder_deployed_detections]
        local_detection_ids = [detection['id'] for detection in self.test_folder_detections]
        self.assertEqual(folder_deployed_detections_ids, local_detection_ids)

    def test_sentinel_detection_validate(self):
        validate_cmd_template = 'az sentinel detection validate -d {}'
        try:
            self.cmd(validate_cmd_template.format(TEST_VALID_DETECTIONS_FOLDER))
        except CLIError:
            raise AssertionError('Validation failed unexpectedly')
        with self.assertRaises(CLIError) as v:
            self.cmd(validate_cmd_template.format(TEST_INVALID_DETECTIONS_FOLDER))
        self.assertEqual(True, True)

    def test_sentinel_detection_generate(self):
        generate_cmd_template = 'az sentinel detection generate -n {} -d {} --skip-interactive'
        detection_name = create_random_name()
        with tempfile.TemporaryDirectory() as generated_detections_folder:
            self.cmd(generate_cmd_template.format(detection_name, generated_detections_folder))
            detection_file = Path(generated_detections_folder) / detection_name / (detection_name + '.yaml')
            detection_documentation = Path(generated_detections_folder) / detection_name / (detection_name + '.md')
            generated_detection = yaml.safe_load(detection_file.read_text())
            self.assertEquals(generated_detection['display_name'], detection_name)
            self.assertTrue(detection_documentation.exists())

    def _get_sentinel_detection(self, detection_id):
        get_cmd_template = 'az sentinel detection show -g {} -n {} --rule-id {}'
        get_cmd = get_cmd_template.format(self.resource_group_name, self.workspace_name, detection_id)
        return self.cmd(get_cmd).get_output_in_json()

    def _delete_sentinel_detection(self, detection_id):
        delete_cmd_template = 'az sentinel detection delete -g {} -n {} --rule-id {}'
        delete_cmd = delete_cmd_template.format(self.resource_group_name, self.workspace_name, detection_id)
        self.cmd(delete_cmd)

    def _list_sentinel_detections(self):
        list_cmd_template = 'az sentinel detection list -g {} -n {}'
        list_cmd = list_cmd_template.format(self.resource_group_name, self.workspace_name)
        return self.cmd(list_cmd).get_output_in_json()
