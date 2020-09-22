# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
import os
import tempfile
from pathlib import Path

import yaml
from azure.cli.testsdk import ScenarioTest, create_random_name
from knack.util import CLIError

from azext_sentinel.constants import DISPLAY_NAME_KEY

ID_KEY = "id"
NAME_KEY = "name"
VALUE_KEY = "value"

TEST_RESOURCE_GROUP_PREFIX = "test_sentinel_rg_"
DEFAULT_RESOURCE_PROVIDER = "Microsoft.OperationalInsights"

TEST_ROOT_PATH = os.path.dirname(os.path.abspath(__file__))
TEST_WORKSPACE_TEMPLATE = os.path.join(TEST_ROOT_PATH, "deploylaworkspacetemplate.json")
TEST_VALID_DETECTIONS_FOLDER = os.path.join(
    TEST_ROOT_PATH, "test_detections/valid_detections"
)
TEST_INVALID_DETECTIONS_FOLDER = os.path.join(
    TEST_ROOT_PATH, "test_detections/invalid_detections"
)
TEST_INDIVIDUAL_DETECTION_FILE = os.path.join(
    TEST_ROOT_PATH, "test_detections/test_individual_detection.yaml"
)
TEST_LOCATION = "eastus"

# See test_sentinel.yaml for details
# TODO: Load recorded constants from the recorded files
RECORDED_RESOURCE_GROUP = "test_sentinel_rg_3mspwrr"
RECORDED_WORKSPACE_NAME = "clitest5cqnfjbargfgdwlue"

# Azure cli command templates
CREATE_RESOURCE_GROUP_TEMPLATE = "az group create --location {} --name {}"
CREATE_WORKSPACE_TEMPLATE = "az deployment group create -g {} --name LAWorkspace --template-file {} --parameters workspaceName={}"
DELETE_RESOURCE_GROUP_TEMPLATE = "az group delete --name {} --yes --no-wait"
DELETE_WORKSPACE_TEMPLATE = "az deployment group delete -g {} --name {} --no-wait"

# Sentinel extension detection command templates
CREATE_CMD_TEMPLATE_FROM_FILE = "az sentinel detection create -g {} -n {} -f {}"
CREATE_CMD_TEMPLATE_FROM_DIR = "az sentinel detection create -g {} -n {} -d {}"
GENERATE_CMD_TEMPLATE = "az sentinel detection generate -n {} -d {} --skip-interactive"
VALIDATE_CMD_TEMPLATE = "az sentinel detection validate -d {}"
SHOW_CMD_TEMPLATE = "az sentinel detection show -g {} -n {} --rule-id {} --operational-insights-resource-provider {}"
DELETE_CMD_TEMPLATE = "az sentinel detection delete -g {} -n {} --operational-insights-resource-provider {} --rule-id {}"
LIST_CMD_TEMPLATE = (
    "az sentinel detection list -g {} -n {} --operational-insights-resource-provider {}"
)


class SentinelScenarioTest(ScenarioTest):
    def setUp(self):
        self.test_individual_detection = yaml.safe_load(
            Path(TEST_INDIVIDUAL_DETECTION_FILE).read_text()
        )
        self.test_folder_detections = [
            yaml.safe_load(file.read_text())
            for file in Path(TEST_VALID_DETECTIONS_FOLDER).glob("**/*.yaml")
        ]
        self.resource_provider = DEFAULT_RESOURCE_PROVIDER
        if self.in_recording:
            self.resource_group_name = create_random_name(TEST_RESOURCE_GROUP_PREFIX)
            self.workspace_name = create_random_name()

            self.cmd(
                CREATE_RESOURCE_GROUP_TEMPLATE.format(
                    TEST_LOCATION, self.resource_group_name
                )
            )
            self.cmd(
                CREATE_WORKSPACE_TEMPLATE.format(
                    self.resource_group_name,
                    str(TEST_WORKSPACE_TEMPLATE),
                    self.workspace_name,
                )
            )
        else:
            self.resource_group_name = RECORDED_RESOURCE_GROUP
            self.workspace_name = RECORDED_WORKSPACE_NAME
        super(ScenarioTest, self).setUp()

    def tearDown(self):
        if self.in_recording:
            self.cmd(
                DELETE_WORKSPACE_TEMPLATE.format(
                    self.resource_group_name, self.workspace_name
                )
            )
            self.cmd(DELETE_RESOURCE_GROUP_TEMPLATE.format(self.resource_group_name))

    def test_sentinel_detection_create(self):
        # Create test detection
        create_cmd = CREATE_CMD_TEMPLATE_FROM_FILE.format(
            self.resource_group_name,
            self.workspace_name,
            TEST_INDIVIDUAL_DETECTION_FILE,
        )
        self.cmd(create_cmd)

        # Test if the deployed detection is the same as the local detection to see if create worked as expected
        file_deployed_detection = self._get_sentinel_detection(
            self.test_individual_detection[ID_KEY]
        )
        self.assertEqual(
            file_deployed_detection[NAME_KEY], self.test_individual_detection[ID_KEY]
        )

        # Cleanup created detection
        self._delete_sentinel_detection(self.test_individual_detection[ID_KEY])

        # Test detection creation from folder
        create_cmd = CREATE_CMD_TEMPLATE_FROM_DIR.format(
            self.resource_group_name, self.workspace_name, TEST_VALID_DETECTIONS_FOLDER
        )
        self.cmd(create_cmd)

        folder_deployed_detections = self._list_sentinel_detections()
        deployed_detection_values = folder_deployed_detections[VALUE_KEY]
        folder_deployed_detections_ids = [
            detection[NAME_KEY] for detection in deployed_detection_values
        ]
        local_detection_ids = [
            detection[ID_KEY] for detection in self.test_folder_detections
        ]
        self.assertEqual(folder_deployed_detections_ids, local_detection_ids)

    def test_sentinel_detection_validate(self):
        try:
            self.cmd(VALIDATE_CMD_TEMPLATE.format(TEST_VALID_DETECTIONS_FOLDER))
        except CLIError:
            raise AssertionError("Validation failed unexpectedly")
        with self.assertRaises(CLIError):
            self.cmd(VALIDATE_CMD_TEMPLATE.format(TEST_INVALID_DETECTIONS_FOLDER))
        self.assertEqual(True, True)

    def test_sentinel_detection_generate(self):
        detection_name = create_random_name()
        with tempfile.TemporaryDirectory() as generated_detections_folder:
            self.cmd(
                GENERATE_CMD_TEMPLATE.format(
                    detection_name, generated_detections_folder
                )
            )
            detection_file = (
                Path(generated_detections_folder) / detection_name / (detection_name + ".yaml")
            )
            detection_documentation = (
                Path(generated_detections_folder) / detection_name / (detection_name + ".md")
            )
            generated_detection = yaml.safe_load(detection_file.read_text())
            self.assertEquals(generated_detection[DISPLAY_NAME_KEY], detection_name)
            self.assertTrue(detection_documentation.exists())

    def _get_sentinel_detection(self, detection_id):
        get_cmd = SHOW_CMD_TEMPLATE.format(
            self.resource_group_name,
            self.workspace_name,
            detection_id,
            self.resource_provider,
        )
        return self.cmd(get_cmd).get_output_in_json()

    def _delete_sentinel_detection(self, detection_id):
        delete_cmd = DELETE_CMD_TEMPLATE.format(
            self.resource_group_name,
            self.workspace_name,
            self.resource_provider,
            detection_id,
        )
        self.cmd(delete_cmd)

    def _list_sentinel_detections(self):
        list_cmd = LIST_CMD_TEMPLATE.format(
            self.resource_group_name, self.workspace_name, self.resource_provider
        )
        return self.cmd(list_cmd).get_output_in_json()
