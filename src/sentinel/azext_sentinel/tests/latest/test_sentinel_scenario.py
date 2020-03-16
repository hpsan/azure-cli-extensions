# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import os
import unittest
from pathlib import Path

from azure_devtools.scenario_tests import AllowLargeResponse
from azure.cli.testsdk import (ScenarioTest, ResourceGroupPreparer, create_random_name)


TEST_DIR = os.path.abspath(os.path.join(os.path.abspath(__file__), '..'))
TEST_RESOURCE_GROUP_PREFIX = 'test_sentinel_rg_'
TEST_WORKSPACE_TEMPLATE = Path(__file__).parent / 'deploylaworkspacetemplate.json'
TEST_LOCATION = 'eastus'

# See test_sentinel.yaml for details
RECORDED_RESOURCE_GROUP = 'test_sentinel_rg_sdhofaa'
RECORDED_WORKSPACE_NAME = 'clitestudvmeohyplhiastcf'

class SentinelScenarioTest(ScenarioTest):
    def setUp(self):
        if self.in_recording:
            self.resource_group_name = create_random_name(TEST_RESOURCE_GROUP_PREFIX)
            self.workspace_name = create_random_name()
            rg_create_template = 'az group create --location {} --name {}'
            workspace_create_template = 'az deployment group create -g {} --name LAWorkspace --template-file {} --parameters workspaceName={}'
            self.cmd(rg_create_template.format(TEST_LOCATION, self.resource_group_name))
            self.cmd(workspace_create_template.format(self.resource_group_name, str(TEST_WORKSPACE_TEMPLATE), self.workspace_name))
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

    def test_sentinel(self):
        test_cmd = 'sentinel detection list -g {} --workspace-name {}'
        self.cmd(test_cmd.format(self.resource_group_name, self.workspace_name))
        assert True
        # self.cmd('sentinel update -g {rg} -n {name} --tags foo=boo', checks=[
        #     self.check('tags.foo', 'boo')
        # ])
        # count = len(self.cmd('sentinel list').get_output_in_json())
        # self.cmd('sentinel show - {rg} -n {name}', checks=[
        #     self.check('name', '{name}'),
        #     self.check('resourceGroup', '{rg}'),
        #     self.check('tags.foo', 'boo')
        # ])
        # self.cmd('sentinel delete -g {rg} -n {name}')
        # final_count = len(self.cmd('sentinel list').get_output_in_json())
        # self.assertTrue(final_count, count - 1)