# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

from azure.cli.core.commands.client_factory import get_mgmt_service_client
from azext_sentinel.vendored_sdks import SecurityInsights


def cf_sentinel(cli_ctx, *_):
    return get_mgmt_service_client(cli_ctx, SecurityInsights)


def cf_sentinel_alert_rules(cli_ctx, *_):
    return cf_sentinel(cli_ctx).alert_rules
