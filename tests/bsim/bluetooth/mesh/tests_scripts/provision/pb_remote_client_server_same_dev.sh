#!/usr/bin/env bash
# Copyright 2023 Nordic Semiconductor
# SPDX-License-Identifier: Apache-2.0

source $(dirname "${BASH_SOURCE[0]}")/../../_mesh_test.sh

# Test a node re-provisioning through Remote Provisioning models. Procedure:
# 1. Device (prov_device_pb_remote_client_server_same_dev) provisions it self
#    and start scanning for an upprovisioned device, and provisions the
#    second device (prov_device_pb_remote_server_same_dev) with local RPR server.
# 2. The first device (prov_device_pb_remote_client_server_same_dev) execute
#    device key refresh procedure the second device (prov_device_pb_remote_server_same_dev).
# 3. The first device (prov_device_pb_remote_client_server_same_dev) execute
#    address refresh procedure the second device (prov_device_pb_remote_server_same_dev).
# 4. The first device (prov_device_pb_remote_client_server_same_dev) execute
#    device key refresh procedure on it self with local RPR client and server.
# 5. The first device (prov_device_pb_remote_client_server_same_dev) execute
#    address refresh procedure on it self with local RPR client and server.
#
# Composition refresh requires BT_SETTINGS in order to set different CDP data
# allowing it to run, and is tested in pb_remote_pst_ncrp.

RunTest mesh_prov_pb_remote_client_server_same_dev \
	prov_device_pb_remote_client_server_same_dev \
	prov_device_pb_remote_server_same_dev

overlay=overlay_psa_conf
RunTest mesh_prov_pb_remote_client_server_same_dev \
	prov_device_pb_remote_client_server_same_dev \
	prov_device_pb_remote_server_same_dev
