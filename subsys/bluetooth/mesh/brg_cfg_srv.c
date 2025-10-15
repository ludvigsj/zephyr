/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/bluetooth/mesh.h>
#include <zephyr/bluetooth/mesh/brg_cfg.h>
#include "access.h"
#include "brg_cfg.h"
#include "foundation.h"
#include "subnet.h"

#define LOG_LEVEL CONFIG_BT_MESH_MODEL_LOG_LEVEL
#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(bt_mesh_brg_cfg_srv);

static void bridge_status_send(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx)
{
	BT_MESH_MODEL_BUF_DEFINE(msg, OP_SUBNET_BRIDGE_STATUS, 1);

	bt_mesh_model_msg_init(&msg, OP_SUBNET_BRIDGE_STATUS);
	net_buf_simple_add_u8(&msg, bt_mesh_brg_cfg_enable_get() ? 1 : 0);

	if (bt_mesh_model_send(model, ctx, &msg, NULL, NULL)) {
		LOG_ERR("Brg Status send failed");
	}
}

static int subnet_bridge_get(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
			     struct net_buf_simple *buf)
{
	bridge_status_send(model, ctx);

	return 0;
}

static int subnet_bridge_set(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
			     struct net_buf_simple *buf)
{
	uint8_t enable = net_buf_simple_pull_u8(buf);

	if (enable > BT_MESH_BRG_CFG_ENABLED) {
		return -EINVAL;
	}

	bt_mesh_brg_cfg_enable_set(enable);
	bridge_status_send(model, ctx);

	return 0;
}

static void bridging_table_status_send(const struct bt_mesh_model *model,
				       struct bt_mesh_msg_ctx *ctx, uint8_t status,
				       struct bt_mesh_brg_cfg_table_entry *entry)
{
	BT_MESH_MODEL_BUF_DEFINE(msg, OP_BRIDGING_TABLE_STATUS, 9);

	bt_mesh_model_msg_init(&msg, OP_BRIDGING_TABLE_STATUS);
	net_buf_simple_add_u8(&msg, status);
	net_buf_simple_add_u8(&msg, entry->directions);
	net_buf_simple_add_le24(&msg, key_idx_pack_pair(entry->net_idx1, entry->net_idx2));
	net_buf_simple_add_le16(&msg, entry->addr1);
	net_buf_simple_add_le16(&msg, entry->addr2);

	if (bt_mesh_model_send(model, ctx, &msg, NULL, NULL)) {
		LOG_ERR("Brg Tbl Status send failed");
	}
}

static bool netkey_check(uint16_t net_idx1, uint16_t net_idx2)
{
	return bt_mesh_subnet_get(net_idx1) && bt_mesh_subnet_get(net_idx2);
}

static int bridging_table_add(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
			      struct net_buf_simple *buf)
{
	struct bt_mesh_brg_cfg_table_entry entry;
	uint8_t status = STATUS_SUCCESS;
	int err;

	entry.directions = net_buf_simple_pull_u8(buf);
	key_idx_unpack_pair(buf, &entry.net_idx1, &entry.net_idx2);
	entry.addr1 = net_buf_simple_pull_le16(buf);
	entry.addr2 = net_buf_simple_pull_le16(buf);

	err = bt_mesh_brg_cfg_tbl_add(entry.directions, entry.net_idx1, entry.net_idx2, entry.addr1,
				      entry.addr2, &status);
	if (err) {
		return err;
	}

	bridging_table_status_send(model, ctx, status, &entry);

	return 0;
}

static int bridging_table_remove(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
				 struct net_buf_simple *buf)
{
	struct bt_mesh_brg_cfg_table_entry entry;
	uint8_t status = STATUS_SUCCESS;
	int err;

	entry.directions = 0;
	key_idx_unpack_pair(buf, &entry.net_idx1, &entry.net_idx2);
	entry.addr1 = net_buf_simple_pull_le16(buf);
	entry.addr2 = net_buf_simple_pull_le16(buf);

	err = bt_mesh_brg_cfg_tbl_remove(entry.net_idx1, entry.net_idx2, entry.addr1, entry.addr2,
					 &status);
	if (err) {
		return err;
	}

	bridging_table_status_send(model, ctx, status, &entry);

	return 0;
}

static bool pair_already_in_msg(struct net_buf_simple *msg, uint32_t pair)
{
	struct net_buf_simple_state buf_state;
	bool result = false;
	uint32_t msg_field;

	net_buf_simple_save(msg, &buf_state);

	while (msg->len >= 3) {
		msg_field = net_buf_simple_remove_le24(msg);

		if (msg_field == pair) {
			result = true;
			break;
		}
	}

	net_buf_simple_restore(msg, &buf_state);
	return result;
}

/* Opcode + 2 bytes for filter + 1 byte for start index */
#define BRG_SUBNETS_BUF_HEADROOM (BT_MESH_MODEL_OP_LEN(OP_BRIDGED_SUBNETS_LIST) + 2 + 1)

/* Maximum potential number of entries in a bridged subnets list. */
#define BRG_SUBNETS_MAX_COUNT MIN(CONFIG_BT_MESH_BRG_TABLE_ITEMS_MAX,                              \
				  CONFIG_BT_MESH_SUBNET_COUNT * (CONFIG_BT_MESH_SUBNET_COUNT - 1))

/* The maximum size of bridged subnets list field that can fit in a single message. */
#define BRG_SUBNETS_MAX_LIST_SIZE (BT_MESH_TX_SDU_MAX - BRG_SUBNETS_BUF_HEADROOM -                 \
				   BT_MESH_MIC_SHORT)

/*
 * Buffer to store the full filtered list of subnet pairs. The message will be constructed from a
 * part of this buffer, depending on start_id, meaning we need to include headroom at the start in
 * case start_id = 0, and tailroom at the end in case we are returning the final part of the list.
 *
 * Need to construct the full filtered list in order to be able to check for duplicates - we need to
 * know whether we have seen a pair before, even if it will not be part of the final message.
 *
 * Defined here, since it needs to contain the entire filtered list and potentially be too big for
 * the stack.
 */
#define BRG_SUBNETS_BUF_SIZE (BRG_SUBNETS_BUF_HEADROOM + (BRG_SUBNETS_MAX_COUNT * 3) +             \
			      BT_MESH_MIC_SHORT)
NET_BUF_SIMPLE_DEFINE_STATIC(bridged_subnets_buf, BRG_SUBNETS_BUF_SIZE);

static int bridged_subnets_get(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
			       struct net_buf_simple *buf)
{
	struct net_buf_simple *msg = &bridged_subnets_buf;
	const struct bt_mesh_brg_cfg_row *brg_tbl;
	int rows = bt_mesh_brg_cfg_tbl_get(&brg_tbl);
	int16_t net_idx_filter = net_buf_simple_pull_le16(buf);

	if (net_idx_filter & BT_MESH_BRG_CFG_NKEY_PRHB_FLT_MASK) {
		return -EINVAL;
	}

	net_buf_simple_init(msg, BRG_SUBNETS_BUF_HEADROOM);

	struct bt_mesh_brg_cfg_filter_netkey filter_net_idx;

	filter_net_idx.filter = net_idx_filter & BIT_MASK(2);
	filter_net_idx.net_idx = (net_idx_filter >> 4) & BIT_MASK(12);

	uint8_t start_id = net_buf_simple_pull_u8(buf);

	uint16_t net_idx1, net_idx2;
	uint32_t pair;

	for (int i = 0; i < rows; i++) {
		net_idx1 = brg_tbl[i].net_idx1;
		net_idx2 = brg_tbl[i].net_idx2;
		pair = key_idx_pack_pair(net_idx1, net_idx2);

		/*
		 * Check if the message will become too long after we truncate the first `start_id`
		 * items.
		 */
		if (msg->len - (3 * start_id) + 3 > BRG_SUBNETS_MAX_LIST_SIZE ||
		    net_buf_simple_tailroom(msg) < 3 + BT_MESH_MIC_SHORT) {
			break;
		}

		if (!pair_already_in_msg(msg, pair) &&
		    (filter_net_idx.filter == 0 ||
		     (filter_net_idx.filter == 1 && net_idx1 == filter_net_idx.net_idx) ||
		     (filter_net_idx.filter == 2 && net_idx2 == filter_net_idx.net_idx) ||
		     (filter_net_idx.filter == 3 && (net_idx1 == filter_net_idx.net_idx ||
						     net_idx2 == filter_net_idx.net_idx)))) {
			net_buf_simple_add_le24(msg, pair);
		}
	}

	/*
	 * Adjust the buffer by truncating the start and pushing the needed overhead data.
	 * Doing it this way avoids having to copy from one buffer to another and avoids allocating
	 * more buffer space than needed.
	 */
	net_buf_simple_pull(msg, MIN(start_id * 3, msg->len));
	net_buf_simple_push_u8(msg, start_id);
	net_buf_simple_push_le16(msg, net_idx_filter);
	net_buf_simple_push_be16(msg, OP_BRIDGED_SUBNETS_LIST);

	if (bt_mesh_model_send(model, ctx, msg, NULL, NULL)) {
		LOG_ERR("Brg Subnet List send failed");
	}

	return 0;
}

static int bridging_table_get(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
			      struct net_buf_simple *buf)
{
	BT_MESH_MODEL_BUF_DEFINE(msg, OP_BRIDGING_TABLE_LIST,
				 BT_MESH_TX_SDU_MAX - BT_MESH_MODEL_OP_LEN(OP_BRIDGING_TABLE_LIST));
	uint8_t status = STATUS_SUCCESS;
	uint16_t net_idx1, net_idx2;

	bt_mesh_model_msg_init(&msg, OP_BRIDGING_TABLE_LIST);

	key_idx_unpack_pair(buf, &net_idx1, &net_idx2);

	uint16_t start_id = net_buf_simple_pull_le16(buf);

	if (!netkey_check(net_idx1, net_idx2)) {
		status = STATUS_INVALID_NETKEY;
	}

	net_buf_simple_add_u8(&msg, status);
	net_buf_simple_add_le24(&msg, key_idx_pack_pair(net_idx1, net_idx2));
	net_buf_simple_add_le16(&msg, start_id);

	if (status != STATUS_SUCCESS) {
		goto tbl_get_respond;
	}

	int cnt = 0;
	const struct bt_mesh_brg_cfg_row *brg_tbl;
	int rows = bt_mesh_brg_cfg_tbl_get(&brg_tbl);

	for (int i = 0; i < rows; i++) {
		if (brg_tbl[i].net_idx1 == net_idx1 && brg_tbl[i].net_idx2 == net_idx2) {
			if (cnt >= start_id) {
				if (net_buf_simple_tailroom(&msg) < 5 + BT_MESH_MIC_SHORT) {
					LOG_WRN("Bridging Table List message too large");
					break;
				}

				net_buf_simple_add_le16(&msg, brg_tbl[i].addr1);
				net_buf_simple_add_le16(&msg, brg_tbl[i].addr2);
				net_buf_simple_add_u8(&msg, brg_tbl[i].direction);
			}
			cnt++;
		}
	}

tbl_get_respond:
	if (bt_mesh_model_send(model, ctx, &msg, NULL, NULL)) {
		LOG_ERR("Brg Tbl List send failed");
	}

	return 0;
}

static int bridging_table_size_get(const struct bt_mesh_model *model, struct bt_mesh_msg_ctx *ctx,
				   struct net_buf_simple *buf)
{
	BT_MESH_MODEL_BUF_DEFINE(msg, OP_BRIDGING_TABLE_SIZE_STATUS, 2);
	bt_mesh_model_msg_init(&msg, OP_BRIDGING_TABLE_SIZE_STATUS);

	net_buf_simple_add_le16(&msg, CONFIG_BT_MESH_BRG_TABLE_ITEMS_MAX);

	if (bt_mesh_model_send(model, ctx, &msg, NULL, NULL)) {
		LOG_ERR("Brg Tbl Size Status send failed");
	}

	return 0;
}

const struct bt_mesh_model_op _bt_mesh_brg_cfg_srv_op[] = {
	{OP_SUBNET_BRIDGE_GET, BT_MESH_LEN_EXACT(0), subnet_bridge_get},
	{OP_SUBNET_BRIDGE_SET, BT_MESH_LEN_EXACT(1), subnet_bridge_set},
	{OP_BRIDGING_TABLE_ADD, BT_MESH_LEN_EXACT(8), bridging_table_add},
	{OP_BRIDGING_TABLE_REMOVE, BT_MESH_LEN_EXACT(7), bridging_table_remove},
	{OP_BRIDGED_SUBNETS_GET, BT_MESH_LEN_EXACT(3), bridged_subnets_get},
	{OP_BRIDGING_TABLE_GET, BT_MESH_LEN_EXACT(5), bridging_table_get},
	{OP_BRIDGING_TABLE_SIZE_GET, BT_MESH_LEN_EXACT(0), bridging_table_size_get},
	BT_MESH_MODEL_OP_END,
};

static int brg_cfg_srv_init(const struct bt_mesh_model *model)
{
	const struct bt_mesh_model *config_srv =
		bt_mesh_model_find(bt_mesh_model_elem(model), BT_MESH_MODEL_ID_CFG_SRV);

	if (config_srv == NULL) {
		LOG_ERR("Not on primary element");
		return -EINVAL;
	}

	/*
	 * Bridge Configuration Server model security is device key based and only the local
	 * device key is allowed to access this model.
	 */
	model->keys[0] = BT_MESH_KEY_DEV_LOCAL;
	model->rt->flags |= BT_MESH_MOD_DEVKEY_ONLY;

	bt_mesh_model_extend(model, config_srv);

	return 0;
}

void brg_cfg_srv_reset(const struct bt_mesh_model *model)
{
	bt_mesh_brg_cfg_tbl_reset();
}

const struct bt_mesh_model_cb _bt_mesh_brg_cfg_srv_cb = {
	.init = brg_cfg_srv_init,
	.reset = brg_cfg_srv_reset,
};
