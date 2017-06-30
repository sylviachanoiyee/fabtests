/*
 * Copyright (c) 2013-2017 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <rdma/fabric.h>
#include <rdma/fi_errno.h>
#include <rdma/fi_tagged.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>

#include "shared.h"

#define USE_SEND 0
#define USE_SENDMSG 1
#define NO_COMP 0
#define GET_COMP 1

static struct fid_ep *lcl_ep;
static fi_addr_t remote_addr;

static int send_msg(int use_sendmsg, int expect_completion, uint64_t flags)
{
	int ret;
	struct fi_msg msg;
	struct fi_context fi_ctx_send;
	struct fi_cq_msg_entry  send_completion;

	ft_sync();

	ft_fill_buf(tx_buf, opts.transfer_size);

	if (use_sendmsg) {
		struct iovec msg_iov;
		msg_iov.iov_base = tx_buf;
		msg_iov.iov_len = opts.transfer_size;

		msg.msg_iov = &msg_iov;
		msg.desc = NULL;
		msg.iov_count = 1;
		msg.addr = remote_addr;
		msg.data = 0;
		msg.context = &fi_ctx_send;

		ret = fi_sendmsg(lcl_ep, &msg, flags);

		if (ret) {
			FT_PRINTERR("fi_sendmsg", ret);
			return ret;
		}
	} else {
		ret = fi_send(lcl_ep, tx_buf, opts.transfer_size, NULL,
				remote_addr, &fi_ctx_send);
		if (ret) {
			FT_PRINTERR("fi_send", ret);
			return ret;
		}
	}

	ret = fi_cq_sread(txcq, &send_completion, 1, NULL,
				expect_completion ? 10000 : 2000);
	if ((ret <= 0) && (ret != -FI_EAGAIN)) {
		FT_PRINTERR("fi_cq_read", ret);
		return ret;
	}

	if (ret > 0) {
		if (!expect_completion) {
			FT_PRINTERR("ERROR: No completion is expected but \
					completion event found", -FI_EOTHER);
			return -FI_EOTHER;
		}
		if (&fi_ctx_send != send_completion.op_context) {
			FT_PRINTERR("ERROR: send ctx != cq_ctx", -FI_EOTHER);
			return -FI_EOTHER;
		}
	} else {
		if (expect_completion) {
			FT_PRINTERR("ERROR: No completion event found",
					-FI_EOTHER);
			return -FI_EOTHER;
		}
	}

	fprintf(stdout, "GOOD: Test success\n");

	return 0;
}

static int receive_msg()
{
	int ret;
	struct fi_context fi_ctx_recv;
	struct fi_cq_msg_entry  recv_completion;

	ret = fi_recv(lcl_ep, rx_buf, opts.transfer_size, NULL,
			FI_ADDR_UNSPEC, &fi_ctx_recv);
	if (ret) {
		FT_PRINTERR("fi_send", ret);
		return ret;
	}

	ft_sync();

	ret = fi_cq_sread(rxcq, &recv_completion, 1, NULL, 10000);
	if ((ret <= 0) && (ret != -FI_EAGAIN)) {
		FT_PRINTERR("fi_cq_read", ret);
		return ret;
	}

	if (ret > 0) {
		if (recv_completion.op_context == NULL) {
			FT_PRINTERR("ERROR: op_context is NULL", -FI_EOTHER);
			return -FI_EOTHER;
		}

		if (!(recv_completion.flags & FI_RECV)) {
			fprintf(stdout, "Flags %lx\n", (unsigned long)recv_completion.flags);
			FT_PRINTERR("wrong completion flag set for the recv \
					message", -FI_EOTHER);
			return -FI_EOTHER;
		}
	} else{
		FT_PRINTERR("ERROR: No completion event found", -FI_EOTHER);
		return -FI_EOTHER;
	}

	ret = ft_check_buf(rx_buf, opts.transfer_size);
	if(ret)
		return ret;

	fprintf(stdout, "GOOD: Test success\n");

	return 0;
}

static int run_test(uint64_t sendflag, int use_sendmsg, int expect_completion)
{
	int ret = 0;

	if (opts.dst_addr) {
		if (ret) {
			FT_PRINTERR("fi_ep_bind", ret);
			return ret;
		}
		ret = send_msg(use_sendmsg, expect_completion, sendflag);
		if (ret)
			return ret;
	} else {
		ret = receive_msg();
		if (ret)
			return ret;
	}

	return 0;
}

static int alloc_res()
{
	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	return 0;
}

static int exit_test(int ret)
{
	FT_CLOSE_FID(lcl_ep);
	ft_free_res();
	return ft_exit_code(ret);

}

static int setup_av_ep(struct fid_ep **ep, fi_addr_t *remote_addr,
			uint64_t epflags)
{
	int ret;
	hints->src_addr = NULL;

	fi_freeinfo(fi);

	ret = fi_getinfo(FT_FIVERSION, NULL, NULL, 0, hints, &fi);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}

	ret = fi_endpoint(domain, fi, ep, NULL);
	if (ret) {
		FT_PRINTERR("fi_endpoint", ret);
		return ret;
	}

	FT_EP_BIND(*ep, av, 0);
	FT_EP_BIND(*ep, txcq, epflags);
	FT_EP_BIND(*ep, rxcq, FI_RECV);

	ret = fi_enable(*ep);
	if (ret) {
		FT_PRINTERR("fi_enable", ret);
		return ret;
	}

	ret = ft_init_av_addr(av, *ep, remote_addr);
	if (ret)
		return ret;

	return 0;
}

int main(int argc, char **argv)
{
	int op, ret;
	uint64_t completion_flag;

	opts = INIT_OPTS;
	opts.options |= FT_OPT_SIZE;
	opts.transfer_size = 1024*1024;

	ret = alloc_res();
	if (ret)
		return ft_exit_code(ret);

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps = FI_MSG;
	hints->mode = FI_CONTEXT;
	hints->tx_attr->op_flags = 0;
	cq_attr.format = FI_CQ_FORMAT_MSG;
	completion_flag = 0;

	while ((op = getopt(argc, argv, "ch" ADDR_OPTS INFO_OPTS)) != -1) {
		switch (op) {
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints);
			break;
		case 'c':
			hints->tx_attr->op_flags = FI_COMPLETION;
			completion_flag = FI_SELECTIVE_COMPLETION;
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "A simple cq completion check example.");
			FT_PRINT_OPTS_USAGE("-c", "Run test with \
					hints->tx_attr->op_flags=FI_COMPLETION");
			return ft_exit_code(EXIT_FAILURE);
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	ret = ft_init_fabric();
	if (ret)
		return ft_exit_code(ret);

	ret = setup_av_ep(&lcl_ep, &remote_addr, FI_TRANSMIT | completion_flag);
	if (ret)
		return ft_exit_code(ret);

	if (!completion_flag)
		fprintf(stdout, "Testing for op flag=0, ep flag=FI_TRANSMIT\n");
	else
		fprintf(stdout, "Testing for op flag=FI_COMPLETION, \
			ep flag=FI_TRANSMIT | FI_SELECTIVE_COMPLETION\n");

	ret = run_test(0, USE_SEND, GET_COMP);
	if (ret)
		return exit_test(ret);

	ret = run_test(FI_COMPLETION, USE_SENDMSG, GET_COMP);
	if (ret)
		return exit_test(ret);

	ret = run_test(0, USE_SENDMSG, completion_flag? NO_COMP : GET_COMP);
	if (ret)
		return exit_test(ret);

	return exit_test(0);
}
