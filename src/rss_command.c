/*
 * rss_command.c — pure bulk-transfer RSS/ECMP source-port predictor
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 *
 * This command performs arithmetic only.  It opens no socket, invokes no
 * external program, and never claims that a cyclic-RETA prediction is a NIC
 * observation.
 */
#define _POSIX_C_SOURCE 200809L

#include "rss_command.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "multipath.h"
#include "process_hygiene.h"
#include "rss.h"

#define RSS_PLAN_RETA_MAX 4096U

typedef struct {
    uint8_t key[D33_RSS_KEY_BYTES_MAX];
    size_t key_length;
    unsigned int queues;
    unsigned int paths;
    unsigned int reta;
    unsigned int directions;
    uint16_t port_mask;
    uint16_t ports[MULTIPATH_PATHS_MAX];
    uint16_t base_port;
    uint16_t server_port;
    uint8_t src_ip[4];
    uint8_t dst_ip[4];
    uint8_t key_seen;
    uint8_t queues_seen;
    uint8_t paths_seen;
    uint8_t reta_seen;
    uint8_t direction_seen;
    uint8_t mask_seen;
    uint8_t ports_seen;
    uint8_t base_seen;
    uint8_t src_seen;
    uint8_t dst_seen;
    uint8_t server_seen;
    const char *ports_text;
} rss_plan_config_t;

static int power_of_two(unsigned int value)
{
    return value != 0U && (value & (value - 1U)) == 0U;
}

static int hex_nibble(unsigned char c)
{
    if (c >= (unsigned char)'0' && c <= (unsigned char)'9')
        return (int)(c - (unsigned char)'0');
    if (c >= (unsigned char)'a' && c <= (unsigned char)'f')
        return (int)(c - (unsigned char)'a') + 10;
    if (c >= (unsigned char)'A' && c <= (unsigned char)'F')
        return (int)(c - (unsigned char)'A') + 10;
    return -1;
}

static int parse_hex_key(const char *text, uint8_t *key,
                         size_t *length_out)
{
    size_t length;
    size_t i;

    if (!text || !key || !length_out)
        return -1;
    length = strlen(text);
    if ((length & 1U) != 0U || length < 32U ||
        length > 2U * D33_RSS_KEY_BYTES_MAX)
        return -1;
    for (i = 0U; i < length / 2U; i++) {
        int high = hex_nibble((unsigned char)text[2U * i]);
        int low = hex_nibble((unsigned char)text[2U * i + 1U]);

        if (high < 0 || low < 0)
            return -1;
        key[i] = (uint8_t)(((unsigned int)high << 4) |
                           (unsigned int)low);
    }
    *length_out = length / 2U;
    return 0;
}

static int parse_uint(const char *text, unsigned int maximum,
                      unsigned int *value_out)
{
    char *end = NULL;
    unsigned long value;

    if (!text || text[0] == '\0' || !value_out || text[0] == '+' ||
        text[0] == '-' || text[0] == ' ' || text[0] == '\t')
        return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || !end || *end != '\0' || value == 0UL ||
        value > maximum)
        return -1;
    *value_out = (unsigned int)value;
    return 0;
}

static int parse_mask(const char *text, uint16_t *mask_out)
{
    uint16_t value = 0U;
    size_t digits;
    size_t i;

    if (!text || !mask_out || text[0] != '0' || text[1] != 'x')
        return -1;
    digits = strlen(text + 2U);
    if (digits == 0U || digits > 4U)
        return -1;
    for (i = 0U; i < digits; i++) {
        int nibble = hex_nibble((unsigned char)text[i + 2U]);

        if (nibble < 0)
            return -1;
        value = (uint16_t)((uint16_t)(value << 4) |
                           (uint16_t)(unsigned int)nibble);
    }
    if (value == 0U || (value & (uint16_t)~D33_PORT_CUBE_BITS) != 0U)
        return -1;
    *mask_out = value;
    return 0;
}

static int parse_ports(const char *text, uint16_t *ports,
                       unsigned int expected)
{
    const char *cursor = text;
    unsigned int count = 0U;

    if (!text || !ports || expected == 0U || text[0] == '\0')
        return -1;
    while (*cursor != '\0') {
        const char *end = cursor;
        char item[6];
        size_t length;
        unsigned int port;
        unsigned int earlier;

        while (*end != '\0' && *end != ',')
            end++;
        length = (size_t)(end - cursor);
        if (count >= expected || length == 0U || length >= sizeof(item))
            return -1;
        memcpy(item, cursor, length);
        item[length] = '\0';
        if (parse_uint(item, UINT16_MAX, &port) != 0)
            return -1;
        for (earlier = 0U; earlier < count; earlier++)
            if (ports[earlier] == (uint16_t)port)
                return -1;
        ports[count++] = (uint16_t)port;
        if (*end == '\0')
            break;
        cursor = end + 1;
        if (*cursor == '\0')
            return -1;
    }
    return count == expected ? 0 : -1;
}

static int parse_direction(const char *text, unsigned int *directions_out)
{
    if (!text || !directions_out)
        return -1;
    if (strcmp(text, "c2s") == 0)
        *directions_out = D33_RSS_DIRECTION_C2S;
    else if (strcmp(text, "s2c") == 0)
        *directions_out = D33_RSS_DIRECTION_S2C;
    else if (strcmp(text, "both") == 0)
        *directions_out = D33_RSS_DIRECTION_C2S |
                          D33_RSS_DIRECTION_S2C;
    else
        return -1;
    return 0;
}

static unsigned int coverage(const unsigned int *histogram,
                             unsigned int queues)
{
    unsigned int count = 0U;
    unsigned int queue;

    for (queue = 0U; queue < queues; queue++)
        if (histogram[queue] != 0U)
            count++;
    return count;
}

static int build_ports(const rss_plan_config_t *config,
                       uint16_t ports[MULTIPATH_PATHS_MAX])
{
    unsigned int leg;

    if (config->ports_seen) {
        memcpy(ports, config->ports, sizeof(config->ports));
        return 0;
    }
    if (!config->mask_seen || !config->base_seen)
        return -1;
    for (leg = 0U; leg < config->paths; leg++)
        if (d33_cube_port(config->base_port, (uint8_t)config->paths,
                          config->port_mask, (uint8_t)leg,
                          &ports[leg]) != 0)
            return -1;
    return 0;
}

static int predict_histogram(const rss_plan_config_t *config,
                             d33_rss_direction_t direction,
                             const uint16_t ports[MULTIPATH_PATHS_MAX],
                             unsigned int histogram[D33_RSS_QUEUES_MAX],
                             unsigned int assignments[MULTIPATH_PATHS_MAX])
{
    static const uint8_t zero_ip[4] = { 0U, 0U, 0U, 0U };
    const uint8_t *client_ip = config->src_seen ? config->src_ip : zero_ip;
    const uint8_t *server_ip = config->dst_seen ? config->dst_ip : zero_ip;
    uint16_t server_port = config->server_seen ? config->server_port : 1U;
    unsigned int leg;

    memset(histogram, 0, sizeof(unsigned int) * D33_RSS_QUEUES_MAX);
    for (leg = 0U; leg < config->paths; leg++) {
        uint32_t hash = 0U;
        unsigned int queue = 0U;
        int rc;

        if (direction == D33_RSS_DIRECTION_C2S)
            rc = d33_rss_ipv4_queue(
                config->key, config->key_length, client_ip, server_ip,
                ports[leg], server_port, config->reta, config->queues,
                &hash, &queue);
        else
            rc = d33_rss_ipv4_queue(
                config->key, config->key_length, server_ip, client_ip,
                server_port, ports[leg], config->reta, config->queues,
                &hash, &queue);
        if (rc != 0 || queue >= config->queues)
            return -1;
        histogram[queue]++;
        if (assignments)
            assignments[leg] = queue;
    }
    return 0;
}

static void print_histogram(const char *name, const unsigned int *histogram,
                            unsigned int queues, int exact_tuple)
{
    unsigned int queue;

    printf("%s coverage=%u/%u histogram=", name,
           coverage(histogram, queues), queues);
    for (queue = 0U; queue < queues; queue++)
        printf("%s%u", queue == 0U ? "" : ",", histogram[queue]);
    printf(" queue-labels=%s\n", exact_tuple ? "tuple-exact" : "relative");
}

static void print_assignments(
    const char *name, const uint16_t ports[MULTIPATH_PATHS_MAX],
    const unsigned int assignments[MULTIPATH_PATHS_MAX], unsigned int paths)
{
    unsigned int leg;

    printf("%s assignments=", name);
    for (leg = 0U; leg < paths; leg++)
        printf("%s%u:%u", leg == 0U ? "" : ",",
               (unsigned int)ports[leg], assignments[leg]);
    putchar('\n');
}

static int report_mask(const rss_plan_config_t *config, uint16_t mask)
{
    unsigned int c2s = 0U;
    unsigned int s2c = 0U;

    if ((config->directions & D33_RSS_DIRECTION_C2S) != 0U &&
        d33_rss_mask_rank(config->key, config->key_length, mask,
                          config->queues, D33_RSS_DIRECTION_C2S,
                          &c2s) != 0)
        return -1;
    if ((config->directions & D33_RSS_DIRECTION_S2C) != 0U &&
        d33_rss_mask_rank(config->key, config->key_length, mask,
                          config->queues, D33_RSS_DIRECTION_S2C,
                          &s2c) != 0)
        return -1;
    printf("mask=0x%04x", (unsigned int)mask);
    if ((config->directions & D33_RSS_DIRECTION_C2S) != 0U)
        printf(" rank-c2s=%u coverage-c2s=%u", c2s, 1U << c2s);
    if ((config->directions & D33_RSS_DIRECTION_S2C) != 0U)
        printf(" rank-s2c=%u coverage-s2c=%u", s2c, 1U << s2c);
    putchar('\n');
    return 0;
}

static unsigned int path_log2(unsigned int paths)
{
    unsigned int result = 0U;

    while (paths > 1U) {
        paths >>= 1;
        result++;
    }
    return result;
}

static int search_masks(const rss_plan_config_t *config)
{
    unsigned int candidate;
    unsigned int found = 0U;
    unsigned int required_rank = path_log2(config->paths);

    for (candidate = 1U; candidate <= D33_PORT_CUBE_BITS; candidate++) {
        unsigned int c2s = required_rank;
        unsigned int s2c = required_rank;
        int full;

        if (!d33_cube_mask_valid((uint8_t)config->paths,
                                 (uint16_t)candidate))
            continue;
        if ((config->directions & D33_RSS_DIRECTION_C2S) != 0U &&
            d33_rss_mask_rank(config->key, config->key_length,
                              (uint16_t)candidate, config->queues,
                              D33_RSS_DIRECTION_C2S, &c2s) != 0)
            return -1;
        if ((config->directions & D33_RSS_DIRECTION_S2C) != 0U &&
            d33_rss_mask_rank(config->key, config->key_length,
                              (uint16_t)candidate, config->queues,
                              D33_RSS_DIRECTION_S2C, &s2c) != 0)
            return -1;
        full = c2s == required_rank && s2c == required_rank;
        if (full) {
            if (report_mask(config, (uint16_t)candidate) != 0)
                return -1;
            found++;
        }
    }
    printf("full-rank-masks=%u searched-low14=yes\n", found);
    return found == 0U ? 2 : 0;
}

static void rss_usage(void)
{
    fprintf(stderr,
        "usage: unmoor rss-plan --rss-key HEX --queues N --paths 2|4|8|16|32\n"
        "       [--reta N] [--direction c2s|s2c|both]\n"
        "       [--port-mask 0xNNNN [--base-port P] | --ports P0,P1,...]\n"
        "       [--src-ip A --dst-ip B --server-port P]\n");
}

int rss_plan_command(int argc, char *argv[])
{
    rss_plan_config_t config;
    uint16_t selected_ports[MULTIPATH_PATHS_MAX];
    unsigned int histogram[D33_RSS_QUEUES_MAX];
    unsigned int assignments[MULTIPATH_PATHS_MAX];
    int tuple_any;
    int tuple_complete;
    int debuggable = 0;
    int i;

    memset(&config, 0, sizeof(config));
    memset(selected_ports, 0, sizeof(selected_ports));
    config.reta = D33_RSS_RETA_DEFAULT;
    config.directions = D33_RSS_DIRECTION_C2S |
                        D33_RSS_DIRECTION_S2C;
    for (i = 0; i < argc; i++) {
        if (strcmp(argv[i], "--debuggable") == 0) {
            if (debuggable)
                goto invalid;
            debuggable = 1;
        } else if (strcmp(argv[i], "--rss-key") == 0 && i + 1 < argc) {
            if (config.key_seen ||
                parse_hex_key(argv[++i], config.key,
                              &config.key_length) != 0)
                goto invalid;
            config.key_seen = 1U;
        } else if (strcmp(argv[i], "--queues") == 0 && i + 1 < argc) {
            if (config.queues_seen ||
                parse_uint(argv[++i], D33_RSS_QUEUES_MAX,
                           &config.queues) != 0)
                goto invalid;
            config.queues_seen = 1U;
        } else if (strcmp(argv[i], "--paths") == 0 && i + 1 < argc) {
            if (config.paths_seen ||
                parse_uint(argv[++i], MULTIPATH_PATHS_MAX,
                           &config.paths) != 0)
                goto invalid;
            config.paths_seen = 1U;
        } else if (strcmp(argv[i], "--reta") == 0 && i + 1 < argc) {
            if (config.reta_seen ||
                parse_uint(argv[++i], RSS_PLAN_RETA_MAX,
                           &config.reta) != 0)
                goto invalid;
            config.reta_seen = 1U;
        } else if (strcmp(argv[i], "--direction") == 0 && i + 1 < argc) {
            if (config.direction_seen ||
                parse_direction(argv[++i], &config.directions) != 0)
                goto invalid;
            config.direction_seen = 1U;
        } else if (strcmp(argv[i], "--port-mask") == 0 && i + 1 < argc) {
            if (config.mask_seen ||
                parse_mask(argv[++i], &config.port_mask) != 0)
                goto invalid;
            config.mask_seen = 1U;
        } else if (strcmp(argv[i], "--ports") == 0 && i + 1 < argc) {
            if (config.ports_seen)
                goto invalid;
            config.ports_text = argv[++i];
            config.ports_seen = 1U;
        } else if (strcmp(argv[i], "--base-port") == 0 && i + 1 < argc) {
            unsigned int value;
            if (config.base_seen ||
                parse_uint(argv[++i], UINT16_MAX, &value) != 0)
                goto invalid;
            config.base_port = (uint16_t)value;
            config.base_seen = 1U;
        } else if (strcmp(argv[i], "--src-ip") == 0 && i + 1 < argc) {
            if (config.src_seen ||
                inet_pton(AF_INET, argv[++i], config.src_ip) != 1)
                goto invalid;
            config.src_seen = 1U;
        } else if (strcmp(argv[i], "--dst-ip") == 0 && i + 1 < argc) {
            if (config.dst_seen ||
                inet_pton(AF_INET, argv[++i], config.dst_ip) != 1)
                goto invalid;
            config.dst_seen = 1U;
        } else if (strcmp(argv[i], "--server-port") == 0 && i + 1 < argc) {
            unsigned int value;
            if (config.server_seen ||
                parse_uint(argv[++i], UINT16_MAX, &value) != 0)
                goto invalid;
            config.server_port = (uint16_t)value;
            config.server_seen = 1U;
        } else {
            goto invalid;
        }
    }
    tuple_any = config.src_seen || config.dst_seen || config.server_seen;
    tuple_complete = config.src_seen && config.dst_seen && config.server_seen;
    if (config.ports_seen && config.paths_seen &&
        parse_ports(config.ports_text, config.ports, config.paths) != 0)
        goto invalid;
    if (!config.key_seen || !config.queues_seen || !config.paths_seen ||
        !power_of_two(config.queues) ||
        !multipath_path_count_valid(config.paths) ||
        !power_of_two(config.reta) || config.queues > config.reta ||
        (config.mask_seen && config.ports_seen) ||
        (config.base_seen && !config.mask_seen) ||
        (tuple_any && !tuple_complete) ||
        (tuple_any && !config.mask_seen && !config.ports_seen) ||
        (config.mask_seen &&
         !d33_cube_mask_valid((uint8_t)config.paths,
                              config.port_mask)) ||
        (config.mask_seen && config.base_seen &&
         d33_cube_port(config.base_port, (uint8_t)config.paths,
                       config.port_mask, 0U,
                       &selected_ports[0]) != 0))
        goto invalid;

    if (process_harden_command("rss-plan", debuggable) != 0)
        return 1;

    printf("rss-plan: queues=%u paths=%u reta=%u reta-model=cyclic direction=%s\n",
           config.queues, config.paths, config.reta,
           config.directions == D33_RSS_DIRECTION_C2S ? "c2s" :
           config.directions == D33_RSS_DIRECTION_S2C ? "s2c" : "both");
    if (!config.mask_seen && !config.ports_seen)
        return search_masks(&config);
    if (config.mask_seen && report_mask(&config, config.port_mask) != 0)
        return 1;
    if (!config.ports_seen && !config.base_seen)
        return 0;
    if (build_ports(&config, selected_ports) != 0)
        goto invalid;
    printf("ports=");
    for (i = 0; i < (int)config.paths; i++)
        printf("%s%u", i == 0 ? "" : ",",
               (unsigned int)selected_ports[i]);
    putchar('\n');
    if ((config.directions & D33_RSS_DIRECTION_C2S) != 0U) {
        if (predict_histogram(&config, D33_RSS_DIRECTION_C2S,
                              selected_ports, histogram, assignments) != 0)
            return 1;
        print_histogram("c2s", histogram, config.queues, tuple_complete);
        if (tuple_complete)
            print_assignments("c2s", selected_ports, assignments,
                              config.paths);
    }
    if ((config.directions & D33_RSS_DIRECTION_S2C) != 0U) {
        if (predict_histogram(&config, D33_RSS_DIRECTION_S2C,
                              selected_ports, histogram, assignments) != 0)
            return 1;
        print_histogram("s2c", histogram, config.queues, tuple_complete);
        if (tuple_complete)
            print_assignments("s2c", selected_ports, assignments,
                              config.paths);
    }
    return 0;

invalid:
    fprintf(stderr, "rss-plan: invalid or incomplete predictor arguments\n");
    rss_usage();
    return 1;
}
