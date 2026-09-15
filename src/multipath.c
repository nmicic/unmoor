/*
 * multipath.c — multipath fixed-resource endpoint-path policy
 *
 * Copyright (c) 2026 Nenad Micic
 * SPDX-License-Identifier: Apache-2.0
 */
#include "multipath.h"

#include <limits.h>
#include <string.h>

_Static_assert(sizeof(multipath_token_t) == MULTIPATH_TOKEN_BYTES,
               "multipath token layout changed");
_Static_assert(sizeof(path_leg_t) == PATH_LEG_BYTES,
               "path leg layout changed");
_Static_assert((int)MULTIPATH_PATH_EMPTY ==
                   (int)PATH_LEG_VALIDATION_EMPTY &&
               (int)MULTIPATH_PATH_CONFIGURED ==
                   (int)PATH_LEG_VALIDATION_CONFIGURED &&
               (int)MULTIPATH_PATH_PROVISIONAL ==
                   (int)PATH_LEG_VALIDATION_PROVISIONAL &&
               (int)MULTIPATH_PATH_VALIDATED ==
                   (int)PATH_LEG_VALIDATION_VALIDATED,
               "multipath and common-leg validation values diverged");
_Static_assert(sizeof(multipath_handle_t) == MULTIPATH_HANDLE_BYTES,
               "multipath handle layout changed");
_Static_assert(sizeof(multipath_plan_item_t) == MULTIPATH_PLAN_ITEM_BYTES,
               "multipath plan-item layout changed");
_Static_assert(sizeof(multipath_plan_t) == MULTIPATH_PLAN_BYTES,
               "multipath plan layout changed");
_Static_assert(sizeof(multipath_t) <= MULTIPATH_STATE_BYTES_MAX,
               "multipath state exceeds reviewed resource ceiling");
_Static_assert(sizeof(multipath_snapshot_t) <= MULTIPATH_SNAPSHOT_BYTES_MAX,
               "multipath snapshot exceeds reviewed resource ceiling");

static int bytes_zero(const uint8_t *bytes, size_t length)
{
    size_t i;

    for (i = 0; i < length; i++) {
        if (bytes[i] != 0U)
            return 0;
    }
    return 1;
}

static int ipv6_is_v4_mapped(const uint8_t address[16])
{
    static const uint8_t prefix[12] = {
        0U, 0U, 0U, 0U, 0U, 0U, 0U, 0U,
        0U, 0U, 0xffU, 0xffU
    };

    return memcmp(address, prefix, sizeof(prefix)) == 0;
}

int multipath_path_count_valid(unsigned int path_count)
{
    return path_count >= MULTIPATH_PATHS_MIN &&
           path_count <= MULTIPATH_PATHS_MAX &&
           (path_count & (path_count - 1U)) == 0U;
}

uint32_t multipath_low_mask(unsigned int path_count)
{
    if (!multipath_path_count_valid(path_count))
        return 0U;
    if (path_count == 32U)
        return UINT32_MAX;
    return (UINT32_C(1) << path_count) - UINT32_C(1);
}

int multipath_token_valid(const multipath_token_t *token)
{
    if (token == NULL || token->local_leg >= MULTIPATH_PATHS_MAX ||
        token->port == 0U || !bytes_zero(token->reserved,
                                         sizeof(token->reserved)))
        return 0;
    if (token->family == 4U)
        return token->scope == 0U &&
               bytes_zero(token->address + 4, sizeof(token->address) - 4U);
    if (token->family == 6U)
        return !ipv6_is_v4_mapped(token->address);
    return 0;
}

int multipath_token_init(multipath_token_t *token, uint8_t local_leg,
                         uint8_t family, uint16_t host_port,
                         uint32_t ipv6_scope, const uint8_t *address,
                         size_t address_length)
{
    size_t required;

    if (token == NULL)
        return MULTIPATH_ERROR;
    memset(token, 0, sizeof(*token));
    if (address == NULL || local_leg >= MULTIPATH_PATHS_MAX ||
        host_port == 0U || (family != 4U && family != 6U))
        return MULTIPATH_ERROR;
    required = family == 4U ? 4U : 16U;
    if (address_length != required || (family == 4U && ipv6_scope != 0U))
        return MULTIPATH_ERROR;
    token->local_leg = local_leg;
    token->family = family;
    token->port = host_port;
    token->scope = ipv6_scope;
    memcpy(token->address, address, required);
    if (!multipath_token_valid(token)) {
        memset(token, 0, sizeof(*token));
        return MULTIPATH_ERROR;
    }
    return 0;
}

int multipath_token_equal(const multipath_token_t *a,
                          const multipath_token_t *b)
{
    if (!multipath_token_valid(a) || !multipath_token_valid(b))
        return 0;
    return a->local_leg == b->local_leg && a->family == b->family &&
           a->port == b->port && a->scope == b->scope &&
           memcmp(a->address, b->address, sizeof(a->address)) == 0;
}

static void handle_clear(multipath_handle_t *handle)
{
    if (handle != NULL)
        memset(handle, 0, sizeof(*handle));
}

static void outputs_clear(multipath_handle_t *handle, int *primary_changed)
{
    handle_clear(handle);
    if (primary_changed != NULL)
        *primary_changed = 0;
}

static int handle_well_formed(const multipath_handle_t *handle)
{
    return handle != NULL && handle->index < MULTIPATH_PATHS_MAX &&
           handle->generation != 0U &&
           bytes_zero(handle->reserved, sizeof(handle->reserved));
}

static void handle_from_entry(const multipath_t *paths, uint8_t index,
                              multipath_handle_t *handle)
{
    if (handle == NULL)
        return;
    memset(handle, 0, sizeof(*handle));
    handle->generation = paths->entry[index].generation;
    handle->index = index;
}

static int entry_occupied(const multipath_entry_t *entry)
{
    return entry->state != MULTIPATH_PATH_EMPTY;
}

static int entry_zero(const multipath_entry_t *entry)
{
    static const multipath_entry_t zero;

    return memcmp(entry, &zero, sizeof(*entry)) == 0;
}

static int paths_valid(const multipath_t *paths)
{
    unsigned int i;
    unsigned int j;

    if (paths == NULL || !bytes_zero(paths->reserved,
                                     sizeof(paths->reserved)) ||
        !multipath_path_count_valid(paths->path_limit) ||
        paths->alternate_cursor >= paths->path_limit)
        return 0;
    if (paths->primary_index != MULTIPATH_NO_INDEX) {
        const multipath_entry_t *primary;

        if (paths->primary_index >= paths->path_limit)
            return 0;
        primary = &paths->entry[paths->primary_index];
        if (primary->state != MULTIPATH_PATH_PROVISIONAL &&
            primary->state != MULTIPATH_PATH_VALIDATED)
            return 0;
    }
    for (i = 0; i < MULTIPATH_PATHS_MAX; i++) {
        const multipath_entry_t *entry = &paths->entry[i];

        if (i >= paths->path_limit) {
            if (!entry_zero(entry))
                return 0;
            continue;
        }

        if (!entry_occupied(entry)) {
            if (!entry_zero(entry))
                return 0;
            continue;
        }
        if (entry->state > MULTIPATH_PATH_VALIDATED ||
            !multipath_token_valid(&entry->token) ||
            entry->token.local_leg >= paths->path_limit ||
            entry->generation == 0U ||
            entry->generation > paths->generation_counter ||
            entry->challenge_sent > 1U ||
            entry->challenge_maintenance > 1U)
            return 0;
        if (entry->challenge_pending) {
            if (entry->challenge_id == 0U ||
                entry->challenge_id > paths->challenge_counter)
                return 0;
        } else if (entry->challenge_id != 0U ||
                   entry->challenge_attempts != 0U ||
                   entry->challenge_due_ms != 0 ||
                   entry->challenge_sent != 0U ||
                   entry->challenge_maintenance != 0U) {
            return 0;
        }
        if (entry->response_pending) {
            if (entry->response_id == 0U)
                return 0;
        } else if (entry->response_id != 0U ||
                   entry->response_due_ms != 0) {
            return 0;
        }
        if (entry->challenge_maintenance &&
            (!entry->challenge_pending ||
             entry->state != MULTIPATH_PATH_VALIDATED))
            return 0;
        if (entry->state == MULTIPATH_PATH_VALIDATED &&
            entry->challenge_pending && !entry->challenge_maintenance)
            return 0;
        for (j = i + 1U; j < paths->path_limit; j++) {
            if (entry_occupied(entry) && entry_occupied(&paths->entry[j]) &&
                multipath_token_equal(&entry->token,
                                      &paths->entry[j].token))
                return 0;
        }
    }
    return 1;
}

static int token_fits_paths(const multipath_t *paths,
                            const multipath_token_t *token)
{
    return paths_valid(paths) && multipath_token_valid(token) &&
           token->local_leg < paths->path_limit;
}

void multipath_reset(multipath_t *paths)
{
    uint8_t path_limit;

    if (paths == NULL)
        return;
    path_limit = paths->path_limit;
    memset(paths, 0, sizeof(*paths));
    paths->primary_index = MULTIPATH_NO_INDEX;
    if (multipath_path_count_valid(path_limit))
        paths->path_limit = path_limit;
}

int multipath_init(multipath_t *paths, unsigned int path_count)
{
    if (!paths || !multipath_path_count_valid(path_count))
        return MULTIPATH_ERROR;
    memset(paths, 0, sizeof(*paths));
    paths->primary_index = MULTIPATH_NO_INDEX;
    paths->path_limit = (uint8_t)path_count;
    return 0;
}

int multipath_traffic_epoch_adopt(const multipath_t *paths)
{
    return paths_valid(paths) ? 0 : MULTIPATH_ERROR;
}

static int counter_available(uint64_t counter)
{
    return counter != UINT64_MAX;
}

static uint64_t counter_take(uint64_t *counter)
{
    *counter += 1U;
    return *counter;
}

static int counter_has_room(uint64_t counter, unsigned int count)
{
    return count <= UINT64_MAX - counter;
}

static void counter_add_saturating(uint64_t *counter, unsigned int count)
{
    if (count > UINT64_MAX - *counter)
        *counter = UINT64_MAX;
    else
        *counter += count;
}

static int find_token(const multipath_t *paths,
                      const multipath_token_t *token)
{
    unsigned int i;

    for (i = 0; i < paths->path_limit; i++) {
        if (entry_occupied(&paths->entry[i]) &&
            multipath_token_equal(&paths->entry[i].token, token))
            return (int)i;
    }
    return -1;
}

static int find_empty(const multipath_t *paths)
{
    unsigned int i;

    for (i = 0; i < paths->path_limit; i++) {
        if (!entry_occupied(&paths->entry[i]))
            return (int)i;
    }
    return -1;
}

/* Empty slots always win. A full table retains the current primary, prefers
 * an unvalidated non-primary victim, then takes the oldest generation within
 * that authority class. Thus a newer unproven tuple cannot displace a proven
 * standby merely because its generation is newer. */
static int replacement_index(const multipath_t *paths)
{
    int vacant = find_empty(paths);
    int selected = -1;
    unsigned int wanted_validated;
    unsigned int i;

    if (vacant >= 0)
        return vacant;
    for (wanted_validated = 0U; wanted_validated <= 1U;
         wanted_validated++) {
        uint64_t oldest = UINT64_MAX;

        for (i = 0; i < paths->path_limit; i++) {
            const multipath_entry_t *entry = &paths->entry[i];
            unsigned int is_validated =
                entry->state == MULTIPATH_PATH_VALIDATED;

            if (i == paths->primary_index || !entry_occupied(entry) ||
                is_validated != wanted_validated)
                continue;
            if (entry->generation < oldest) {
                oldest = entry->generation;
                selected = (int)i;
            }
        }
        if (selected >= 0)
            return selected;
    }
    return selected;
}

static void retire_entry(multipath_t *paths, uint8_t index)
{
    if (!entry_occupied(&paths->entry[index]))
        return;
    memset(&paths->entry[index], 0, sizeof(paths->entry[index]));
    paths->counters.replacements++;
}

static int install_unvalidated(multipath_t *paths, uint8_t index,
                               const multipath_token_t *token,
                               multipath_path_state_t state, int64_t now_ms)
{
    multipath_entry_t fresh;

    if (!counter_available(paths->generation_counter) ||
        !counter_available(paths->challenge_counter))
        return MULTIPATH_EXHAUSTED;
    memset(&fresh, 0, sizeof(fresh));
    fresh.token = *token;
    fresh.generation = counter_take(&paths->generation_counter);
    fresh.challenge_id = counter_take(&paths->challenge_counter);
    fresh.challenge_due_ms = now_ms;
    fresh.state = (uint8_t)state;
    fresh.challenge_pending = 1U;
    paths->entry[index] = fresh;
    paths->counters.challenges_created++;
    return MULTIPATH_ACCEPTED;
}

static int ignore_authority(multipath_t *paths,
                            multipath_rx_authority_t authority)
{
    if (authority == MULTIPATH_RX_INVALID)
        paths->counters.ignored_invalid++;
    else if (authority == MULTIPATH_RX_REPLAY)
        paths->counters.ignored_replay++;
    else if (authority == MULTIPATH_RX_STALE)
        paths->counters.ignored_stale++;
    else
        return MULTIPATH_ERROR;
    return MULTIPATH_IGNORED;
}

static int set_primary(multipath_t *paths, uint8_t index,
                       int *primary_changed)
{
    if (paths->primary_index == index)
        return 0;
    paths->primary_index = index;
    if (paths->counters.primary_changes != UINT64_MAX)
        paths->counters.primary_changes++;
    if (primary_changed != NULL)
        *primary_changed = 1;
    return 1;
}

int multipath_bootstrap_primary(multipath_t *paths,
                                const multipath_token_t *token,
                                int64_t now_ms,
                                multipath_handle_t *handle_out)
{
    int found;
    int vacant;
    uint8_t index;

    handle_clear(handle_out);
    if (!token_fits_paths(paths, token) || now_ms < 0)
        return MULTIPATH_ERROR;
    if (paths->primary_index != MULTIPATH_NO_INDEX) {
        const multipath_entry_t *primary =
            &paths->entry[paths->primary_index];
        if (!multipath_token_equal(&primary->token, token))
            return MULTIPATH_ERROR;
        handle_from_entry(paths, paths->primary_index, handle_out);
        return MULTIPATH_ACCEPTED;
    }
    found = find_token(paths, token);
    if (found >= 0) {
        index = (uint8_t)found;
        paths->entry[index].state = MULTIPATH_PATH_PROVISIONAL;
    } else {
        vacant = find_empty(paths);
        if (vacant < 0 ||
            install_unvalidated(paths, (uint8_t)vacant, token,
                                MULTIPATH_PATH_PROVISIONAL,
                                now_ms) != MULTIPATH_ACCEPTED)
            return MULTIPATH_EXHAUSTED;
        index = (uint8_t)vacant;
        paths->counters.configurations++;
    }
    (void)set_primary(paths, index, NULL);
    handle_from_entry(paths, index, handle_out);
    return MULTIPATH_ACCEPTED;
}

/* Authority and token have already been checked. */
static int observe_hwm(multipath_t *paths,
                       const multipath_token_t *ingress, int64_t now_ms,
                       multipath_handle_t *handle_out,
                       int *primary_changed_out)
{
    int found = find_token(paths, ingress);
    uint8_t index;

    if (found >= 0) {
        index = (uint8_t)found;
        if (paths->entry[index].state == MULTIPATH_PATH_CONFIGURED)
            paths->entry[index].state = MULTIPATH_PATH_PROVISIONAL;
    } else {
        int replacement = replacement_index(paths);

        if (replacement < 0)
            return MULTIPATH_ERROR;
        index = (uint8_t)replacement;
        if (!counter_available(paths->generation_counter) ||
            !counter_available(paths->challenge_counter))
            return MULTIPATH_EXHAUSTED;
        retire_entry(paths, index);
        if (install_unvalidated(paths, index, ingress,
                                MULTIPATH_PATH_PROVISIONAL,
                                now_ms) != MULTIPATH_ACCEPTED)
            return MULTIPATH_EXHAUSTED;
    }
    (void)set_primary(paths, index, primary_changed_out);
    paths->counters.hwm_accepted++;
    handle_from_entry(paths, index, handle_out);
    return MULTIPATH_ACCEPTED;
}

int multipath_configure_alternate(multipath_t *paths,
                                  const multipath_token_t *token,
                                  int64_t now_ms,
                                  multipath_handle_t *handle_out)
{
    int found;
    uint8_t index;

    handle_clear(handle_out);
    if (!token_fits_paths(paths, token))
        return MULTIPATH_ERROR;
    found = find_token(paths, token);
    if (found >= 0) {
        handle_from_entry(paths, (uint8_t)found, handle_out);
        return MULTIPATH_ACCEPTED;
    }
    found = replacement_index(paths);
    if (found < 0)
        return MULTIPATH_ERROR;
    index = (uint8_t)found;
    if (!counter_available(paths->generation_counter) ||
        !counter_available(paths->challenge_counter))
        return MULTIPATH_EXHAUSTED;
    retire_entry(paths, index);
    if (install_unvalidated(paths, index, token,
                            MULTIPATH_PATH_CONFIGURED,
                            now_ms) != MULTIPATH_ACCEPTED)
        return MULTIPATH_EXHAUSTED;
    paths->counters.configurations++;
    handle_from_entry(paths, index, handle_out);
    return MULTIPATH_ACCEPTED;
}

int multipath_reconfigure_local_slot(multipath_t *paths,
                                     const multipath_handle_t *target,
                                     int64_t now_ms,
                                     multipath_handle_t *handle_out)
{
    multipath_entry_t fresh;
    const multipath_entry_t *current;
    uint8_t index;
    unsigned int local_leg_owners = 0U;
    unsigned int i;

    handle_clear(handle_out);
    if (!paths_valid(paths) || !handle_well_formed(target) || now_ms < 0)
        return MULTIPATH_ERROR;
    index = target->index;
    if (index >= paths->path_limit || index == paths->primary_index)
        return MULTIPATH_IGNORED;
    current = &paths->entry[index];
    if (!entry_occupied(current) ||
        current->generation != target->generation ||
        current->state != MULTIPATH_PATH_VALIDATED)
        return MULTIPATH_IGNORED;
    for (i = 0U; i < paths->path_limit; i++)
        if (entry_occupied(&paths->entry[i]) &&
            paths->entry[i].token.local_leg == current->token.local_leg)
            local_leg_owners++;
    if (local_leg_owners != 1U)
        return MULTIPATH_IGNORED;
    if (!counter_available(paths->generation_counter) ||
        !counter_available(paths->challenge_counter))
        return MULTIPATH_EXHAUSTED;

    memset(&fresh, 0, sizeof(fresh));
    fresh.token = current->token;
    fresh.generation = counter_take(&paths->generation_counter);
    fresh.challenge_id = counter_take(&paths->challenge_counter);
    fresh.challenge_due_ms = now_ms;
    fresh.state = MULTIPATH_PATH_CONFIGURED;
    fresh.challenge_pending = 1U;

    /* Every possible failure was checked above. One assignment is the exact
     * transaction boundary; no other table byte or primary index changes. */
    paths->entry[index] = fresh;
    if (paths->counters.replacements != UINT64_MAX)
        paths->counters.replacements++;
    if (paths->counters.configurations != UINT64_MAX)
        paths->counters.configurations++;
    if (paths->counters.challenges_created != UINT64_MAX)
        paths->counters.challenges_created++;
    handle_from_entry(paths, index, handle_out);
    return MULTIPATH_ACCEPTED;
}

int multipath_reconfigure_local_set(
    multipath_t *paths, const multipath_snapshot_t *expected,
    int64_t now_ms, multipath_handle_t handles_out[MULTIPATH_PATHS_MAX])
{
    multipath_snapshot_t current;
    multipath_t fresh;
    uint32_t low;
    uint32_t local_leg_mask = 0U;
    unsigned int i;

    if (handles_out)
        memset(handles_out, 0,
               sizeof(handles_out[0]) * MULTIPATH_PATHS_MAX);
    if (!paths_valid(paths) || expected == NULL || handles_out == NULL ||
        now_ms < 0 || multipath_get_snapshot(paths, &current) != 0 ||
        memcmp(&current, expected, sizeof(current)) != 0)
        return MULTIPATH_ERROR;
    low = multipath_low_mask(paths->path_limit);
    if (current.occupied_mask != low || current.validated_mask != low ||
        current.configured_mask != 0U || current.provisional_mask != 0U ||
        current.primary_index == MULTIPATH_NO_INDEX ||
        current.primary_mask !=
            (UINT32_C(1) << current.primary_index) ||
        !counter_has_room(paths->generation_counter, paths->path_limit) ||
        !counter_has_room(paths->challenge_counter, paths->path_limit))
        return MULTIPATH_IGNORED;
    for (i = 0U; i < paths->path_limit; i++) {
        uint32_t leg_bit = UINT32_C(1) <<
                           current.entry[i].token.local_leg;

        if (current.entry[i].response_pending ||
            (local_leg_mask & leg_bit) != 0U)
            return MULTIPATH_IGNORED;
        local_leg_mask |= leg_bit;
    }
    if (local_leg_mask != low)
        return MULTIPATH_IGNORED;

    fresh = *paths;
    for (i = 0U; i < fresh.path_limit; i++) {
        multipath_entry_t replacement;

        memset(&replacement, 0, sizeof(replacement));
        replacement.token = current.entry[i].token;
        replacement.generation = counter_take(&fresh.generation_counter);
        replacement.challenge_id = counter_take(&fresh.challenge_counter);
        replacement.challenge_due_ms = now_ms;
        /* The transport still names the retained physical primary until a
         * fresh authenticated HWM proves movement.  Preserve that slot as
         * PROVISIONAL so multipath and peer_confirm_from() report the same
         * roaming-freshest-path authority transition; clearing primary here would make the
         * first response on the unchanged leg diverge (changed vs unchanged).
         * Bulk DATA remains independently frozen until the full cohort is
         * VALIDATED, so this does not make provisional payload-eligible. */
        replacement.state = i == current.primary_index ?
                            MULTIPATH_PATH_PROVISIONAL :
                            MULTIPATH_PATH_CONFIGURED;
        replacement.challenge_pending = 1U;
        fresh.entry[i] = replacement;
    }
    counter_add_saturating(&fresh.counters.replacements, fresh.path_limit);
    counter_add_saturating(&fresh.counters.configurations, fresh.path_limit);
    counter_add_saturating(&fresh.counters.challenges_created,
                           fresh.path_limit);
    if (!paths_valid(&fresh))
        return MULTIPATH_ERROR;

    /* Every fallible check and every fresh entry was completed against the
     * private copy.  This assignment is the local authority transaction. */
    *paths = fresh;
    for (i = 0U; i < paths->path_limit; i++)
        handle_from_entry(paths, (uint8_t)i, &handles_out[i]);
    return MULTIPATH_ACCEPTED;
}

int multipath_observe(multipath_t *paths,
                      const multipath_token_t *ingress,
                      multipath_rx_authority_t authority,
                      int64_t now_ms,
                      multipath_handle_t *handle_out,
                      int *primary_changed_out)
{
    outputs_clear(handle_out, primary_changed_out);
    if (!paths_valid(paths))
        return MULTIPATH_ERROR;
    if (authority != MULTIPATH_RX_HWM)
        return ignore_authority(paths, authority);
    if (!token_fits_paths(paths, ingress))
        return MULTIPATH_ERROR;
    return observe_hwm(paths, ingress, now_ms, handle_out,
                       primary_changed_out);
}

int multipath_receive_challenge(multipath_t *paths,
                                const multipath_token_t *ingress,
                                multipath_rx_authority_t authority,
                                uint64_t challenge_id, int64_t now_ms,
                                multipath_handle_t *handle_out,
                                int *primary_changed_out)
{
    multipath_handle_t local_handle;
    multipath_entry_t *entry;
    int result;

    outputs_clear(handle_out, primary_changed_out);
    if (!paths_valid(paths))
        return MULTIPATH_ERROR;
    if (authority != MULTIPATH_RX_HWM)
        return ignore_authority(paths, authority);
    if (!token_fits_paths(paths, ingress) || challenge_id == 0U)
        return MULTIPATH_ERROR;
    result = observe_hwm(paths, ingress, now_ms, &local_handle,
                         primary_changed_out);
    if (result != MULTIPATH_ACCEPTED)
        return result;
    entry = &paths->entry[local_handle.index];
    if (!entry->response_pending || entry->response_id != challenge_id) {
        entry->response_pending = 1U;
        entry->response_id = challenge_id;
        paths->counters.responses_queued++;
    }
    /* An authenticated fresh HWM challenge is peer-owned retry evidence.
     * It may advance an earlier local hard-failure floor, but cannot create a
     * second owner: the entry still retains exactly one response id. */
    entry->response_due_ms = now_ms;
    if (handle_out != NULL)
        *handle_out = local_handle;
    return MULTIPATH_ACCEPTED;
}

int multipath_receive_response(multipath_t *paths,
                               const multipath_token_t *ingress,
                               multipath_rx_authority_t authority,
                               uint64_t challenge_id,
                               multipath_handle_t *handle_out,
                               int *primary_changed_out)
{
    multipath_entry_t *entry;
    int found;
    uint8_t index;

    outputs_clear(handle_out, primary_changed_out);
    if (!paths_valid(paths))
        return MULTIPATH_ERROR;
    if (authority != MULTIPATH_RX_HWM)
        return ignore_authority(paths, authority);
    if (!token_fits_paths(paths, ingress) || challenge_id == 0U)
        return MULTIPATH_ERROR;
    found = find_token(paths, ingress);
    if (found < 0) {
        paths->counters.response_mismatches++;
        return MULTIPATH_IGNORED;
    }
    index = (uint8_t)found;
    entry = &paths->entry[index];
    if (!entry->challenge_pending || !entry->challenge_sent ||
        entry->challenge_id != challenge_id) {
        paths->counters.response_mismatches++;
        return MULTIPATH_IGNORED;
    }
    if (entry->state == MULTIPATH_PATH_CONFIGURED)
        entry->state = MULTIPATH_PATH_PROVISIONAL;
    (void)set_primary(paths, index, primary_changed_out);
    entry->state = MULTIPATH_PATH_VALIDATED;
    entry->challenge_pending = 0U;
    entry->challenge_sent = 0U;
    entry->challenge_maintenance = 0U;
    entry->challenge_id = 0U;
    entry->challenge_due_ms = 0;
    entry->challenge_attempts = 0U;
    paths->counters.hwm_accepted++;
    paths->counters.validations++;
    handle_from_entry(paths, index, handle_out);
    return MULTIPATH_ACCEPTED;
}

static const multipath_entry_t *entry_for_handle(const multipath_t *paths,
                                                  const multipath_handle_t *h)
{
    const multipath_entry_t *entry;

    if (!handle_well_formed(h))
        return NULL;
    entry = &paths->entry[h->index];
    if (!entry_occupied(entry) || entry->generation != h->generation)
        return NULL;
    return entry;
}

int multipath_challenge_due(const multipath_t *paths,
                            const multipath_handle_t *target,
                            int64_t now_ms, uint64_t *challenge_id_out)
{
    const multipath_entry_t *entry;

    if (challenge_id_out == NULL || !paths_valid(paths) ||
        !handle_well_formed(target))
        return MULTIPATH_ERROR;
    *challenge_id_out = 0U;
    entry = entry_for_handle(paths, target);
    if (entry == NULL || !entry->challenge_pending ||
        now_ms < entry->challenge_due_ms)
        return MULTIPATH_IGNORED;
    *challenge_id_out = entry->challenge_id;
    return MULTIPATH_ACCEPTED;
}

int multipath_challenge_attempted(multipath_t *paths,
                                  const multipath_handle_t *target,
                                  uint64_t challenge_id, int64_t now_ms,
                                  int completed)
{
    multipath_entry_t *entry;
    int64_t retry_ms;

    if (!paths_valid(paths) || !handle_well_formed(target) ||
        challenge_id == 0U || (completed != 0 && completed != 1))
        return MULTIPATH_ERROR;
    entry = &paths->entry[target->index];
    if (!entry_occupied(entry) || entry->generation != target->generation ||
        !entry->challenge_pending || entry->challenge_id != challenge_id)
        return MULTIPATH_IGNORED;
    retry_ms = entry->challenge_maintenance
             ? MULTIPATH_VALIDATED_KEEPALIVE_MS
             : MULTIPATH_CHALLENGE_RETRY_MS;
    if (now_ms < 0 || now_ms > INT64_MAX - retry_ms)
        return MULTIPATH_ERROR;
    entry->challenge_due_ms = now_ms + retry_ms;
    if (completed)
        entry->challenge_sent = 1U;
    if (entry->challenge_attempts != UINT32_MAX)
        entry->challenge_attempts++;
    paths->counters.challenge_attempts++;
    if (entry->challenge_attempts > 1U)
        paths->counters.challenge_retries++;
    return MULTIPATH_ACCEPTED;
}

int multipath_validated_keepalive_arm(multipath_t *paths,
                                      const multipath_handle_t *target,
                                      int64_t now_ms,
                                      uint64_t *challenge_id_out)
{
    multipath_entry_t *entry;
    uint64_t challenge_id;

    if (challenge_id_out != NULL)
        *challenge_id_out = 0U;
    if (!paths_valid(paths) || !handle_well_formed(target) ||
        challenge_id_out == NULL || now_ms < 0)
        return MULTIPATH_ERROR;
    entry = &paths->entry[target->index];
    if (!entry_occupied(entry) || entry->generation != target->generation ||
        entry->state != MULTIPATH_PATH_VALIDATED ||
        entry->challenge_pending)
        return MULTIPATH_IGNORED;
    if (!counter_available(paths->challenge_counter))
        return MULTIPATH_EXHAUSTED;

    challenge_id = counter_take(&paths->challenge_counter);
    entry->challenge_id = challenge_id;
    entry->challenge_due_ms = now_ms;
    entry->challenge_attempts = 0U;
    entry->challenge_pending = 1U;
    entry->challenge_sent = 0U;
    entry->challenge_maintenance = 1U;
    if (paths->counters.challenges_created != UINT64_MAX)
        paths->counters.challenges_created++;
    *challenge_id_out = challenge_id;
    return paths_valid(paths) ? MULTIPATH_ACCEPTED : MULTIPATH_ERROR;
}

int multipath_response_pending(const multipath_t *paths,
                               const multipath_handle_t *target,
                               uint64_t *challenge_id_out)
{
    const multipath_entry_t *entry;

    if (challenge_id_out == NULL || !paths_valid(paths) ||
        !handle_well_formed(target))
        return MULTIPATH_ERROR;
    *challenge_id_out = 0U;
    entry = entry_for_handle(paths, target);
    if (entry == NULL || !entry->response_pending)
        return MULTIPATH_IGNORED;
    *challenge_id_out = entry->response_id;
    return MULTIPATH_ACCEPTED;
}

int multipath_response_due(const multipath_t *paths,
                           const multipath_handle_t *target,
                           int64_t now_ms, uint64_t *challenge_id_out)
{
    const multipath_entry_t *entry;

    if (challenge_id_out == NULL || !paths_valid(paths) ||
        !handle_well_formed(target) || now_ms < 0)
        return MULTIPATH_ERROR;
    *challenge_id_out = 0U;
    entry = entry_for_handle(paths, target);
    if (entry == NULL || !entry->response_pending ||
        now_ms < entry->response_due_ms)
        return MULTIPATH_IGNORED;
    *challenge_id_out = entry->response_id;
    return MULTIPATH_ACCEPTED;
}

int multipath_response_attempted(multipath_t *paths,
                                 const multipath_handle_t *target,
                                 uint64_t challenge_id, int64_t now_ms,
                                 int completed)
{
    multipath_entry_t *entry;

    if (!paths_valid(paths) || !handle_well_formed(target) ||
        challenge_id == 0U || now_ms < 0 ||
        (completed != 0 && completed != 1) ||
        now_ms > INT64_MAX - MULTIPATH_RESPONSE_RETRY_MS)
        return MULTIPATH_ERROR;
    entry = &paths->entry[target->index];
    if (!entry_occupied(entry) || entry->generation != target->generation ||
        !entry->response_pending || entry->response_id != challenge_id)
        return MULTIPATH_IGNORED;
    if (completed) {
        entry->response_pending = 0U;
        entry->response_id = 0U;
        entry->response_due_ms = 0;
        paths->counters.responses_completed++;
    } else {
        entry->response_due_ms = now_ms + MULTIPATH_RESPONSE_RETRY_MS;
    }
    return MULTIPATH_ACCEPTED;
}

static void plan_clear(multipath_plan_t *plan)
{
    memset(plan, 0, sizeof(*plan));
}

static void plan_append(const multipath_t *paths, uint8_t index,
                        multipath_plan_t *plan)
{
    multipath_plan_item_t *item = &plan->item[plan->count];

    handle_from_entry(paths, index, &item->handle);
    item->token = paths->entry[index].token;
    plan->slot_mask |= UINT32_C(1) << index;
    plan->count++;
}

int multipath_plan_primary(const multipath_t *paths,
                           multipath_plan_t *plan_out)
{
    if (plan_out == NULL || !paths_valid(paths))
        return MULTIPATH_ERROR;
    plan_clear(plan_out);
    if (paths->primary_index == MULTIPATH_NO_INDEX)
        return 0;
    plan_append(paths, paths->primary_index, plan_out);
    return 1;
}

int multipath_plan_critical(multipath_t *paths,
                            multipath_plan_t *plan_out)
{
    unsigned int offset;

    if (plan_out == NULL || !paths_valid(paths))
        return MULTIPATH_ERROR;
    plan_clear(plan_out);
    if (paths->primary_index == MULTIPATH_NO_INDEX)
        return 0;
    plan_append(paths, paths->primary_index, plan_out);
    for (offset = 0U; offset < paths->path_limit; offset++) {
        uint8_t alternate = (uint8_t)
            (((unsigned int)paths->alternate_cursor + offset) &
             (paths->path_limit - 1U));

        if (alternate == paths->primary_index ||
            paths->entry[alternate].state != MULTIPATH_PATH_VALIDATED)
            continue;
        plan_append(paths, alternate, plan_out);
        paths->alternate_cursor = (uint8_t)
            (((unsigned int)alternate + 1U) &
             (paths->path_limit - 1U));
        break;
    }
    return (int)plan_out->count;
}

int multipath_plan_target(const multipath_t *paths,
                          const multipath_token_t *target,
                          multipath_plan_t *plan_out)
{
    int found;

    if (plan_out == NULL || !token_fits_paths(paths, target))
        return MULTIPATH_ERROR;
    plan_clear(plan_out);
    found = find_token(paths, target);
    if (found < 0)
        return 0;
    plan_append(paths, (uint8_t)found, plan_out);
    return 1;
}

static int plan_shape_valid(const multipath_t *paths,
                            const multipath_plan_t *plan)
{
    uint32_t exact_mask = 0U;
    unsigned int i;

    if (!plan || plan->count > MULTIPATH_PLAN_COPIES_MAX ||
        !bytes_zero(plan->reserved, sizeof(plan->reserved)) ||
        (plan->slot_mask & ~multipath_low_mask(paths->path_limit)) != 0U)
        return 0;
    for (i = 0U; i < plan->count; i++) {
        const multipath_plan_item_t *item = &plan->item[i];
        uint32_t bit;

        if (!handle_well_formed(&item->handle) ||
            item->handle.index >= paths->path_limit ||
            !multipath_token_valid(&item->token) ||
            item->token.local_leg >= paths->path_limit)
            return 0;
        bit = UINT32_C(1) << item->handle.index;
        if ((exact_mask & bit) != 0U)
            return 0;
        exact_mask |= bit;
    }
    for (; i < MULTIPATH_PLAN_COPIES_MAX; i++) {
        if (!bytes_zero((const uint8_t *)&plan->item[i],
                        sizeof(plan->item[i])))
            return 0;
    }
    return exact_mask == plan->slot_mask;
}

int multipath_plan_resolve(multipath_t *paths,
                           const multipath_plan_t *plan, size_t ordinal,
                           multipath_token_t *token_out)
{
    const multipath_plan_item_t *item;
    const multipath_entry_t *entry;

    if (token_out == NULL || !paths_valid(paths) ||
        !plan_shape_valid(paths, plan) || ordinal >= plan->count)
        return MULTIPATH_ERROR;
    memset(token_out, 0, sizeof(*token_out));
    item = &plan->item[ordinal];
    entry = entry_for_handle(paths, &item->handle);
    if (entry == NULL || !multipath_token_equal(&entry->token, &item->token)) {
        paths->counters.plan_generation_skips++;
        return MULTIPATH_IGNORED;
    }
    *token_out = item->token;
    return MULTIPATH_ACCEPTED;
}

int multipath_get_snapshot(const multipath_t *paths,
                           multipath_snapshot_t *snapshot_out)
{
    unsigned int i;

    if (snapshot_out == NULL || !paths_valid(paths))
        return MULTIPATH_ERROR;
    memset(snapshot_out, 0, sizeof(*snapshot_out));
    memcpy(snapshot_out->entry, paths->entry, sizeof(paths->entry));
    snapshot_out->counters = paths->counters;
    snapshot_out->generation_counter = paths->generation_counter;
    snapshot_out->challenge_counter = paths->challenge_counter;
    snapshot_out->primary_index = paths->primary_index;
    snapshot_out->path_limit = paths->path_limit;
    snapshot_out->alternate_cursor = paths->alternate_cursor;
    for (i = 0; i < paths->path_limit; i++) {
        uint32_t bit = UINT32_C(1) << i;

        if (entry_occupied(&paths->entry[i])) {
            snapshot_out->path_count++;
            snapshot_out->occupied_mask |= bit;
        }
        if (paths->entry[i].state == MULTIPATH_PATH_CONFIGURED)
            snapshot_out->configured_mask |= bit;
        if (paths->entry[i].state == MULTIPATH_PATH_PROVISIONAL)
            snapshot_out->provisional_mask |= bit;
        if (paths->entry[i].state == MULTIPATH_PATH_VALIDATED) {
            snapshot_out->validated_count++;
            snapshot_out->validated_mask |= bit;
        }
    }
    if (paths->primary_index != MULTIPATH_NO_INDEX)
        snapshot_out->primary_mask =
            UINT32_C(1) << paths->primary_index;
    return 0;
}

int multipath_describe_leg(const multipath_t *paths, unsigned int index,
                           path_leg_t *leg_out)
{
    const multipath_entry_t *entry;

    if (leg_out != NULL)
        memset(leg_out, 0, sizeof(*leg_out));
    if (leg_out == NULL || !paths_valid(paths) ||
        index >= paths->path_limit)
        return MULTIPATH_ERROR;
    entry = &paths->entry[index];
    if (!entry_occupied(entry))
        return MULTIPATH_IGNORED;
    leg_out->remote = entry->token;
    leg_out->fd_generation = entry->generation;
    leg_out->validation = entry->state;
    leg_out->envelope = PATH_LEG_ENVELOPE_DIRECT;
    return MULTIPATH_ACCEPTED;
}
