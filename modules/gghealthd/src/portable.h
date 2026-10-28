// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef GGHEALTHD_PORTABLE_H
#define GGHEALTHD_PORTABLE_H

// gghealthd backend for the systemd-free portable core: lifecycle states
// come from ggl-svcd instead of systemd's D-Bus API.

#include <gg/error.h>
#include <gg/types.h>

#define SERVICE_PREFIX "ggl."
#define SERVICE_SUFFIX ".service"

/// Lifecycle state from one ggl-svcd unit line
/// ("<unit> <ActiveState> <Result> <NRestarts> <InactiveEnterUsec>"),
/// with the same mapping gghealthd applies to systemd unit properties.
/// On success *unit points into line and *state at a static string.
GgError portable_parse_unit_line(char *line, char **unit, GgBuffer *state);

/// "ggl.<component>.service" -> <component>; GG_ERR_NOENTRY otherwise.
GgError portable_component_of_unit(const char *unit, GgBuffer *component);

#endif
