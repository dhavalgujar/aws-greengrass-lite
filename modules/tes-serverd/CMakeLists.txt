# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(tes_serverd_libs
    gg-sdk
    ggl-common
    ggl-http
    core-bus
    core-bus-gg-config
    PkgConfig::libevent)
if(NOT GGL_PORTABLE_CORE)
  list(APPEND tes_serverd_libs PkgConfig::libsystemd)
endif()
ggl_init_module(tes-serverd NO_INLINE_TEST LIBS ${tes_serverd_libs})
