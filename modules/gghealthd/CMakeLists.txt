# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

set(gghealthd_libs
    gg-sdk
    ggl-common
    ggl-process
    ggl-constants
    core-bus
    ggl-socket-server
    core-bus-gg-config)
if(GGL_PORTABLE_CORE)
  list(APPEND gghealthd_libs ggl-svc)
else()
  list(APPEND gghealthd_libs PkgConfig::libsystemd)
endif()
ggl_init_module(gghealthd NO_INLINE_TEST LIBS ${gghealthd_libs})
