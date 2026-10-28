# aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Service manager for the systemd-free portable core (see bin/ggl-svcd.c).
if(GGL_PORTABLE_CORE)
  ggl_init_module(ggl-svc NO_INLINE_TEST)
  file(GLOB CORE_UNITS CONFIGURE_DEPENDS "${CMAKE_CURRENT_LIST_DIR}/units/*")
  install(FILES ${CORE_UNITS} DESTINATION lib/ggl-svc)
endif()
