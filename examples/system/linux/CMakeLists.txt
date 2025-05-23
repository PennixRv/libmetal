
message(STATUS "Checking machine directory: ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_MACHINE}")
if (IS_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_MACHINE})
  message(STATUS "Found machine directory: ${PROJECT_MACHINE}")
  add_subdirectory(${PROJECT_MACHINE})
else()
  message(WARNING "Machine directory not found: ${CMAKE_CURRENT_SOURCE_DIR}/${PROJECT_MACHINE}")
endif()
