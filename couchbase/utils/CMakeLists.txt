add_library(
  couchbase_utils OBJECT
  connection_string.cxx
  url_codec.cxx
  json.cxx
  duration_parser.cxx)
set_target_properties(couchbase_utils PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(
  couchbase_utils
  PRIVATE project_options
          project_warnings
          fmt::fmt
          spdlog::spdlog)
target_include_directories(couchbase_utils PRIVATE ${PROJECT_SOURCE_DIR})
