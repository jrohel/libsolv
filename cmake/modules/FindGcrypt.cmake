#
# - Find gcrypt
# Find the native GCRYPT includes and library
#
#  GCRYPT_INCLUDE_DIRS - where to find gcrypt.h, etc.
#  GCRYPT_LIBRARIES    - List of libraries when using gcrypt.
#  GCRYPT_FOUND        - True if gcrypt found.


if(GCRYPT_INCLUDE_DIRS)
  # Already in cache, be silent
  set(GCRYPT_FIND_QUIETLY TRUE)
endif()

find_path(GCRYPT_INCLUDE_DIR gcrypt.h
  HINTS
    "${GCRYPT_HINTS}/include"
)

find_library(GCRYPT_LIBRARY
  NAMES gcrypt libgcrypt-20
  HINTS "${GCRYPT_HINTS}/bin")

# libgpg-error6-0 is used in libgcrypt-1.7.6-win??ws (built from source).
# libgpg-error-0 is used in libgcrypt-1.8.3-win??ws (from Debian).
find_library(GCRYPT_ERROR_LIBRARY
  NAMES gpg-error libgpg-error-0 libgpg-error6-0
  HINTS "${GCRYPT_HINTS}/bin")

# Try to retrieve version from header if found (available since libgcrypt 1.3.0)
if(GCRYPT_INCLUDE_DIR)
  set(_version_regex "^#define[ \t]+GCRYPT_VERSION[ \t]+\"([^\"]+)\".*")
  file(STRINGS "${GCRYPT_INCLUDE_DIR}/gcrypt.h" GCRYPT_VERSION REGEX "${_version_regex}")
  string(REGEX REPLACE "${_version_regex}" "\\1" GCRYPT_VERSION "${GCRYPT_VERSION}")
  unset(_version_regex)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GCRYPT
  REQUIRED_VARS   GCRYPT_LIBRARY GCRYPT_INCLUDE_DIR
  VERSION_VAR     GCRYPT_VERSION)

if(GCRYPT_FOUND)
  set(GCRYPT_LIBRARIES ${GCRYPT_LIBRARY} ${GCRYPT_ERROR_LIBRARY})
  set(GCRYPT_INCLUDE_DIRS ${GCRYPT_INCLUDE_DIR})
else()
  set(GCRYPT_LIBRARIES)
  set(GCRYPT_INCLUDE_DIRS)
endif()

mark_as_advanced(GCRYPT_LIBRARIES GCRYPT_INCLUDE_DIRS)
